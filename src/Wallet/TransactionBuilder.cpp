// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "TransactionBuilder.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <Common/BinaryArray.hpp>
#include <Common/StringTools.h>
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "crypto/ct_ecdh.h"
#include "crypto/gk_proof.h"
#include "crypto/triptych.h"
#include "crypto/transaction_balance.h"
#include "CryptoNoteConfig.h"

extern "C" {
#include "crypto/crypto-ops.h"
#include "crypto/crypto-util.h"
}
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "Denominations.h"
#include "Wallet/WalletErrors.h"

namespace CryptoNote {

// ── Transparent (v1) transaction builder ─────────────────────────────────────

std::unique_ptr<ITransaction> buildTransaction(
    std::vector<TxBuildInput>& inputs,
    std::vector<TxBuildOutput>& outputs,
    const Crypto::SecretKey& viewSecretKey,
    const std::string& extra,
    uint64_t unlockTimestamp,
    uint64_t sizeLimit,
    Crypto::SecretKey& txSecretKey) {

  std::unique_ptr<ITransaction> tx = createTransaction();

  // 1. Set unlock time
  tx->setUnlockTime(unlockTimestamp);

  // 2. Add inputs — this generates key images and populates inputs[i].ephKeys
  for (auto& input : inputs) {
    tx->addInput(input.senderKeys, input.keyInfo, input.ephKeys);
  }

  // 3. Generate deterministic transaction keys (must come after inputs, before outputs).
  //    r = Hs(viewSecretKey || inputsHash). Enables tx key recovery for sending proofs.
  //    If viewSecretKey is null, keep the random keypair — original CryptoNote protocol, safe.
  if (viewSecretKey != NULL_SECRET_KEY) {
    tx->generateDeterministicTransactionKeys(viewSecretKey);
  }
  // else: random tx keypair from TransactionImpl() constructor is used (safe, original protocol)

  // 4. Sort outputs ascending by amount (shuffle first for privacy, then stable sort)
  std::shuffle(outputs.begin(), outputs.end(), Random::generator());
  std::sort(outputs.begin(), outputs.end(), [](const TxBuildOutput& a, const TxBuildOutput& b) {
    return a.amount < b.amount;
  });

  for (const auto& out : outputs) {
    tx->addOutput(out.amount, out.destination);
  }

  // 5. Append extra data (payment ID, etc.)
  if (!extra.empty()) {
    tx->appendExtra(Common::asBinaryArray(extra));
  }

  // 6. Sign each input
  size_t i = 0;
  for (const auto& input : inputs) {
    tx->signInputKey(i++, input.keyInfo, input.ephKeys);
  }

  // 7. Enforce size limit if requested
  if (sizeLimit > 0) {
    size_t txSize = tx->getTransactionData().size();
    if (txSize >= sizeLimit) {
      throw std::system_error(make_error_code(error::TRANSACTION_SIZE_TOO_BIG));
    }
  }

  // 8. Extract and return the deterministic secret key
  tx->getTransactionSecretKey(txSecretKey);

  return tx;
}

// ── Confidential (v2 CT) transaction builder ─────────────────────────────────

// computeCTInputsHash is no longer needed — we use getObjectHash(tx.inputs)
// after fully populating the ConfidentialInput structs, which matches the
// hash used by isOurOutgoingTransaction() in TransfersConsumer.cpp.

namespace {

// RAII guard that securely wipes all temporary CT-build secrets when it goes
// out of scope, on both the success and the exception path. Wallet hardening
// only — does not affect consensus serialization or transaction validity.
struct CTBuildSecretCleanup {
  std::vector<Crypto::EllipticCurveScalar>& outputBlindings;
  std::vector<Crypto::EllipticCurveScalar>& pseudoBlindings;
  std::vector<CTBuildInput>& inputs;
  Crypto::EllipticCurveScalar* excessScalar = nullptr;
  KeyPair* txKeyPair = nullptr;

  ~CTBuildSecretCleanup() {
    if (!outputBlindings.empty()) {
      sodium_memzero(outputBlindings.data(),
                     outputBlindings.size() * sizeof(Crypto::EllipticCurveScalar));
    }
    if (!pseudoBlindings.empty()) {
      sodium_memzero(pseudoBlindings.data(),
                     pseudoBlindings.size() * sizeof(Crypto::EllipticCurveScalar));
    }
    for (auto& input : inputs) {
      sodium_memzero(&input.realBlinding, sizeof(input.realBlinding));
      sodium_memzero(&input.spendPrivkey, sizeof(input.spendPrivkey));
    }
    if (excessScalar != nullptr) {
      sodium_memzero(excessScalar, sizeof(*excessScalar));
    }
    if (txKeyPair != nullptr) {
      sodium_memzero(&txKeyPair->secretKey, sizeof(txKeyPair->secretKey));
    }
  }
};

} // namespace

// NOTE: buildConfidentialTransaction() consumes a *temporary* set of CTBuildInput
// descriptors copied from wallet state. The function securely wipes the secret
// fields (realBlinding, spendPrivkey) of each input on both success and
// exception paths via CTBuildSecretCleanup. Callers must not pass references to
// persistent wallet storage — only short-lived build descriptors.
Transaction buildConfidentialTransaction(
    std::vector<CTBuildInput>& inputs,
    std::vector<CTBuildOutput>& outputs,
    const Crypto::SecretKey& viewSecretKey,
    uint64_t fee,
    const std::string& extra,
    Crypto::SecretKey& txSecretKey,
    uint64_t unlockTime) {

  if (inputs.empty()) {
    throw std::invalid_argument("CT transaction must have at least one input");
  }
  if (outputs.empty()) {
    throw std::invalid_argument("CT transaction must have at least one output");
  }

  // Determine whether this is a v3 unshield (any transparent output) or a v2
  // all-confidential tx. The version tag is set in Step 3 below.
  bool hasTransparentOutput = false;
  for (const auto& out : outputs) {
    if (out.isTransparent) {
      hasTransparentOutput = true;
      break;
    }
  }

  // Output amount validation, per output type:
  //   confidential → must be a canonical denomination (GK proof requires it)
  //   transparent  → just non-zero (v1 plain-output rule); the amount is
  //                  published in the clear and carries no GK proof.
  for (const auto& out : outputs) {
    if (out.isTransparent) {
      if (out.amount == 0) {
        throw std::invalid_argument("Transparent unshield output amount must be non-zero");
      }
    } else if (denominationIndex(out.amount) < 0) {
      throw std::invalid_argument("CT output amount is not a canonical denomination: "
                                  + std::to_string(out.amount));
    }
  }

  // Validate CT ring metadata consistency and canonicalise the ring order.
  //
  // Consensus requires ring members to be sorted by (amount, outputIndex)
  // strictly ascending (see Blockchain::checkConfidentialTransaction Step 4).
  // We sort here, on the caller's mutable inputs[], and re-map realIndex to
  // the post-sort slot for each input. This frees the wallet from having to
  // pre-canonicalise its rings — it just hands us whatever picks it made and
  // tells us which slot is real.
  for (size_t i = 0; i < inputs.size(); ++i) {
    auto& members = inputs[i].ringMembers;
    if (members.empty()) {
      throw std::invalid_argument("CT input has empty ring at index " + std::to_string(i));
    }
    if (inputs[i].realIndex >= members.size()) {
      throw std::invalid_argument("CT input real index out of range at index " + std::to_string(i));
    }

    // Remember which member is the real spend so we can find it after sorting.
    // Identifying by (amount, outputIndex) is safe because rings must not have
    // duplicate (amount, outputIndex) pairs (the canonical-order check rejects
    // duplicates), which we verify below.
    const CTBuildRingMember realRef = members[inputs[i].realIndex];

    std::sort(members.begin(), members.end(),
              [](const CTBuildRingMember& a, const CTBuildRingMember& b) {
                if (a.amount != b.amount) return a.amount < b.amount;
                return a.outputIndex < b.outputIndex;
              });

    // Reject duplicate (amount, outputIndex) pairs — they would defeat the
    // strict-ascending consensus check and indicate a wallet bug.
    for (size_t k = 1; k < members.size(); ++k) {
      if (members[k].amount == members[k - 1].amount &&
          members[k].outputIndex == members[k - 1].outputIndex) {
        throw std::invalid_argument("CT input has duplicate ring member (amount,outputIndex) at index "
                                    + std::to_string(i));
      }
    }

    // Relocate the real index.
    size_t newRealIndex = members.size();
    for (size_t k = 0; k < members.size(); ++k) {
      if (members[k].amount == realRef.amount &&
          members[k].outputIndex == realRef.outputIndex) {
        newRealIndex = k;
        break;
      }
    }
    if (newRealIndex == members.size()) {
      // Real member disappeared during sort — impossible unless caller mutated
      // members between sort and lookup. Treat as wallet bug.
      throw std::runtime_error("CT input lost real ring member during canonicalisation at index "
                               + std::to_string(i));
    }
    inputs[i].realIndex = newRealIndex;
  }

  // ── Step 1: Prepare inputs — key images, pseudo-commitments ─────────────────
  std::vector<Crypto::EllipticCurveScalar> pseudoBlindings(inputs.size());
  std::vector<Crypto::EllipticCurvePoint> pseudoCommitments(inputs.size());
  std::vector<Crypto::KeyImage> keyImages(inputs.size());

  // Pre-size outputBlindings so its storage is registered with the cleanup
  // guard before any code path that can throw populates secrets.
  std::vector<Crypto::EllipticCurveScalar> outputBlindings(outputs.size());

  // Install RAII cleanup as early as possible so secrets are wiped on every
  // exit path (success or exception). excessScalar / txKeyPair pointers are
  // set immediately after those locals are declared further down.
  CTBuildSecretCleanup cleanup{outputBlindings, pseudoBlindings, inputs};

  for (size_t i = 0; i < inputs.size(); ++i) {
    if (inputs[i].isTransparent) {
      // KeyInput (transparent shielding). All ring members must come from the
      // same transparent bucket as the real input — the on-chain verifier
      // resolves the ring via scanOutputKeysForIndexes which only accepts
      // KeyOutput targets in a single amount bucket.
      for (const auto& m : inputs[i].ringMembers) {
        if (m.amount != inputs[i].amount) {
          throw std::invalid_argument("Transparent CT input " + std::to_string(i)
            + " has cross-bucket ring member (bucket " + std::to_string(m.amount)
            + " vs input amount " + std::to_string(inputs[i].amount) + ")");
        }
      }
      // Deterministic pseudo-commitment for the balance kernel: amount*H + 0*G.
      // pseudoBlinding stays zero so excess scalar gets no contribution from
      // this input (matches the verifier's reconstruction).
      std::memset(&pseudoBlindings[i], 0, sizeof(pseudoBlindings[i]));
      if (!Crypto::transparent_amount_to_commitment(inputs[i].amount, pseudoCommitments[i])) {
        throw std::runtime_error("Failed to compute transparent pseudo-commitment for input " + std::to_string(i));
      }
    } else {
      // ConfidentialInput: random blinding, Pedersen commitment.
      //
      // Draw 64 random bytes and call sc_reduce — the unbiased way to sample
      // a uniform scalar in [0, L). Reducing only 32 bytes (sc_reduce32) is
      // biased because L is close to 2^252 < 2^256: values in [0, 2^256 − k·L)
      // get hit one more time than values in [2^256 − k·L, L), yielding a
      // ~1/16 non-uniformity at the high end. Matches random_scalar() in
      // triptych.cpp and gk_proof.cpp.
      Crypto::EllipticCurveScalar r_pseudo;
      unsigned char tmp[64];
      Random::randomBytes(64, tmp);
      sc_reduce(tmp);
      std::memcpy(r_pseudo.data, tmp, 32);
      sodium_memzero(tmp, sizeof(tmp));
      pseudoBlindings[i] = r_pseudo;

      Crypto::PublicKey pseudo_pk;
      bool pcOk = Crypto::pedersen_commit(inputs[i].amount, r_pseudo, pseudo_pk);
      sodium_memzero(&r_pseudo, sizeof(r_pseudo));
      if (!pcOk) {
        throw std::runtime_error("Failed to compute pseudo-commitment for input " + std::to_string(i));
      }
      std::memcpy(&pseudoCommitments[i], &pseudo_pk, 32);
    }

    // Compute key image: I = x * Hp(P_real). Same regardless of input shape.
    Crypto::PublicKey realPubkey = inputs[i].ringMembers[inputs[i].realIndex].pubkey;
    Crypto::generate_key_image(realPubkey, inputs[i].spendPrivkey, keyImages[i]);
  }

  // ── Step 2: Assemble inputs into transaction prefix ────────────────────────
  // We must build the full ConfidentialInput structs BEFORE computing the
  // deterministic tx key, so that getObjectHash(tx.inputs) matches the hash
  // used by isOurOutgoingTransaction() in TransfersConsumer.cpp.
  Transaction tx;
  // v3 unshield when any output is transparent; otherwise v2 all-confidential.
  // Both share the entire CT wire format and input/spend path (see CT-DESIGN.md
  // "Transaction version ladder"); only the version tag + output side differ.
  tx.version = hasTransparentOutput ? TRANSACTION_VERSION_UNSHIELD
                                    : TRANSACTION_VERSION_CT;
  // Caller-supplied unlockTime. The consensus rule is `<= CRYPTONOTE_MAX_
  // UNLOCK_HEIGHT_V6` (same height-only cap as v6 plain). 0 means
  // immediately spendable; non-zero values enable refund-on-timeout
  // patterns. See CT-DESIGN.md for the threat-model rationale.
  tx.unlockTime = unlockTime;
  tx.fee = fee;

  tx.inputs.resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const size_t ringSize = inputs[i].ringMembers.size();

    if (inputs[i].isTransparent) {
      // KeyInput: ring is encoded as relative-offset list into the bucket
      // identified by `amount`. After canonicalisation above, ringMembers are
      // sorted ascending by outputIndex (all share the same amount bucket),
      // so absolute_output_offsets_to_relative produces a valid delta list.
      KeyInput ki;
      ki.amount = inputs[i].amount;
      ki.keyImage = keyImages[i];
      std::vector<uint32_t> absoluteOffsets;
      absoluteOffsets.reserve(ringSize);
      for (const auto& m : inputs[i].ringMembers) {
        absoluteOffsets.push_back(m.outputIndex);
      }
      ki.outputIndexes = absolute_output_offsets_to_relative(absoluteOffsets);
      tx.inputs[i] = std::move(ki);
    } else {
      ConfidentialInput cin;
      cin.ringMembers.reserve(ringSize);
      cin.ringPubkeys.reserve(ringSize);
      cin.ringCommitments.reserve(ringSize);
      for (const auto& m : inputs[i].ringMembers) {
        cin.ringMembers.push_back(RingMemberRef{m.amount, m.outputIndex});
        cin.ringPubkeys.push_back(m.pubkey);
        cin.ringCommitments.push_back(m.commitment);
      }
      cin.pseudoCommitment = pseudoCommitments[i];
      cin.keyImage = keyImages[i];
      tx.inputs[i] = std::move(cin);
    }
  }

  // ── Step 3: Deterministic tx key from view secret key + inputs hash ────────
  // Uses getObjectHash(tx.inputs) which is the canonical serialization of the
  // fully populated ConfidentialInput structs — identical to what
  // ITransactionReader::getTransactionInputsHash() returns.
  Crypto::Hash inputsHash;
  getObjectHash(tx.inputs, inputsHash);
  KeyPair txKeyPair;
  cleanup.txKeyPair = &txKeyPair;
  if (!generateDeterministicTransactionKeys(inputsHash, viewSecretKey, txKeyPair)) {
    throw std::runtime_error("Failed to generate deterministic transaction keys");
  }
  txSecretKey = txKeyPair.secretKey;

  // Extra: add tx public key + any user extra data
  {
    tx.extra.push_back(0x01);  // TX_EXTRA_TAG_PUBKEY
    const uint8_t* pk_data = reinterpret_cast<const uint8_t*>(&txKeyPair.publicKey);
    tx.extra.insert(tx.extra.end(), pk_data, pk_data + 32);

    if (!extra.empty()) {
      const uint8_t* extra_data = reinterpret_cast<const uint8_t*>(extra.data());
      tx.extra.insert(tx.extra.end(), extra_data, extra_data + extra.size());
    }
  }

  // ── Step 4: Prepare outputs ────────────────────────────────────────────────
  // Shuffle outputs for privacy, then sort by amount (ascending) for determinism
  std::shuffle(outputs.begin(), outputs.end(), Random::generator());
  std::sort(outputs.begin(), outputs.end(), [](const CTBuildOutput& a, const CTBuildOutput& b) {
    return a.amount < b.amount;
  });

  // Per-output state: commitments, stealth keys, denomination indices.
  // outputBlindings was pre-sized above and is owned by the cleanup guard.
  std::vector<Crypto::PublicKey> outputCommitments(outputs.size());
  std::vector<Crypto::PublicKey> outputTargetKeys(outputs.size());
  std::vector<std::array<uint8_t, 8>> outputMaskedAmounts(outputs.size());
  std::vector<int> outputDenomIndices(outputs.size());

  // RAII helper: wipe the per-iteration ECDH shared secret on every exit path.
  struct ScopedKeyDerivationWipe {
    Crypto::KeyDerivation* p;
    ~ScopedKeyDerivationWipe() { if (p) sodium_memzero(p, sizeof(*p)); }
  };

  for (size_t i = 0; i < outputs.size(); ++i) {
    // Derive ECDH shared secret with recipient
    Crypto::KeyDerivation sharedSecret;
    ScopedKeyDerivationWipe sharedSecretWipe{&sharedSecret};

    if (!Crypto::generate_key_derivation(outputs[i].destination.viewPublicKey,
                                          txKeyPair.secretKey, sharedSecret)) {
      throw std::runtime_error("Failed to generate key derivation for output " + std::to_string(i));
    }

    // Derive one-time stealth address: P = Hs(shared_secret || idx)*G + B_spend.
    // Both output shapes need this — a transparent unshield output is still a
    // stealth KeyOutput so only the recipient can spend it.
    if (!Crypto::derive_public_key(sharedSecret, i, outputs[i].destination.spendPublicKey,
                                    outputTargetKeys[i])) {
      throw std::runtime_error("Failed to derive one-time output key for output " + std::to_string(i));
    }

    if (outputs[i].isTransparent) {
      // Transparent unshield output: value is published in the clear, no
      // commitment / blinding / mask / GK proof. Leave outputBlindings[i] zero
      // (the kernel treats the plain output as amount*H with zero G-blinding,
      // mirroring a transparent KeyInput), so it makes no contribution to the
      // excess scalar. denomIndex unused for transparent outputs.
      outputDenomIndices[i] = -1;
      continue;
    }

    // Derive blinding factor: r = Hs(shared_secret || output_index)
    Crypto::derive_blinding_factor(sharedSecret, i, outputBlindings[i]);

    // Compute Pedersen commitment: C = amount*H + r*G
    if (!Crypto::pedersen_commit(outputs[i].amount, outputBlindings[i], outputCommitments[i])) {
      throw std::runtime_error("Failed to compute Pedersen commitment for output " + std::to_string(i));
    }

    // ECDH-mask the amount
    Crypto::MaskedAmount masked;
    Crypto::mask_amount(sharedSecret, i, outputs[i].amount, masked);
    std::memcpy(outputMaskedAmounts[i].data(), masked.data, 8);

    outputDenomIndices[i] = denominationIndex(outputs[i].amount);
  }

  // Build outputs (prefix only — GK proofs go in tx.ctProofs)
  tx.outputs.resize(outputs.size());
  for (size_t i = 0; i < outputs.size(); ++i) {
    TransactionOutput txout;
    if (outputs[i].isTransparent) {
      // v3 unshield plain output: a transparent KeyOutput carrying the visible
      // amount, exactly like a v1 output. Lands in the normal per-amount global
      // index (Blockchain.cpp output indexing) so it is later spendable as an
      // ordinary ring member.
      KeyOutput kout;
      kout.key = outputTargetKeys[i];
      txout.amount = outputs[i].amount;  // published in the clear
      txout.target = std::move(kout);
    } else {
      ConfidentialOutput cout;
      cout.targetKey = outputTargetKeys[i];
      std::memcpy(&cout.commitment, &outputCommitments[i], 32);
      cout.maskedAmount = outputMaskedAmounts[i];
      txout.amount = 0;  // CT outputs: amount field is 0 (real amount is in commitment)
      txout.target = std::move(cout);
    }
    tx.outputs[i] = std::move(txout);
  }

  // ── Step 4b: Compute prefix hash for Fiat-Shamir binding ──────────────────
  // Proof response fields are in Transaction body (not prefix), so the prefix
  // hash naturally excludes them — no custom hash function needed.
  Crypto::Hash signingHash = getObjectHash(*static_cast<const TransactionPrefix*>(&tx));

  // ── Step 5: Generate GK denomination proofs for each CONFIDENTIAL output ────
  // One proof per confidential output, in output order. Transparent (unshield)
  // outputs carry no GK proof, so tx.ctProofs is sized to the confidential count
  // and indexed by confProofIdx — this MUST match the consensus expectation
  // (checkConfidentialTransaction: ctProofs.size() == numConfidentialOutputs,
  // proofs consumed in confidential-output order).
  size_t numConfidentialOutputs = 0;
  for (const auto& o : outputs) {
    if (!o.isTransparent) ++numConfidentialOutputs;
  }
  tx.ctProofs.resize(numConfidentialOutputs);
  size_t confProofIdx = 0;
  for (size_t i = 0; i < outputs.size(); ++i) {
    if (outputs[i].isTransparent) {
      continue;  // no GK denomination proof for a transparent unshield output
    }
    Crypto::GKProof proof;
    Crypto::EllipticCurvePoint commitPoint;
    std::memcpy(&commitPoint, &outputCommitments[i], 32);

    if (!Crypto::gk_prove(commitPoint, outputs[i].amount, outputBlindings[i],
                          static_cast<size_t>(outputDenomIndices[i]),
                          signingHash, proof)) {
      throw std::runtime_error("GK prove failed for output " + std::to_string(i));
    }

    // Copy proof into transaction body
    auto& gkp = tx.ctProofs[confProofIdx];
    ++confProofIdx;
    for (size_t j = 0; j < 6; ++j) {
      ge_p3_tobytes(reinterpret_cast<unsigned char*>(&gkp.I[j]), &proof.I[j]);
      ge_p3_tobytes(reinterpret_cast<unsigned char*>(&gkp.A[j]), &proof.A[j]);
      ge_p3_tobytes(reinterpret_cast<unsigned char*>(&gkp.B[j]), &proof.B[j]);
      ge_p3_tobytes(reinterpret_cast<unsigned char*>(&gkp.Q[j]), &proof.Q[j]);
      gkp.z[j] = proof.z[j];
      gkp.za[j] = proof.za[j];
      gkp.zb[j] = proof.zb[j];
    }
    gkp.f = proof.f;
  }

  // ── Step 6: Per-input signing ──────────────────────────────────────────────
  // tx.signatures is a per-input variant parallel to tx.inputs:
  //   KeyInput          → vector<Crypto::Signature>  (legacy ring sig)
  //   ConfidentialInput → CTInputSignature           (Triptych spend proof)
  // The variant alternative is implicit from inputs[i].type().
  tx.signatures.resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const size_t ringSize = inputs[i].ringMembers.size();

    if (inputs[i].isTransparent) {
      // Legacy ring signature: prove knowledge of spendPrivkey for one of the
      // ring's pubkeys, bound to (signingHash, keyImage). Verifier replays via
      // check_tx_input which resolves the ring members from outputIndexes.
      std::vector<Crypto::PublicKey> ringPubkeys;
      ringPubkeys.reserve(ringSize);
      for (const auto& m : inputs[i].ringMembers) {
        ringPubkeys.push_back(m.pubkey);
      }
      std::vector<const Crypto::PublicKey*> ringPubkeyPtrs;
      ringPubkeyPtrs.reserve(ringSize);
      for (const auto& pk : ringPubkeys) {
        ringPubkeyPtrs.push_back(&pk);
      }

      std::vector<Crypto::Signature> sigs(ringSize);
      Crypto::generate_ring_signature(signingHash, keyImages[i],
        ringPubkeyPtrs, inputs[i].spendPrivkey, inputs[i].realIndex, sigs.data());
      tx.signatures[i] = std::move(sigs);
      continue;
    }

    // ConfidentialInput: Triptych spend proof.
    Crypto::TriptychSignature proof;
    Crypto::KeyImage ki;

    if (!Crypto::triptych_ring_size_supported(ringSize)) {
      throw std::runtime_error("Triptych: unsupported ring size " +
                               std::to_string(ringSize) +
                               " for input " + std::to_string(i));
    }

    std::vector<Crypto::PublicKey> ringPubkeys;
    std::vector<Crypto::EllipticCurvePoint> ringCommitments;
    ringPubkeys.reserve(ringSize);
    ringCommitments.reserve(ringSize);
    for (const auto& m : inputs[i].ringMembers) {
      ringPubkeys.push_back(m.pubkey);
      ringCommitments.push_back(m.commitment);
    }

    if (!Crypto::triptych_sign(
        signingHash,
        ringPubkeys.data(),
        ringCommitments.data(),
        pseudoCommitments[i],
        ringSize,
        inputs[i].realIndex,
        inputs[i].spendPrivkey,
        inputs[i].realBlinding,
        pseudoBlindings[i],
        ki,
        proof)) {
      throw std::runtime_error("Triptych sign failed for input " + std::to_string(i));
    }

    // Update key image in the prefix input
    auto& cin = boost::get<ConfidentialInput>(tx.inputs[i]);
    cin.keyImage = ki;

    // Copy Triptych proof into transaction body. The on-wire CTInputSignature
    // struct mirrors Crypto::TriptychSignature field-for-field; we move the
    // vectors over so we don't pay a copy on each n×32-byte payload.
    tx.signatures[i] = CTInputSignature{};
    auto& s = ctInputSig(tx.signatures[i]);
    s.I_bits = std::move(proof.I_bits);
    s.A      = std::move(proof.A);
    s.B      = std::move(proof.B);
    s.Q_P    = std::move(proof.Q_P);
    s.Q_M    = std::move(proof.Q_M);
    s.Q_U    = std::move(proof.Q_U);
    s.z      = std::move(proof.z);
    s.za     = std::move(proof.za);
    s.zb     = std::move(proof.zb);
    s.f_P    = proof.f_P;
    s.f_M    = proof.f_M;
    s.f_U    = proof.f_U;
  }

  // ── Step 7: Compute excess and sign kernel ─────────────────────────────────
  // excess = sum(pseudo_blindings) - sum(output_blindings)
  // For transparent pre-fork inputs, realBlinding is zero, so pseudo_blinding
  // contributes fully. v3 transparent (unshield) OUTPUTS likewise keep a zero
  // blinding (Step 4 skips derive_blinding_factor for them), so they add
  // nothing to the output-blinding sum — matching the kernel treating a plain
  // output as amount*H + 0*G. The balance equation:
  //   sum(C'_in) - sum(C_out) - fee*H = excess*G
  Crypto::EllipticCurveScalar excessScalar;
  cleanup.excessScalar = &excessScalar;
  Crypto::compute_excess_scalar(
      pseudoBlindings.data(), pseudoBlindings.size(),
      outputBlindings.data(), outputBlindings.size(),
      excessScalar);

  Crypto::TransactionKernel cryptoKernel;
  if (!Crypto::sign_transaction_kernel(excessScalar, signingHash, cryptoKernel)) {
    throw std::runtime_error("Failed to sign transaction kernel");
  }

  // Copy to CryptoNote kernel
  tx.kernel.excessCommitment = cryptoKernel.excess;
  std::memcpy(&tx.kernel.sigE, &cryptoKernel.signature, 32);
  std::memcpy(&tx.kernel.sigS, reinterpret_cast<const char*>(&cryptoKernel.signature) + 32, 32);

  // All temporary CT-build secrets (outputBlindings, pseudoBlindings, per-input
  // realBlinding/spendPrivkey, excessScalar, txKeyPair.secretKey) are wiped by
  // CTBuildSecretCleanup's destructor on the way out — including any early
  // exception path above. Wallet hardening only; tx bytes are unchanged.
  return tx;
}

} // namespace CryptoNote
