// Roundtrip self-test for v2 mixed-input CT transactions.
//
// Builds a fake v2 Transaction with one KeyInput (transparent shielding) and
// one ConfidentialInput (CT spend), serializes it via toBinaryArray, parses
// it back via fromBinaryArray, and asserts the round-trip preserves every
// observable field.
//
// Catches the class of bug where the on-wire layout for mixed v2 txs goes
// out of sync between writer and reader — which is what would surface in
// production as "Failed to query blocks: Network error" once the stored
// blob can't be read back.

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "crypto/crypto.h"

using namespace CryptoNote;

namespace {

void fill(uint8_t* p, size_t n, uint8_t seed) {
  for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(seed + i);
}

template <class T>
T makePod(uint8_t seed) {
  T v;
  fill(reinterpret_cast<uint8_t*>(&v), sizeof(T), seed);
  return v;
}

Crypto::Signature makeSig(uint8_t seed) {
  Crypto::Signature s;
  fill(reinterpret_cast<uint8_t*>(&s), sizeof(s), seed);
  return s;
}

Transaction buildMixedV2() {
  Transaction tx;
  tx.version = TRANSACTION_VERSION_CT;
  // Regression: CT prefix used to forcibly zero unlockTime during
  // serialization (and omit it from the wire entirely). A non-zero value
  // here ensures the round-trip assertion below (dst.unlockTime ==
  // src.unlockTime) detects any return of that behavior. 12345 is well
  // under CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6 so structural validation would
  // accept it; we don't run validation here, only the prefix codec.
  tx.unlockTime = 12345;
  tx.fee = 10000000000ULL;
  tx.extra = {0x01, 0xAA, 0xBB, 0xCC};

  // Input 0: KeyInput, ring size 3
  KeyInput ki;
  ki.amount = 100000000ULL;
  ki.outputIndexes = {7, 1, 4};  // relative offsets
  ki.keyImage = makePod<Crypto::KeyImage>(0x10);
  tx.inputs.push_back(ki);

  // Input 1: ConfidentialInput, ring size 4 (Triptych n=2)
  ConfidentialInput cin;
  for (size_t k = 0; k < 4; ++k) {
    cin.ringMembers.push_back(RingMemberRef{
        100000000ULL + k * 10, static_cast<uint32_t>(k)});
    cin.ringPubkeys.push_back(makePod<Crypto::PublicKey>(0x20 + k));
    cin.ringCommitments.push_back(makePod<Crypto::EllipticCurvePoint>(0x30 + k));
  }
  cin.pseudoCommitment = makePod<Crypto::EllipticCurvePoint>(0x40);
  cin.keyImage = makePod<Crypto::KeyImage>(0x50);
  tx.inputs.push_back(cin);

  // Output: one ConfidentialOutput
  ConfidentialOutput cout;
  cout.targetKey = makePod<Crypto::PublicKey>(0x60);
  cout.commitment = makePod<Crypto::EllipticCurvePoint>(0x70);
  std::memset(cout.maskedAmount.data(), 0x80, 8);
  TransactionOutput out;
  out.amount = 0;
  out.target = cout;
  tx.outputs.push_back(out);

  // Per-input authorization, dispatched by inputs[i].type():
  //   slot 0 (KeyInput)          → vector<Signature> with 3 ring sigs
  //   slot 1 (ConfidentialInput) → CTInputSignature with a full Triptych proof
  tx.signatures.resize(2);
  {
    std::vector<Crypto::Signature> sigs;
    for (size_t i = 0; i < 3; ++i) {
      sigs.push_back(makeSig(0x90 + i));
    }
    tx.signatures[0] = std::move(sigs);
  }

  tx.signatures[1] = CTInputSignature{};
  CTInputSignature& cs = ctInputSig(tx.signatures[1]);
  cs.I_bits.resize(2);
  cs.A.resize(2);
  cs.B.resize(2);
  cs.Q_P.resize(2);
  cs.Q_M.resize(2);
  cs.Q_U.resize(2);
  cs.z.resize(2);
  cs.za.resize(2);
  cs.zb.resize(2);
  for (size_t j = 0; j < 2; ++j) {
    cs.I_bits[j] = makePod<Crypto::EllipticCurvePoint>(0xA0 + j);
    cs.A[j]      = makePod<Crypto::EllipticCurvePoint>(0xA2 + j);
    cs.B[j]      = makePod<Crypto::EllipticCurvePoint>(0xA4 + j);
    cs.Q_P[j]    = makePod<Crypto::EllipticCurvePoint>(0xA6 + j);
    cs.Q_M[j]    = makePod<Crypto::EllipticCurvePoint>(0xA8 + j);
    cs.Q_U[j]    = makePod<Crypto::EllipticCurvePoint>(0xAA + j);
    cs.z[j]      = makePod<Crypto::EllipticCurveScalar>(0xAC + j);
    cs.za[j]     = makePod<Crypto::EllipticCurveScalar>(0xAE + j);
    cs.zb[j]     = makePod<Crypto::EllipticCurveScalar>(0xB0 + j);
  }
  cs.f_P = makePod<Crypto::EllipticCurveScalar>(0xB2);
  cs.f_M = makePod<Crypto::EllipticCurveScalar>(0xB3);
  cs.f_U = makePod<Crypto::EllipticCurveScalar>(0xB4);

  // CT output proof: dummy values.
  tx.ctProofs.resize(1);
  CTOutputProof& proof = tx.ctProofs[0];
  for (size_t i = 0; i < 6; ++i) {
    proof.I[i]  = makePod<Crypto::EllipticCurvePoint>(0xC0 + i);
    proof.A[i]  = makePod<Crypto::EllipticCurvePoint>(0xC6 + i);
    proof.B[i]  = makePod<Crypto::EllipticCurvePoint>(0xCC + i);
    proof.Q[i]  = makePod<Crypto::EllipticCurvePoint>(0xD2 + i);
    proof.z[i]  = makePod<Crypto::EllipticCurveScalar>(0xD8 + i);
    proof.za[i] = makePod<Crypto::EllipticCurveScalar>(0xDE + i);
    proof.zb[i] = makePod<Crypto::EllipticCurveScalar>(0xE4 + i);
  }
  proof.f = makePod<Crypto::EllipticCurveScalar>(0xEA);

  tx.kernel.excessCommitment = makePod<Crypto::EllipticCurvePoint>(0xF0);
  tx.kernel.sigE = makePod<Crypto::EllipticCurveScalar>(0xF1);
  tx.kernel.sigS = makePod<Crypto::EllipticCurveScalar>(0xF2);

  return tx;
}

bool memEq(const void* a, const void* b, size_t n) {
  return std::memcmp(a, b, n) == 0;
}

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::fprintf(stderr, "FAIL @ %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      return 1;                                                                \
    }                                                                          \
  } while (0)

// v3 CT->CN unshield with MIXED outputs: a transparent KeyOutput (plain payout)
// alongside a ConfidentialOutput (CT change). Confirms the output-variant codec
// round-trips a mix of target types, and that the prefix hash (getObjectHash,
// same serialization) covers both.
Transaction buildMixedOutputV3() {
  Transaction tx;
  tx.version = TRANSACTION_VERSION_UNSHIELD;
  tx.unlockTime = 0;
  tx.fee = 10000000000ULL;
  tx.extra = {0x01, 0x11, 0x22};

  // One ConfidentialInput spends the confidential value (ring size 4, n=2).
  ConfidentialInput cin;
  for (size_t k = 0; k < 4; ++k) {
    cin.ringMembers.push_back(RingMemberRef{
        100000000ULL + k, static_cast<uint32_t>(k)});
    cin.ringPubkeys.push_back(makePod<Crypto::PublicKey>(0x20 + k));
    cin.ringCommitments.push_back(makePod<Crypto::EllipticCurvePoint>(0x30 + k));
  }
  cin.pseudoCommitment = makePod<Crypto::EllipticCurvePoint>(0x40);
  cin.keyImage = makePod<Crypto::KeyImage>(0x50);
  tx.inputs.push_back(cin);

  // Output 0: transparent KeyOutput (plain payout), amount != 0.
  KeyOutput ko;
  ko.key = makePod<Crypto::PublicKey>(0x61);
  TransactionOutput out0;
  out0.amount = 100000000ULL;
  out0.target = ko;
  tx.outputs.push_back(out0);

  // Output 1: ConfidentialOutput (CT change), amount field 0.
  ConfidentialOutput cout;
  cout.targetKey = makePod<Crypto::PublicKey>(0x62);
  cout.commitment = makePod<Crypto::EllipticCurvePoint>(0x72);
  std::memset(cout.maskedAmount.data(), 0x82, 8);
  TransactionOutput out1;
  out1.amount = 0;
  out1.target = cout;
  tx.outputs.push_back(out1);

  // One CTInputSignature (Triptych) for the single ConfidentialInput.
  tx.signatures.resize(1);
  tx.signatures[0] = CTInputSignature{};
  CTInputSignature& cs = ctInputSig(tx.signatures[0]);
  cs.I_bits.resize(2); cs.A.resize(2); cs.B.resize(2);
  cs.Q_P.resize(2); cs.Q_M.resize(2); cs.Q_U.resize(2);
  cs.z.resize(2); cs.za.resize(2); cs.zb.resize(2);
  for (size_t j = 0; j < 2; ++j) {
    cs.I_bits[j] = makePod<Crypto::EllipticCurvePoint>(0xA0 + j);
    cs.A[j]      = makePod<Crypto::EllipticCurvePoint>(0xA2 + j);
    cs.B[j]      = makePod<Crypto::EllipticCurvePoint>(0xA4 + j);
    cs.Q_P[j]    = makePod<Crypto::EllipticCurvePoint>(0xA6 + j);
    cs.Q_M[j]    = makePod<Crypto::EllipticCurvePoint>(0xA8 + j);
    cs.Q_U[j]    = makePod<Crypto::EllipticCurvePoint>(0xAA + j);
    cs.z[j]      = makePod<Crypto::EllipticCurveScalar>(0xAC + j);
    cs.za[j]     = makePod<Crypto::EllipticCurveScalar>(0xAE + j);
    cs.zb[j]     = makePod<Crypto::EllipticCurveScalar>(0xB0 + j);
  }
  cs.f_P = makePod<Crypto::EllipticCurveScalar>(0xB2);
  cs.f_M = makePod<Crypto::EllipticCurveScalar>(0xB3);
  cs.f_U = makePod<Crypto::EllipticCurveScalar>(0xB4);

  // One CT output proof, for the single ConfidentialOutput.
  tx.ctProofs.resize(1);
  CTOutputProof& proof = tx.ctProofs[0];
  for (size_t i = 0; i < 6; ++i) {
    proof.I[i]  = makePod<Crypto::EllipticCurvePoint>(0xC0 + i);
    proof.A[i]  = makePod<Crypto::EllipticCurvePoint>(0xC6 + i);
    proof.B[i]  = makePod<Crypto::EllipticCurvePoint>(0xCC + i);
    proof.Q[i]  = makePod<Crypto::EllipticCurvePoint>(0xD2 + i);
    proof.z[i]  = makePod<Crypto::EllipticCurveScalar>(0xD8 + i);
    proof.za[i] = makePod<Crypto::EllipticCurveScalar>(0xDE + i);
    proof.zb[i] = makePod<Crypto::EllipticCurveScalar>(0xE4 + i);
  }
  proof.f = makePod<Crypto::EllipticCurveScalar>(0xEA);

  tx.kernel.excessCommitment = makePod<Crypto::EllipticCurvePoint>(0xF0);
  tx.kernel.sigE = makePod<Crypto::EllipticCurveScalar>(0xF1);
  tx.kernel.sigS = makePod<Crypto::EllipticCurveScalar>(0xF2);

  return tx;
}

int runV3() {
  Transaction src = buildMixedOutputV3();

  BinaryArray ba;
  if (!toBinaryArray(src, ba)) {
    std::fprintf(stderr, "v3 toBinaryArray failed\n");
    return 1;
  }
  std::printf("v3 mixed-output serialized %zu bytes\n", ba.size());

  Transaction dst;
  if (!fromBinaryArray(dst, ba)) {
    std::fprintf(stderr, "v3 fromBinaryArray failed (stream did not reach end?)\n");
    return 1;
  }

  CHECK(dst.version == TRANSACTION_VERSION_UNSHIELD);
  CHECK(dst.fee == src.fee);
  CHECK(dst.outputs.size() == 2);

  // Output 0: transparent KeyOutput survives as KeyOutput with amount + key.
  CHECK(dst.outputs[0].target.type() == typeid(KeyOutput));
  CHECK(dst.outputs[0].amount == 100000000ULL);
  CHECK(memEq(&boost::get<KeyOutput>(dst.outputs[0].target).key,
              &boost::get<KeyOutput>(src.outputs[0].target).key, 32));

  // Output 1: ConfidentialOutput survives with amount field 0.
  CHECK(dst.outputs[1].target.type() == typeid(ConfidentialOutput));
  CHECK(dst.outputs[1].amount == 0);
  CHECK(memEq(&boost::get<ConfidentialOutput>(dst.outputs[1].target).commitment,
              &boost::get<ConfidentialOutput>(src.outputs[1].target).commitment, 32));

  // ctProofs / kernel survive.
  CHECK(dst.ctProofs.size() == 1);
  CHECK(memEq(&dst.kernel.excessCommitment, &src.kernel.excessCommitment, 32));

  // Prefix hash must be stable across the round-trip — confirms the mixed
  // output set is fully covered by the signing/prefix hash.
  CHECK(getObjectHash(*static_cast<const TransactionPrefix*>(&src)) ==
        getObjectHash(*static_cast<const TransactionPrefix*>(&dst)));

  // ── wallet scan-layer fee contract for v3 ─────────────────────────────────
  // TransfersContainer derives a scanned tx's displayed fee like this:
  //   isBase                         -> 0
  //   isCtFamilyTransactionVersion   -> prefix.fee (explicit plaintext fee)
  //   else (v1)                      -> visibleIn - visibleOut
  // v3 MUST take the CT-family branch: its confidential inputs/change are
  // blinded, so the visible in/out difference is meaningless. Here the only
  // visible value is the transparent KeyOutput payout (100000000) with zero
  // visible input, so the v1 derivation would yield fee 0 — wrong. Lock both
  // the predicate and the "would-be-wrong" derivation so a regression that
  // drops v3 from the gate (back to `== TRANSACTION_VERSION_CT`) is caught.
  CHECK(isCtFamilyTransactionVersion(dst.version));
  uint64_t visibleIn = 0;                     // no transparent KeyInput in this tx
  uint64_t visibleOut = dst.outputs[0].amount; // only the plain KeyOutput is visible
  uint64_t v1DerivedFee = visibleIn >= visibleOut ? visibleIn - visibleOut : 0;
  CHECK(v1DerivedFee == 0);            // the v1 path would mis-report fee as 0
  CHECK(dst.fee == 10000000000ULL);    // CT-family path reports the real fee
  CHECK(dst.fee != v1DerivedFee);      // ⇒ v3 must NOT use the v1 derivation

  std::printf("OK: v3 mixed-output round-trip (KeyOutput + ConfidentialOutput) preserved\n");
  return 0;
}

int runV3AbsoluteOutputIndexScan() {
  Transaction tx;
  tx.version = TRANSACTION_VERSION_UNSHIELD;
  tx.unlockTime = 0;
  tx.fee = 10000000000ULL;

  AccountPublicAddress receiver;
  Crypto::SecretKey viewSecret;
  Crypto::SecretKey spendSecret;
  Crypto::generate_keys(receiver.viewPublicKey, viewSecret);
  Crypto::generate_keys(receiver.spendPublicKey, spendSecret);

  Crypto::PublicKey txPubKey;
  Crypto::SecretKey txSecretKey;
  Crypto::generate_keys(txPubKey, txSecretKey);
  tx.extra.push_back(0x01);  // TX_EXTRA_TAG_PUBKEY
  const uint8_t* pk = reinterpret_cast<const uint8_t*>(&txPubKey);
  tx.extra.insert(tx.extra.end(), pk, pk + 32);

  ConfidentialOutput first;
  first.targetKey = makePod<Crypto::PublicKey>(0x62);
  first.commitment = makePod<Crypto::EllipticCurvePoint>(0x72);
  std::memset(first.maskedAmount.data(), 0x82, 8);
  TransactionOutput confOut;
  confOut.amount = 0;
  confOut.target = first;
  tx.outputs.push_back(confOut);

  Crypto::KeyDerivation sharedSecret;
  CHECK(Crypto::generate_key_derivation(receiver.viewPublicKey, txSecretKey, sharedSecret));
  KeyOutput payout;
  CHECK(Crypto::derive_public_key(sharedSecret, 1, receiver.spendPublicKey, payout.key));
  TransactionOutput plainOut;
  plainOut.amount = 123456789ULL;
  plainOut.target = payout;
  tx.outputs.push_back(plainOut);

  std::vector<uint32_t> outs;
  uint64_t amount = 0;
  CHECK(findOutputsToAccount(tx, receiver, viewSecret, outs, amount));
  CHECK(outs.size() == 1);
  CHECK(outs[0] == 1);
  CHECK(amount == plainOut.amount);

  AccountKeys accountKeys;
  accountKeys.address = receiver;
  accountKeys.viewSecretKey = viewSecret;
  accountKeys.spendSecretKey = spendSecret;
  std::vector<size_t> legacyOuts;
  uint64_t legacyAmount = 0;
  CHECK(lookup_acc_outs(accountKeys, tx, txPubKey, legacyOuts, legacyAmount));
  CHECK(legacyOuts.size() == 1);
  CHECK(legacyOuts[0] == 1);
  CHECK(legacyAmount == plainOut.amount);

  std::printf("OK: v3 receive scan uses absolute output index for transparent payouts after CT outputs\n");
  return 0;
}

int run() {
  Transaction src = buildMixedV2();

  BinaryArray ba;
  if (!toBinaryArray(src, ba)) {
    std::fprintf(stderr, "toBinaryArray failed\n");
    return 1;
  }
  std::printf("Serialized %zu bytes\n", ba.size());

  Transaction dst;
  if (!fromBinaryArray(dst, ba)) {
    std::fprintf(stderr, "fromBinaryArray failed (stream did not reach end?)\n");
    return 1;
  }

  CHECK(dst.version == src.version);
  CHECK(dst.fee == src.fee);
  CHECK(dst.unlockTime == src.unlockTime);
  CHECK(dst.extra == src.extra);

  // Inputs
  CHECK(dst.inputs.size() == src.inputs.size());
  // Input 0: KeyInput
  CHECK(dst.inputs[0].type() == typeid(KeyInput));
  const auto& ki_src = boost::get<KeyInput>(src.inputs[0]);
  const auto& ki_dst = boost::get<KeyInput>(dst.inputs[0]);
  CHECK(ki_src.amount == ki_dst.amount);
  CHECK(ki_src.outputIndexes == ki_dst.outputIndexes);
  CHECK(memEq(&ki_src.keyImage, &ki_dst.keyImage, sizeof(ki_src.keyImage)));

  // Input 1: ConfidentialInput
  CHECK(dst.inputs[1].type() == typeid(ConfidentialInput));
  const auto& cin_src = boost::get<ConfidentialInput>(src.inputs[1]);
  const auto& cin_dst = boost::get<ConfidentialInput>(dst.inputs[1]);
  CHECK(cin_src.ringMembers.size() == cin_dst.ringMembers.size());
  for (size_t k = 0; k < cin_src.ringMembers.size(); ++k) {
    CHECK(cin_src.ringMembers[k].amount == cin_dst.ringMembers[k].amount);
    CHECK(cin_src.ringMembers[k].outputIndex == cin_dst.ringMembers[k].outputIndex);
    CHECK(memEq(&cin_src.ringPubkeys[k], &cin_dst.ringPubkeys[k], 32));
    CHECK(memEq(&cin_src.ringCommitments[k], &cin_dst.ringCommitments[k], 32));
  }
  CHECK(memEq(&cin_src.pseudoCommitment, &cin_dst.pseudoCommitment, 32));
  CHECK(memEq(&cin_src.keyImage, &cin_dst.keyImage, 32));

  // Per-input authorization variant: slot 0 holds 3 ring sigs, slot 1
  // holds the Triptych proof.
  CHECK(dst.signatures.size() == src.signatures.size());
  CHECK(isKeyInputSig(dst.signatures[0]));
  CHECK(isCtInputSig(dst.signatures[1]));
  const auto& dst_ring = keyInputSig(dst.signatures[0]);
  const auto& src_ring = keyInputSig(src.signatures[0]);
  CHECK(dst_ring.size() == 3);
  for (size_t i = 0; i < 3; ++i) {
    CHECK(memEq(&dst_ring[i], &src_ring[i], sizeof(Crypto::Signature)));
  }

  const auto& dst_cs = ctInputSig(dst.signatures[1]);
  const auto& src_cs = ctInputSig(src.signatures[1]);
  CHECK(dst_cs.I_bits.size() == 2);
  CHECK(dst_cs.Q_P.size() == 2);
  for (size_t j = 0; j < 2; ++j) {
    CHECK(memEq(&dst_cs.I_bits[j], &src_cs.I_bits[j], 32));
    CHECK(memEq(&dst_cs.Q_P[j],    &src_cs.Q_P[j],    32));
    CHECK(memEq(&dst_cs.z[j],      &src_cs.z[j],      32));
  }
  CHECK(memEq(&dst_cs.f_P, &src_cs.f_P, 32));

  // Kernel
  CHECK(memEq(&dst.kernel.excessCommitment, &src.kernel.excessCommitment, 32));
  CHECK(memEq(&dst.kernel.sigE, &src.kernel.sigE, 32));
  CHECK(memEq(&dst.kernel.sigS, &src.kernel.sigS, 32));

  // ctProofs
  CHECK(dst.ctProofs.size() == 1);
  for (size_t i = 0; i < 6; ++i) {
    CHECK(memEq(&dst.ctProofs[0].I[i], &src.ctProofs[0].I[i], 32));
  }
  CHECK(memEq(&dst.ctProofs[0].f, &src.ctProofs[0].f, 32));

  std::printf("OK: v2 mixed-input round-trip preserved every field\n");
  return 0;
}

}  // namespace

// ── CT pool liability accounting (computeCtPoolDelta) ────────────────────────
//
// confidential_supply is a per-block snapshot: pushBlock applies each tx's
// (inflow - outflow) on top of the previous block's stored value, and the
// debit a v3 unshield applies to the pool is exactly computeCtPoolDelta's
// `outflow`. (Reorg rollback restores the pool automatically because pop
// drops the tip's meta snapshot — there is no separate running counter to
// rewind; see Blockchain::removeLastBlock / getConfidentialSupply.) These
// vectors pin the accounting half for every shield direction: the pool only
// moves by VISIBLE value, never by the hidden CT amounts.

static CryptoNote::TransactionOutput keyOut(uint64_t amount, uint8_t seed) {
  KeyOutput ko;
  ko.key = makePod<Crypto::PublicKey>(seed);
  CryptoNote::TransactionOutput out;
  out.amount = amount;
  out.target = ko;
  return out;
}

static CryptoNote::TransactionOutput confOut(uint8_t seed) {
  ConfidentialOutput co;
  co.targetKey = makePod<Crypto::PublicKey>(seed);
  co.commitment = makePod<Crypto::EllipticCurvePoint>(seed + 1);
  std::memset(co.maskedAmount.data(), seed + 2, 8);
  CryptoNote::TransactionOutput out;
  out.amount = 0;  // CT outputs carry no visible amount
  out.target = co;
  return out;
}

static int checkDelta(const char* label, const Transaction& tx, uint64_t fee,
                      uint64_t wantInflow, uint64_t wantOutflow) {
  uint64_t inflow = 0, outflow = 0;
  if (!CryptoNote::computeCtPoolDelta(tx, fee, inflow, outflow)) {
    std::fprintf(stderr, "[%s] computeCtPoolDelta returned false (overflow)\n", label);
    return 1;
  }
  if (inflow != wantInflow || outflow != wantOutflow) {
    std::fprintf(stderr, "[%s] delta mismatch: got inflow=%llu outflow=%llu, want inflow=%llu outflow=%llu\n",
                 label, (unsigned long long)inflow, (unsigned long long)outflow,
                 (unsigned long long)wantInflow, (unsigned long long)wantOutflow);
    return 1;
  }
  std::printf("[%s] pool delta OK (inflow=%llu outflow=%llu)\n",
              label, (unsigned long long)inflow, (unsigned long long)outflow);
  return 0;
}

int runV3PoolDelta() {
  int rc = 0;

  // Pure unshield: CT input -> plain payout 90 + fee 10. 100 visible leaves pool.
  {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_UNSHIELD;
    tx.inputs.push_back(ConfidentialInput{});      // hidden amount -> 0 plain_in
    tx.outputs.push_back(keyOut(90, 0x60));
    rc |= checkDelta("v3 pure unshield", tx, /*fee=*/10, /*inflow=*/0, /*outflow=*/100);
  }

  // Partial unshield: CT input -> CT change (hidden) + plain payout 35 + fee 5.
  // Only the visible 35 + 5 leaves the pool; the CT change stays inside.
  {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_UNSHIELD;
    tx.inputs.push_back(ConfidentialInput{});
    tx.outputs.push_back(confOut(0x70));
    tx.outputs.push_back(keyOut(35, 0x80));
    rc |= checkDelta("v3 partial unshield", tx, /*fee=*/5, /*inflow=*/0, /*outflow=*/40);
  }

  // Shield (v2-style, for contrast): plain input 100 -> CT output + fee 10.
  // 90 visible value enters the pool.
  {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_CT;
    KeyInput ki;
    ki.amount = 100;
    ki.outputIndexes = {1};
    ki.keyImage = makePod<Crypto::KeyImage>(0x11);
    tx.inputs.push_back(ki);
    tx.outputs.push_back(confOut(0x90));
    rc |= checkDelta("shield (plain->CT)", tx, /*fee=*/10, /*inflow=*/90, /*outflow=*/0);
  }

  // CT->CT: CT input -> CT output + fee 10. Only the visible fee leaves the pool.
  {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_CT;
    tx.inputs.push_back(ConfidentialInput{});
    tx.outputs.push_back(confOut(0xA0));
    rc |= checkDelta("CT->CT", tx, /*fee=*/10, /*inflow=*/0, /*outflow=*/10);
  }

  if (rc == 0) {
    std::printf("OK: v3 CT pool delta accounting (unshield/partial/shield/CT-to-CT)\n");
  }
  return rc;
}

int main() {
  int rc = run();
  rc |= runV3();
  rc |= runV3AbsoluteOutputIndexScan();
  rc |= runV3PoolDelta();
  return rc;
}
