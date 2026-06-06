// Copyright (c) 2026, The Karbo developers
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

#include "PqValidation.h"

#include <cstring>
#include <unordered_set>

#include "CryptoNoteConfig.h"
#include "CryptoNoteTools.h"
#include "PqTxType.h"

#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"

namespace CryptoNote {

namespace {

bool pqInputFieldsValid(const PqInput& in) {
  return in.authPub.size() == PQ_AUTH_PUB_SIZE &&
         in.rhoReveal.size() == PQ_RHO_SIZE &&
         in.signature.size() == PQ_SIGNATURE_SIZE;
}

bool pqOutputFieldsValid(const PqOutput& o) {
  return o.kemCt.size() == PQ_KEM_CIPHERTEXT_SIZE &&
         o.encPayload.size() == PQ_ENC_PAYLOAD_SIZE;
}

CryptoPQ::DsaPublicKey toDsaPub(const std::vector<uint8_t>& v) {
  CryptoPQ::DsaPublicKey k;
  std::memcpy(k.data(), v.data(), k.size());
  return k;
}

CryptoPQ::Rho toRho(const std::vector<uint8_t>& v) {
  CryptoPQ::Rho r;
  std::memcpy(r.data(), v.data(), r.size());
  return r;
}

Crypto::Hash toHash(const CryptoPQ::Hash256& h) {
  Crypto::Hash out;
  std::memcpy(out.data, h.data(), 32);
  return out;
}

bool fail(std::string* error, const char* msg) {
  if (error) *error = msg;
  return false;
}

}  // namespace

CryptoPQ::Hash256 pqSigningDigest(const Transaction& tx, uint64_t fee) {
  CryptoPQ::UnsignedTx u;
  u.version = tx.version;
  u.fee = fee;
  for (const auto& in : tx.inputs) {
    const PqInput& pin = boost::get<PqInput>(in);
    CryptoPQ::DigestInput di;
    std::memcpy(di.prevTxid.data(), pin.prevTxid.data, 32);
    di.prevOutIndex = pin.prevOutIndex;
    di.authPub = toDsaPub(pin.authPub);
    di.rhoReveal = toRho(pin.rhoReveal);
    u.inputs.push_back(di);
  }
  for (const auto& out : tx.outputs) {
    const PqOutput& po = boost::get<PqOutput>(out.target);
    CryptoPQ::DigestOutput dou;
    dou.type = 0x10;  // PQ output variant tag
    dou.amount = out.amount;
    std::memcpy(dou.kemCt.data(), po.kemCt.data(), dou.kemCt.size());
    std::memcpy(dou.encPayload.data(), po.encPayload.data(), dou.encPayload.size());
    std::memcpy(dou.spendCommit.data(), po.spendCommit.data, 32);
    u.outputs.push_back(dou);
  }
  return CryptoPQ::txSigningDigest(u);
}

Crypto::Hash pqNullifier(const PqInput& in) {
  if (!pqInputFieldsValid(in)) {
    return Crypto::Hash{};
  }
  return toHash(CryptoPQ::nullifier(toDsaPub(in.authPub), toRho(in.rhoReveal)));
}

bool checkPqTransactionSemantic(const Transaction& tx, std::string* error) {
  if (tx.txType != TX_PQ) {
    return fail(error, "not a TX_PQ subtype");
  }
  if (tx.inputs.empty() || tx.outputs.empty()) {
    return fail(error, "TX_PQ with empty inputs or outputs");
  }
  if (tx.inputs.size() > parameters::MAX_PQ_INPUTS_PER_TX) {
    return fail(error, "too many PQ inputs");
  }
  if (tx.outputs.size() > parameters::MAX_PQ_OUTPUTS_PER_TX) {
    return fail(error, "too many PQ outputs");
  }
  if (tx.unlockTime != 0) {
    return fail(error, "PQ tx must have unlockTime == 0");
  }
  if (!tx.signatures.empty()) {
    return fail(error, "PQ tx must not use the legacy signatures vector");
  }

  for (const auto& in : tx.inputs) {
    if (in.type() != typeid(PqInput)) {
      return fail(error, "TX_PQ input is not a PqInput");
    }
    if (!pqInputFieldsValid(boost::get<PqInput>(in))) {
      return fail(error, "PqInput field has wrong length");
    }
  }
  for (const auto& out : tx.outputs) {
    if (out.target.type() != typeid(PqOutput)) {
      return fail(error, "TX_PQ output is not a PqOutput");
    }
    if (out.amount == 0) {
      return fail(error, "PQ output with zero amount");
    }
    if (!pqOutputFieldsValid(boost::get<PqOutput>(out.target))) {
      return fail(error, "PqOutput field has wrong length");
    }
  }

  if (toBinaryArray(tx).size() > parameters::MAX_PQ_TX_SIZE) {
    return fail(error, "PQ tx exceeds MAX_PQ_TX_SIZE");
  }
  return true;
}

bool checkBridgeTransactionSemantic(const Transaction& tx, std::string* error) {
  if (tx.txType != TX_BRIDGE) {
    return fail(error, "not a TX_BRIDGE subtype");
  }
  if (tx.inputs.empty() || tx.outputs.empty()) {
    return fail(error, "TX_BRIDGE with empty inputs or outputs");
  }
  if (tx.outputs.size() > parameters::MAX_PQ_OUTPUTS_PER_TX) {
    return fail(error, "too many bridge PQ outputs");
  }
  if (tx.unlockTime != 0) {
    return fail(error, "bridge tx must have unlockTime == 0");
  }
  // One-way: classical inputs only.
  for (const auto& in : tx.inputs) {
    if (in.type() != typeid(KeyInput)) {
      return fail(error, "TX_BRIDGE input is not a classical KeyInput");
    }
  }
  // Outputs must all be PQ.
  for (const auto& out : tx.outputs) {
    if (out.target.type() != typeid(PqOutput)) {
      return fail(error, "TX_BRIDGE output is not a PqOutput");
    }
    if (out.amount == 0) {
      return fail(error, "bridge PQ output with zero amount");
    }
    if (!pqOutputFieldsValid(boost::get<PqOutput>(out.target))) {
      return fail(error, "bridge PqOutput field has wrong length");
    }
  }
  if (toBinaryArray(tx).size() > parameters::MAX_PQ_TX_SIZE) {
    return fail(error, "bridge tx exceeds MAX_PQ_TX_SIZE");
  }
  return true;
}

bool checkPqTransactionInputs(const Transaction& tx,
                             const std::vector<PqResolvedInput>& resolved,
                             uint64_t minFeePerByte,
                             std::vector<Crypto::Hash>* outNullifiers,
                             std::string* error) {
  if (resolved.size() != tx.inputs.size()) {
    return fail(error, "resolved inputs size mismatch");
  }

  std::unordered_set<Crypto::Hash> nullifiers;
  std::vector<Crypto::Hash> computed;
  computed.reserve(tx.inputs.size());

  uint64_t sumIn = 0;
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    if (tx.inputs[i].type() != typeid(PqInput)) {
      return fail(error, "TX_PQ input is not a PqInput");
    }
    const PqInput& in = boost::get<PqInput>(tx.inputs[i]);
    if (!pqInputFieldsValid(in)) {
      return fail(error, "PqInput field has wrong length");
    }

    const PqResolvedInput& r = resolved[i];
    if (!r.exists) {
      return fail(error, "referenced output does not exist");
    }
    if (!r.isPqOutput) {
      return fail(error, "referenced output is not a PqOutput");
    }
    if (r.isCoinbase) {
      return fail(error, "PQ input spends a coinbase output");
    }

    // Ownership / authorization binding.
    Crypto::Hash sc = toHash(CryptoPQ::spendCommit(toDsaPub(in.authPub), toRho(in.rhoReveal)));
    if (sc != r.spendCommit) {
      return fail(error, "spend_commit mismatch");
    }

    // Intra-tx nullifier uniqueness.
    Crypto::Hash nf = pqNullifier(in);
    if (!nullifiers.insert(nf).second) {
      return fail(error, "duplicate nullifier within transaction");
    }
    computed.push_back(nf);

    // Overflow-safe input sum.
    if (sumIn + r.amount < sumIn) {
      return fail(error, "input amount overflow");
    }
    sumIn += r.amount;
  }

  uint64_t sumOut = 0;
  for (const auto& out : tx.outputs) {
    if (sumOut + out.amount < sumOut) {
      return fail(error, "output amount overflow");
    }
    sumOut += out.amount;
  }

  if (sumIn < sumOut) {
    return fail(error, "outputs exceed inputs");
  }
  uint64_t fee = sumIn - sumOut;

  // Fee floor: fee >= minFeePerByte * size (overflow-safe).
  uint64_t size = toBinaryArray(tx).size();
  if (minFeePerByte != 0 && size != 0) {
    if (size > UINT64_MAX / minFeePerByte) {
      return fail(error, "fee floor overflow");  // implausibly large tx
    }
    uint64_t floor = minFeePerByte * size;
    if (fee < floor) {
      return fail(error, "fee below minimum");
    }
  }

  // ML-DSA signature verification over the recomputed digest.
  CryptoPQ::Hash256 digest = pqSigningDigest(tx, fee);
  for (const auto& input : tx.inputs) {
    const PqInput& in = boost::get<PqInput>(input);
    CryptoPQ::DsaPublicKey pub = toDsaPub(in.authPub);
    CryptoPQ::DsaSignature sig;
    std::memcpy(sig.data(), in.signature.data(), sig.size());
    if (!CryptoPQ::dsa_verify(pub, digest.data(), digest.size(), sig)) {
      return fail(error, "ML-DSA signature verification failed");
    }
  }

  if (outNullifiers) {
    *outNullifiers = std::move(computed);
  }
  return true;
}

}  // namespace CryptoNote
