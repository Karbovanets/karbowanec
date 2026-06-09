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

#include "PqTransactionBuilder.h"

#include <cstring>
#include <stdexcept>

#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "crypto/crypto.h"
#include "CryptoNoteCore/PqValidation.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "crypto_pq/PqOutputBuilder.h"

namespace CryptoNote {

CryptoPQ::Hash256 pqTransactionInputsHash(const TransactionPrefix& tx) {
  std::vector<CryptoPQ::InputRef> refs;
  refs.reserve(tx.inputs.size());
  for (const auto& input : tx.inputs) {
    CryptoPQ::InputRef ref{};
    if (input.type() == typeid(PqInput)) {
      const PqInput& in = boost::get<PqInput>(input);
      std::memcpy(ref.prevTxid.data(), in.prevTxid.data, 32);
      ref.prevOutIndex = in.prevOutIndex;
    } else if (input.type() == typeid(KeyInput)) {
      // Outpoint is hidden by the ring; the key image is the on-wire per-input
      // identifier (see header note on the cemented bridge convention).
      const KeyInput& in = boost::get<KeyInput>(input);
      std::memcpy(ref.prevTxid.data(), in.keyImage.data, 32);
      ref.prevOutIndex = 0;
    } else {
      throw std::runtime_error("pqTransactionInputsHash: unsupported input type");
    }
    refs.push_back(ref);
  }
  return CryptoPQ::inputsHash(refs);
}

Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const CryptoPQ::DsaPublicKey& spendPub,
                               const CryptoPQ::DsaSecretKey& spendSk,
                               uint64_t unlockTime) {
  if (inputs.empty()) {
    throw std::runtime_error("buildPqTransaction: no inputs");
  }
  if (outputs.empty()) {
    throw std::runtime_error("buildPqTransaction: no outputs");
  }
  if (inputs.size() > parameters::MAX_PQ_INPUTS_PER_TX) {
    throw std::runtime_error("buildPqTransaction: too many inputs");
  }
  if (outputs.size() > parameters::MAX_PQ_OUTPUTS_PER_TX) {
    throw std::runtime_error("buildPqTransaction: too many outputs");
  }

  Transaction tx;
  tx.version = TRANSACTION_VERSION_PQ;
  tx.txType = TX_PQ;
  tx.unlockTime = unlockTime;
  tx.extra.clear();
  tx.signatures.clear();  // PQ inputs carry their own ML-DSA sig, not this vector.

  // Inputs (unsigned for now): reveal the spender's long-term spend pubkey and
  // the per-output rho. spend_commit(spendPub, rho) must match the referenced
  // output's commitment, which holds because the recipient (this wallet) is the
  // spender and rho is the output's own rho.
  tx.inputs.reserve(inputs.size());
  uint64_t sumIn = 0;
  for (const auto& si : inputs) {
    PqInput in;
    in.prevTxid = si.prevTxid;
    in.prevOutIndex = si.prevOutIndex;
    in.authPub.assign(spendPub.begin(), spendPub.end());
    in.rhoReveal.assign(si.rho.begin(), si.rho.end());
    in.signature.assign(PQ_SIGNATURE_SIZE, 0);  // filled after digest
    tx.inputs.push_back(std::move(in));
    if (sumIn + si.amount < sumIn) {
      throw std::runtime_error("buildPqTransaction: input amount overflow");
    }
    sumIn += si.amount;
  }

  // inputsHash binds the canonical input order; the same value seeds every
  // output's out_context (the receiver recomputes it identically).
  CryptoPQ::Hash256 ih = pqTransactionInputsHash(tx);

  // Outputs: out_context uses the output's index within tx.outputs (the same
  // index the receiver scans by), so build in order.
  tx.outputs.reserve(outputs.size());
  uint64_t sumOut = 0;
  for (size_t i = 0; i < outputs.size(); ++i) {
    const PqSendOutput& so = outputs[i];
    CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(
        so.recipientViewPub, so.recipientSpendPub, ih,
        static_cast<uint32_t>(i), so.amount);

    PqOutput po;
    po.kemCt.assign(built.kemCt.begin(), built.kemCt.end());
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);

    TransactionOutput out;
    out.amount = so.amount;
    out.target = std::move(po);
    tx.outputs.push_back(std::move(out));

    if (sumOut + so.amount < sumOut) {
      throw std::runtime_error("buildPqTransaction: output amount overflow");
    }
    sumOut += so.amount;
  }

  if (sumIn < sumOut) {
    throw std::runtime_error("buildPqTransaction: outputs exceed inputs");
  }
  const uint64_t fee = sumIn - sumOut;

  // Sign every input over the canonical digest (excludes the signature field).
  CryptoPQ::Hash256 digest = pqSigningDigest(tx, fee);
  for (auto& input : tx.inputs) {
    PqInput& in = boost::get<PqInput>(input);
    CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(spendSk, digest.data(), digest.size());
    in.signature.assign(sig.begin(), sig.end());
  }

  return tx;
}

Transaction buildBridgeTransaction(std::vector<BridgeLegacyInput>& inputs,
                                   const std::vector<PqSendOutput>& outputs,
                                   uint64_t unlockTime) {
  if (inputs.empty()) {
    throw std::runtime_error("buildBridgeTransaction: no inputs");
  }
  if (outputs.empty()) {
    throw std::runtime_error("buildBridgeTransaction: no outputs");
  }
  if (outputs.size() > parameters::MAX_PQ_OUTPUTS_PER_TX) {
    throw std::runtime_error("buildBridgeTransaction: too many outputs");
  }

  Transaction tx;
  tx.version = TRANSACTION_VERSION_PQ;
  tx.txType = TX_BRIDGE;
  tx.unlockTime = unlockTime;
  tx.extra.clear();

  // Classical KeyInputs (one ring each). Generate the key image + ephemeral key
  // for the real output; record the per-input ephemeral secret for signing.
  std::vector<KeyPair> ephKeys(inputs.size());
  uint64_t sumIn = 0;
  tx.inputs.reserve(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const TransactionTypes::InputKeyInfo& info = inputs[i].keyInfo;

    KeyInput in;
    in.amount = info.amount;
    generate_key_image_helper(inputs[i].senderKeys,
                              info.realOutput.transactionPublicKey,
                              info.realOutput.outputInTransaction,
                              ephKeys[i], in.keyImage);
    for (const auto& o : info.outputs) {
      in.outputIndexes.push_back(o.outputIndex);
    }
    in.outputIndexes = absolute_output_offsets_to_relative(in.outputIndexes);
    tx.inputs.push_back(in);

    if (sumIn + info.amount < sumIn) {
      throw std::runtime_error("buildBridgeTransaction: input amount overflow");
    }
    sumIn += info.amount;
  }

  // Wallet-side inputsHash (key-image based for bridge); seeds out_context.
  CryptoPQ::Hash256 ih = pqTransactionInputsHash(tx);

  // PQ outputs.
  tx.outputs.reserve(outputs.size());
  uint64_t sumOut = 0;
  for (size_t i = 0; i < outputs.size(); ++i) {
    const PqSendOutput& so = outputs[i];
    CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(
        so.recipientViewPub, so.recipientSpendPub, ih,
        static_cast<uint32_t>(i), so.amount);

    PqOutput po;
    po.kemCt.assign(built.kemCt.begin(), built.kemCt.end());
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);

    TransactionOutput out;
    out.amount = so.amount;
    out.target = std::move(po);
    tx.outputs.push_back(std::move(out));

    if (sumOut + so.amount < sumOut) {
      throw std::runtime_error("buildBridgeTransaction: output amount overflow");
    }
    sumOut += so.amount;
  }

  if (sumIn < sumOut) {
    throw std::runtime_error("buildBridgeTransaction: outputs exceed inputs");
  }

  // Ring-sign each KeyInput over the prefix hash (covers the PQ outputs).
  Crypto::Hash prefixHash = getObjectHash(static_cast<const TransactionPrefix&>(tx));
  tx.signatures.resize(tx.inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const TransactionTypes::InputKeyInfo& info = inputs[i].keyInfo;
    const KeyInput& in = boost::get<KeyInput>(tx.inputs[i]);

    std::vector<const Crypto::PublicKey*> keysPtrs;
    keysPtrs.reserve(info.outputs.size());
    for (const auto& o : info.outputs) {
      keysPtrs.push_back(&o.targetKey);
    }

    std::vector<Crypto::Signature> sigs(keysPtrs.size());
    Crypto::generate_ring_signature(prefixHash, in.keyImage, keysPtrs,
                                    ephKeys[i].secretKey,
                                    info.realOutput.transactionIndex, sigs.data());
    tx.signatures[i] = std::move(sigs);
  }

  return tx;
}

}  // namespace CryptoNote
