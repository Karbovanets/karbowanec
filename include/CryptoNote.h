// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <boost/variant.hpp>
#include "android.h"
#include "CryptoTypes.h"

namespace CryptoNote {

struct BaseInput {
  uint32_t blockIndex;
};

struct KeyInput {
  uint64_t amount;
  std::vector<uint32_t> outputIndexes;
  Crypto::KeyImage keyImage;
};

struct KeyOutput {
  Crypto::PublicKey key;
};

// --- PQ Phase 1 wire types (transaction version 2) ------------------------
// Plain amounts: the value lives in the enclosing TransactionOutput.amount.
// Fixed-size byte blobs (consensus-enforced lengths). Stored as vectors so the
// variant stays small; the serializer reads/writes exactly these many bytes.
constexpr size_t PQ_KEM_CIPHERTEXT_SIZE = 1088;  // ML-KEM-768 ciphertext
constexpr size_t PQ_ENC_PAYLOAD_SIZE    = 48;    // ChaCha20-Poly1305(rho) = 32 ct + 16 tag
constexpr size_t PQ_AUTH_PUB_SIZE       = 1952;  // ML-DSA-65 public (spend) key
constexpr size_t PQ_RHO_SIZE            = 32;
constexpr size_t PQ_SIGNATURE_SIZE      = 3309;  // ML-DSA-65 signature

// One PQ input. The ML-DSA signature lives INSIDE the input (not in the legacy
// Transaction.signatures vector). authPub is the spender's long-term ML-DSA
// spend public key (see docs/PQ-OWNERSHIP-FIX.md).
struct PqInput {
  Crypto::Hash         prevTxid;
  uint32_t             prevOutIndex;
  std::vector<uint8_t> authPub;     // PQ_AUTH_PUB_SIZE
  std::vector<uint8_t> rhoReveal;   // PQ_RHO_SIZE
  std::vector<uint8_t> signature;   // PQ_SIGNATURE_SIZE
};

// One PQ output target. amount is plain (in TransactionOutput.amount).
struct PqOutput {
  std::vector<uint8_t> kemCt;       // PQ_KEM_CIPHERTEXT_SIZE
  std::vector<uint8_t> encPayload;  // PQ_ENC_PAYLOAD_SIZE
  Crypto::Hash         spendCommit; // SHA3-256(spend_pub || rho)
};

typedef boost::variant<BaseInput, KeyInput, PqInput> TransactionInput;

typedef boost::variant<KeyOutput, PqOutput> TransactionOutputTarget;

struct TransactionOutput {
  uint64_t amount;
  TransactionOutputTarget target;
};

using TransactionInputs = std::vector<TransactionInput>;

struct TransactionPrefix {
  uint8_t version;
  // PQ sub-type (TX_PQ / TX_BRIDGE / TX_FREE_REG). Only present on the wire for
  // version >= TRANSACTION_VERSION_PQ; 0 for legacy v1.
  uint8_t txType = 0;
  uint64_t unlockTime;
  TransactionInputs inputs;
  std::vector<TransactionOutput> outputs;
  std::vector<uint8_t> extra;
};

struct Transaction : public TransactionPrefix {
  std::vector<std::vector<Crypto::Signature>> signatures;
};

struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

struct ParentBlock {
  uint8_t majorVersion;
  uint8_t minorVersion;
  Crypto::Hash previousBlockHash;
  uint16_t transactionCount;
  std::vector<Crypto::Hash> baseTransactionBranch;
  Transaction baseTransaction;
  std::vector<Crypto::Hash> blockchainBranch;
};

struct BlockHeader {
  uint8_t majorVersion;
  uint8_t minorVersion;
  uint32_t nonce;
  uint64_t timestamp;
  Crypto::Hash previousBlockHash;
};

struct Block : public BlockHeader {
  ParentBlock parentBlock;
  Transaction baseTransaction;
  Crypto::Signature signature;
  std::vector<Crypto::Hash> transactionHashes;
};

struct AccountKeys {
  AccountPublicAddress address;
  Crypto::SecretKey spendSecretKey;
  Crypto::SecretKey viewSecretKey;
};

struct KeyPair {
  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
};

using BinaryArray = std::vector<uint8_t>;

}
