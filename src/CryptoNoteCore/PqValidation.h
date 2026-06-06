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

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoTypes.h"
#include "crypto_pq/PqHash.h"

// Consensus validation for PQ Phase 1 transactions (TRANSACTION_VERSION_PQ,
// subtype TX_PQ). Spec §9, amended by the ownership-model fix
// (docs/PQ-OWNERSHIP-FIX.md). These functions are CONTEXT-FREE: chain-state
// lookups (resolving referenced outputs, checking the on-disk nullifier set,
// height gating) are done by the caller (Blockchain) and fed in here, so the
// consensus crypto is deterministic and unit-testable in isolation.

namespace CryptoNote {

// A referenced output resolved from the chain, parallel to a PqInput.
struct PqResolvedInput {
  Crypto::Hash spendCommit;       // referenced PqOutput.spendCommit
  uint64_t     amount = 0;        // referenced output amount (plain)
  bool         exists = false;    // referenced output was found
  bool         isPqOutput = false;// referenced output target is a PqOutput
  bool         isCoinbase = false;// referenced output is from a coinbase tx
};

// Context-free shape / semantic checks for one v2 TX_PQ transaction:
//  - subtype == TX_PQ
//  - non-empty; all inputs PqInput; all outputs PqOutput (mixed-family reject)
//  - inputs <= MAX_PQ_INPUTS_PER_TX, outputs <= MAX_PQ_OUTPUTS_PER_TX
//  - serialized size <= MAX_PQ_TX_SIZE
//  - every PQ blob field has the exact consensus length
//  - every output amount != 0
//  - unlockTime == 0; legacy signatures vector empty
bool checkPqTransactionSemantic(const Transaction& tx, std::string* error);

// Context-free shape checks for one v2 TX_BRIDGE transaction (one-way legacy ->
// PQ migration). The input side is classical (KeyInput + ring signatures,
// validated by the existing v1 path); only the bridge-specific shape is checked
// here:
//  - subtype == TX_BRIDGE
//  - non-empty; every input is a KeyInput (no PqInput); every output is a
//    PqOutput (no classical output) -> one-way, no mixed families
//  - outputs <= MAX_PQ_OUTPUTS_PER_TX; PqOutput field lengths exact; amount != 0
//  - unlockTime == 0; serialized size <= MAX_PQ_TX_SIZE
// Balance, ring signatures, key-image double-spend and fee floor are enforced by
// the classical pipeline (check_tx_semantic / checkTransactionInputs).
bool checkBridgeTransactionSemantic(const Transaction& tx, std::string* error);

// Context-free input/balance/signature checks given resolved referenced outputs
// (resolved[i] corresponds to tx.inputs[i]). On success, *outNullifiers (if not
// null) is filled with each input's nullifier so the caller can test them
// against the on-disk pq_nullifiers set.
//
// Checks, in order (fail fast on the cheap ones):
//  - resolved.size() == inputs.size(); every referenced output exists, is a
//    PqOutput, and is not coinbase
//  - spend_commit(authPub, rhoReveal) == referenced spendCommit
//  - intra-tx nullifier uniqueness
//  - balance: sum(referenced amounts) == sum(output amounts) + fee, fee >= 0
//  - fee >= minFeePerByte * serialized_size
//  - ML-DSA verify each input over the recomputed txSigningDigest
bool checkPqTransactionInputs(const Transaction& tx,
                             const std::vector<PqResolvedInput>& resolved,
                             uint64_t minFeePerByte,
                             std::vector<Crypto::Hash>* outNullifiers,
                             std::string* error);

// Helper: recompute one PQ input's nullifier. Returns a zero hash if the input
// fields are malformed (wrong sizes).
Crypto::Hash pqNullifier(const PqInput& in);

// The spec §8.1 signing digest for a v2 TX_PQ given its computed fee
// (fee = sum(referenced amounts) - sum(output amounts)). The spender signs this
// with its ML-DSA spend secret; the validator recomputes and verifies it.
CryptoPQ::Hash256 pqSigningDigest(const Transaction& tx, uint64_t fee);

}  // namespace CryptoNote
