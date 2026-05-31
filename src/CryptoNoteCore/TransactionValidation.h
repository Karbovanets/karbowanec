// Copyright (c) 2016-2026, The Karbo developers
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

#include "CryptoNoteBasic.h"

namespace CryptoNote {

class Currency;

// ─── Pure-consensus structural validator ─────────────────────────────────────
//
// checkTransactionConsensusShape collects every byte-level / structural rule
// that MUST run identically on every node regardless of the path the tx
// arrived on — mempool admission, block import, alt-chain reorg, checkpointed-
// block replay. It is the union of consensus invariants that were previously
// scattered across Core::check_tx_semantic and the patchwork "mirror" checks
// in Blockchain::checkTransactionInputs.
//
// Scope:
//   * Non-empty inputs and outputs
//   * Supported version (CURRENT_TRANSACTION_VERSION, or CT-family:
//     TRANSACTION_VERSION_CT / TRANSACTION_VERSION_UNSHIELD)
//   * Input variants permitted by version (delegates to check_inputs_types_supported)
//   * Output shape: KeyOutput amount > 0 and key-on-curve for v1; ConfidentialOutput
//     with amount field == 0 for v2 CT (delegates to check_outs_valid)
//   * Plain in/out arithmetic does not overflow uint64 (delegates to check_money_overflow)
//   * signatures.size() == inputs.size()
//   * Per-input authorization variant matches input variant
//   * KeyInput: outputIndexes non-empty, no duplicate-offset (zero past first)
//   * ConfidentialInput: ring members/pubkeys/commitments size-consistent, no
//     zero-amount ring buckets, Triptych proof slot present
//   * Intra-tx key-image uniqueness across all input variants
//   * v1 plain: amount_in >= amount_out
//   * v2 CT: unlockTime <= CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6 (same height-only
//     cap as v6 plain — see CT-DESIGN.md for the "hide amounts, not graph"
//     threat-model rationale that allows CT outputs to be lockable)
//
// Out of scope (kept in the downstream validators where context lives):
//   * Curve membership for individual keys (ct_public_key_valid,
//     point_valid_for_pedersen) — done by checkConfidentialTransaction
//   * Triptych proof shape vs. ring size — done in check_tx_semantic
//   * ctProofs.size() == confidential-output count — done in check_tx_semantic
//   * Chain-state lookups (ring resolution, output presence, double-spend)
//   * Mempool policy (CT_MAX_INPUTS, CT_MAX_OUTPUTS, fee thresholds,
//     account-registration well-formedness)
//
// blockHeight is reserved for height-gated consensus rules. None exist today,
// so callers may pass 0 (or any value) without changing behavior. When a
// future rule needs height-gating, this is where the gate lives — so policy
// parameters that have ever changed (e.g. CT_MAX_INPUTS) can be migrated to
// consensus without losing the height-aware carve-out.
//
// On false, writes a human-readable diagnostic into *error if non-null. The
// caller is responsible for emitting the diagnostic at the appropriate
// severity for its context.
bool checkTransactionConsensusShape(const Transaction& tx,
                                    uint32_t blockHeight,
                                    const Currency& currency,
                                    std::string* error = nullptr);

} // namespace CryptoNote
