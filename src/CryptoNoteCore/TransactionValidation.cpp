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

#include "TransactionValidation.h"

#include <algorithm>
#include <unordered_set>

#include "../CryptoNoteConfig.h"  // CURRENT_TRANSACTION_VERSION, TRANSACTION_VERSION_CT
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"  // isKeyInputSig / isCtInputSig / keyInputSig / ctInputSig

namespace CryptoNote {

namespace {
inline void setError(std::string* error, const char* msg) {
  if (error) *error = msg;
}
inline void setError(std::string* error, std::string&& msg) {
  if (error) *error = std::move(msg);
}
} // namespace

bool checkTransactionConsensusShape(const Transaction& tx,
                                     uint32_t blockHeight,
                                     const Currency& currency,
                                     std::string* error) {
  // blockHeight and currency are unused today. Plumbed for future height-gated
  // consensus rules so call sites do not need to be re-touched when one lands.
  (void)blockHeight;
  (void)currency;

  // ── 1. Non-empty input / output sides ───────────────────────────────────
  // A zero-input tx reduces the validation surface to whatever cryptographic
  // checks still fire on inputs.size()==0 (Schnorr forgery on the CT kernel
  // for v2; nothing on v1). A zero-output tx skips per-output checks and
  // produces a degenerate "burn everything as fee" shape that consensus
  // shouldn't accept.
  if (tx.inputs.empty()) {
    setError(error, "transaction has no inputs");
    return false;
  }
  if (tx.outputs.empty()) {
    setError(error, "transaction has no outputs");
    return false;
  }

  // ── 2. Supported version ────────────────────────────────────────────────
  if (tx.version != CURRENT_TRANSACTION_VERSION &&
      !isCtFamilyTransactionVersion(tx.version)) {
    setError(error, "unsupported transaction version");
    return false;
  }

  // ── 3. Input variants permitted by version ──────────────────────────────
  // v1: only KeyInput allowed.
  // v2 CT: KeyInput (transparent shielding) or ConfidentialInput (CT spend).
  // BaseInput is rejected here — coinbase is validated separately via
  // prevalidate/validate_miner_transaction.
  if (!check_inputs_types_supported(tx)) {
    setError(error, "unsupported input types");
    return false;
  }

  // ── 4. Output shape ─────────────────────────────────────────────────────
  // v1: KeyOutput with amount > 0, key on prime-order subgroup, no duplicates.
  // v2 CT: ConfidentialOutput with amount field == 0 (real amount lives in
  // the Pedersen commitment). The amount==0 rule is essential: pushBlock's
  // computeCtPoolDelta sums output.amount over all outputs to derive the CT
  // pool delta; a nonzero CT-output amount would skew confidential_supply
  // accounting and split consensus.
  {
    std::string outErr;
    if (!check_outs_valid(tx, &outErr)) {
      setError(error, "outputs invalid: " + outErr);
      return false;
    }
  }

  // ── 5. uint64 arithmetic safety on plain in/out sums ────────────────────
  // No-op for v2 CT (amounts hidden in commitments).
  if (!check_money_overflow(tx)) {
    setError(error, "transaction sums overflow uint64_t");
    return false;
  }

  // ── 6. Signature slot count matches input count ─────────────────────────
  // Wire deserialization enforces this on incoming blobs, but this validator
  // also runs on internally-constructed transactions (block-template
  // assembly, RPC paths, test fixtures, alt-chain snapshots) that never went
  // through CryptoNoteSerialization. Without this guard the per-input loop
  // below could index past tx.signatures.
  if (tx.signatures.size() != tx.inputs.size()) {
    setError(error, "signatures count does not match inputs count");
    return false;
  }

  // ── 7. Per-input authorization variant matches input variant ────────────
  // After (3), tx.inputs[i] is either KeyInput or ConfidentialInput (BaseInput
  // is rejected upstream). The matching tx.signatures[i] variant must hold:
  //   KeyInput          → std::vector<Crypto::Signature>  (legacy ring sig)
  //   ConfidentialInput → CTInputSignature                (Triptych proof slot)
  // Plus shape-level invariants on the input fields themselves.
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    if (in.type() == typeid(KeyInput)) {
      const auto& ki = boost::get<KeyInput>(in);
      // outputIndexes packed format: first absolute, others offsets-to-prev.
      // First can be zero, subsequent zeros would alias the same ring member.
      if (ki.outputIndexes.empty()) {
        setError(error, "KeyInput has empty outputIndexes");
        return false;
      }
      if (std::find(++std::begin(ki.outputIndexes),
                    std::end(ki.outputIndexes),
                    static_cast<uint32_t>(0)) != std::end(ki.outputIndexes)) {
        setError(error, "KeyInput outputIndexes contains a duplicate (zero offset after first)");
        return false;
      }
      if (!isKeyInputSig(tx.signatures[i])) {
        setError(error, "KeyInput is missing a ring-signature authorization slot");
        return false;
      }
      if (keyInputSig(tx.signatures[i]).size() != ki.outputIndexes.size()) {
        setError(error, "KeyInput ring-signature count does not match outputIndexes");
        return false;
      }
    } else if (in.type() == typeid(ConfidentialInput)) {
      const auto& ci = boost::get<ConfidentialInput>(in);
      if (ci.ringMembers.empty()) {
        setError(error, "ConfidentialInput has empty ring");
        return false;
      }
      if (ci.ringPubkeys.size() != ci.ringMembers.size()) {
        setError(error, "ConfidentialInput ringPubkeys size does not match ringMembers");
        return false;
      }
      if (ci.ringCommitments.size() != ci.ringMembers.size()) {
        setError(error, "ConfidentialInput ringCommitments size does not match ringMembers");
        return false;
      }
      for (const auto& rm : ci.ringMembers) {
        if (rm.amount == 0) {
          setError(error, "ConfidentialInput ring member references zero amount bucket");
          return false;
        }
      }
      if (!isCtInputSig(tx.signatures[i])) {
        setError(error, "ConfidentialInput is missing a Triptych proof slot");
        return false;
      }
    }
    // Unreachable for other variants — check_inputs_types_supported (3) above
    // rejected anything that isn't KeyInput / ConfidentialInput.
  }

  // ── 8. Intra-tx key-image uniqueness ────────────────────────────────────
  // Two inputs in the same tx sharing a key image would double-spend within
  // a single transaction. Applies across both KeyInput and ConfidentialInput.
  {
    std::unordered_set<Crypto::KeyImage> seenKeyImages;
    seenKeyImages.reserve(tx.inputs.size());
    for (const auto& in : tx.inputs) {
      const Crypto::KeyImage* ki = nullptr;
      if (in.type() == typeid(KeyInput)) {
        ki = &boost::get<KeyInput>(in).keyImage;
      } else if (in.type() == typeid(ConfidentialInput)) {
        ki = &boost::get<ConfidentialInput>(in).keyImage;
      } else {
        continue;
      }
      if (!seenKeyImages.insert(*ki).second) {
        setError(error, "transaction has duplicate intra-tx key image");
        return false;
      }
    }
  }

  // ── 9. v1 plain balance: inputs >= outputs ──────────────────────────────
  // The difference is the miner fee. (5) above already validated that both
  // sums fit in uint64_t, so the get_*_money_amount calls cannot return
  // false here — propagate the bool anyway so a future call-order change
  // cannot silently introduce a wrapped sum.
  if (!isCtFamilyTransactionVersion(tx.version)) {
    uint64_t amount_in = 0;
    uint64_t amount_out = 0;
    if (!get_inputs_money_amount(tx, amount_in) ||
        !get_outs_money_amount(tx, amount_out)) {
      setError(error, "v1 plain tx amounts overflow uint64_t");
      return false;
    }
    if (amount_in < amount_out) {
      setError(error, "v1 plain tx outputs exceed inputs");
      return false;
    }
  }

  // ── 10. v2 CT: unlockTime within the v6 height-only cap ─────────────────
  // Karbo CT hides amounts, not the transaction graph (see CT-DESIGN.md).
  // Under that threat model, exposing a per-output lock height is acceptable
  // (it labels the output as "time-locked CT" but doesn't reveal the amount),
  // and the practical utility — pre-signed refund transactions for atomic
  // swaps, vesting schedules, time-delayed payouts, escrow with timeout —
  // is significant.
  //
  // The cap is the same one v6 plain txs use:
  //   tx.unlockTime <= CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6 (~76 years of blocks)
  // This is height-only — no timestamp branch, matching the v6 rule cleanup
  // that retired the dual height/timestamp ambiguity. Values above the cap
  // are bogus (Unix-timestamp typo for height, etc.) and rejected as
  // structurally invalid.
  //
  // Historical note: this rule was originally `unlockTime == 0`. That was
  // overly strict for the "hide amounts only" threat model; relaxed to the
  // v6 cap so CT can participate in the same time-lock-based protocols as
  // v6 plain txs do.
  if (isCtFamilyTransactionVersion(tx.version)) {
    if (tx.unlockTime > CryptoNote::parameters::CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6) {
      setError(error, "CT transaction unlockTime exceeds CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6");
      return false;
    }
  }

  return true;
}

} // namespace CryptoNote
