# Karbo Confidential Transactions: Design Intent and Threat Model

## Goal

**Karbo CT hides amounts, not the transaction graph.**

This single sentence is the design axis. Every consensus rule, validation
helper, wallet primitive, and exchange-integration surface in the Karbo CT
codebase descends from it. If you find a rule, comment, or design decision in
the codebase that contradicts this statement, that rule is the bug.

## What this means concretely

Karbo CT provides:

- **Amount confidentiality.** A transaction's output values are committed via
  Pedersen commitments; the plaintext amount is not on-chain. Range and
  canonical-denomination membership are proven by Groth–Kohlweiss (GK) proofs.
  An observer cannot read amounts directly off the wire.
- **Confidential-supply integrity.** The on-chain `confidentialSupply`
  consensus invariant tracks the visible value held in the CT pool. The
  identity
  `visible_plain_supply + pq_plain_supply + confidential_supply == already_generated_coins`
  is preserved by every block — no transaction can mint coins by routing
  through CT.
- **Spend authorization.** Triptych spend proofs (for CT inputs) and classic
  ring signatures (for transparent shielding inputs) prove the spender owns
  the input being consumed.

Karbo CT *does not* provide:

- **Sender anonymity at the level Monero claims.** While CT inputs use rings
  for compatibility and as defense-in-depth, the ring is not the load-bearing
  privacy primitive. A determined observer with access to the transaction
  graph can perform standard chain analysis. Karbo is *not* an attempt to
  hide who sent to whom.
- **Receiver anonymity beyond stealth addresses.** Output one-time keys
  are derived from view+spend keys, but tag/address association at higher
  layers (exchanges, services, public posting) is out of scope for the
  protocol to defend.
- **Metadata-free transactions.** Output count, transaction size, fee,
  unlock-time, broadcast timing, and propagation patterns are visible. CT
  rules do not attempt to hide them.

If a user requires Monero-level untraceability, Karbo is not the right tool.
That is a deliberate design choice and not a future-roadmap deficiency.

## Why this threat model

A "confidential amounts only" tier is genuinely useful and underserved:

- **Business and commercial transactions** where amounts are competitively
  sensitive but counterparties are known. Payroll, contractor payments,
  vendor settlement, B2B invoicing, treasury operations.
- **Exchange deposits and withdrawals** where the user wants the deposit
  amount hidden from passive chain observers (e.g., who else uses the
  same exchange) without requiring the exchange itself to integrate
  ring-signature analysis.
- **Recurring payments** where the regular amount would otherwise allow
  trivial pattern identification.
- **High-value individual transactions** where the amount is the sensitive
  fact, not the participants.

These use cases get strong amount privacy without paying the costs that
full untraceability imposes:

- Much smaller and faster transactions (no Triptych-over-everything; output
  proofs are bounded by the canonical denomination set, not output count).
- Tractable exchange integration (deposits and withdrawals expose amounts
  to the exchange when desired; no special view-key dance required).
- Lower verification cost (no large-ring full-anonymity proofs per output).
- Standard atomic-swap and DEX integration paths remain reachable without
  protocol-specific machinery.

This is the Bitcoin "Confidential Transactions" / Elements (Liquid) / Beam
design tier, not the Monero design tier. It is a coherent niche.

## Consensus rules that follow from the threat model

These rules embody the threat model directly. They are documented here so
future contributors do not reintroduce strict-privacy assumptions on the
mistaken belief that Karbo's CT was aiming for Monero parity.

### Amount privacy (load-bearing)

- CT outputs (`ConfidentialOutput`) carry `amount == 0` on the wire; the
  plaintext value is forbidden. The Pedersen commitment is the only on-chain
  representation of the value. *See `checkTransactionConsensusShape` and
  `checkConfidentialTransaction`.*
- CT output amounts must be one of the canonical denominations enumerated
  in `DENOMINATIONS[0..63]` (10^10 through 10^17 atomic units, in {1..9} per
  decade plus the 10^17 cap). The GK proof per output proves canonical
  membership. *See `gk_prove` / `gk_verify_batch` and `Denominations.h`.*
- The balance kernel proves `sum(input_commitments) - sum(output_commitments) - fee*H = excess*G`
  with a Schnorr signature over the prefix hash. This prevents inflation
  via mis-committed amounts. *See `crypto/transaction_balance.{h,cpp}`.*
- Triptych spend proofs (for ConfidentialInput) bind the spender to the
  real input among ring members. *See `crypto/triptych.{h,cpp}`.*

### Graph visibility (intentional)

- Transaction graph is visible. Inputs reference prior outputs by global
  index; this is the same shape as v1 plain transactions.
- Output count is visible.
- Fee is visible (carried in `tx.fee` as a plaintext field for CT
  transactions; required because the balance kernel needs the explicit fee
  to close).
- Transaction size and broadcast timing are visible.
- Unlock-time is visible (see the next section for the relaxation that
  goes with this).

### Cross-shield boundaries

- `CN/plain → CT` (shield-in) is allowed. A transparent input is consumed
  to fund a CT output. The transparent amount is publicly visible going in;
  the resulting CT output's amount is hidden. This is a normal use case.
- `CT → CT` is allowed (the common case).
- `CT → CN/plain` (unshield) is currently restricted; users who need to
  move CT-held value to a transparent counterparty (atomic swaps, exchange
  deposits to non-CT-aware addresses) should be supported in a follow-up
  pass. Reopening this path is consistent with the "hide amounts, not
  graph" threat model — the unshield necessarily reveals the unshielded
  amount, but the *prior* CT lifetime kept it hidden, and the user opts
  into the disclosure at unshield time.

## Consequences for specific protocol choices

### Unlock-time on CT transactions

CT transactions may set `tx.unlockTime` to any value in
`[0, CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6]` (height-only, no timestamp branch).
This matches the v6 plain-transaction rule.

Earlier drafts of the Karbo CT spec required `tx.unlockTime == 0` to avoid
labeling CT outputs as "swap activity" or "vesting-locked." Under the
threat model in this document, that constraint was over-restrictive: a
visible lock-height field labels the *output* as time-locked but does not
reveal the *amount*, which is what CT defends. The practical utility
unlocked by allowing non-zero unlockTime is significant:

- Pre-signed refund transactions for adaptor-signature atomic swaps
  (Karbo-side timeout).
- Vesting schedules on CT payouts (treasury, contractor work, employee
  compensation).
- Time-delayed payouts (escrow with timeout, conditional bounties).
- Cooperative recovery patterns in multi-party wallets.

The cap at `CRYPTONOTE_MAX_UNLOCK_HEIGHT_V6` (~76 years of blocks from
genesis at 240s/block) is the same one v6 plain uses. Above it, values are
treated as bogus (Unix-timestamp typo for height) and the transaction is
rejected as structurally invalid.

### Ring size and decoy selection

CT inputs use Triptych rings with sizes 4, 8, or 16 (the supported set).
These provide defense-in-depth against trivial graph analysis but are not
counted as the privacy guarantee. Wallets are free to choose larger rings
when they expect higher-traffic anonymity sets and smaller rings when they
prefer smaller transactions. Decoy selection policy is wallet-side and not
part of consensus.

### Checkpoint trust model

CT structural-only validation (skipping Triptych / GK / balance-kernel
verification) is unlocked only under a *hardcoded* or *signed-DNS*
checkpoint zone — both are anchored to the project's signing keys. Unsigned
DNS records were never admitted (see `Checkpoints.cpp::load_checkpoints_from_dns`)
and a DNS-injected anchor cannot extend the bypass zone past the trusted
set. This protects `confidentialSupply` from being inflated by an attacker
injecting a poisoned anchor — which would *not* be a privacy attack but a
soundness attack.

### What this does *not* allow

The threat-model relaxation in this document is privacy scope, not soundness
scope. The following must remain consensus-enforced regardless:

- CT output `amount` field == 0 (the plaintext channel is closed).
- GK proof present and valid on every CT output.
- Balance kernel present and valid on every CT transaction.
- `confidentialSupply` invariant tracked correctly across blocks and reorgs.
- Triptych spend proof valid on every ConfidentialInput.
- Transparent shielding inputs (KeyInput in a CT tx) verify their ring
  signature even inside a checkpoint zone (`forceFullRingSigCheck=true`).

A bug in any of the above is a hard-fork-level fix, not a privacy
discussion. They are the soundness boundary; the threat-model relaxations
in this document only move the privacy boundary.

## How to use this document

When designing new CT-adjacent features or reviewing changes:

1. Ask: does this rule defend an *amount* secret or a *graph* secret?
2. If amount: it stays load-bearing — the change probably needs a careful
   review and possibly a hard fork.
3. If graph: it is defense-in-depth at best, not the design intent. The
   change should be justified on its own merits (operational utility, code
   simplicity, interop with external tools), not on a graph-privacy
   argument that Karbo doesn't claim to provide.
4. Soundness is never negotiable. See the "What this does not allow"
   section.

A new contributor wondering "why does Karbo not do X that Monero does?"
should land here first. Karbo and Monero target different points on the
privacy-versus-utility curve; both are defensible, and the difference is
intentional, not an oversight or a TODO.
