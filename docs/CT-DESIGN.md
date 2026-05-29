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
- `CT → CN/plain` (unshield) is being reopened to support moving CT-held
  value to a transparent counterparty (atomic-swap redeem, exchange
  deposits to non-CT-aware addresses). Reopening this path is consistent
  with the "hide amounts, not graph" threat model — the unshield
  necessarily reveals the unshielded amount, but the *prior* CT lifetime
  kept it hidden, and the user opts into the disclosure at unshield time.
  **Unshield is assigned its own transaction version, `v3`** (the version
  ladder is `v1 = CN/plain`, `v2 = CT`, `v3 = CT → CN unshield`, `v4 = PQ`;
  see "Transaction version ladder" below). `v3` is a CT-aware version that
  permits **mixed outputs** — `ConfidentialOutput` and `KeyOutput` in the
  same transaction — and so covers pure unshield, **partial unshield** (CT
  change + plain payout in one tx, for CEX-deposit ergonomics), and shield
  from one shape. The reason for a version *bump* rather than relaxing `v2`
  in place is isolation: `v2` stays strictly all-confidential outputs, so the
  ordinary shielded-payment hot path never reaches the mixed-output /
  mixed-balance code, and a bug in that new path cannot be triggered by a
  vanilla shielded send.
  **The *spend* path is identical to `v2 CT → CT`:** the confidential value
  being consumed is still spent by a `ConfidentialInput` (same Triptych
  proof, same key image `I = x·H_p(P)`), and mixed *inputs* (`KeyInput` +
  `ConfidentialInput`) already exist in `v2`, so `v3` inherits input handling
  verbatim. The one genuinely new consensus surface is the **plain-output
  term in the balance kernel** — see "v3 unshield: scope and the balance
  kernel" below. The key-image invariant in the next subsection holds
  identically across `v1`/`v2`/`v3`.
  Detailed working notes (swap construction, adversarial test set) live in
  `karbo-swaps-and-ct-to-cn.md`.

### Transaction version ladder

| Version | Meaning | Status |
|---------|---------|--------|
| `v1` | CN / plain transparent (`CURRENT_TRANSACTION_VERSION`) | shipped |
| `v2` | CT — confidential outputs, Triptych spends (`TRANSACTION_VERSION_CT`) | shipped (dev/ct) |
| `v3` | CT → CN unshield (confidential input → transparent output) | planned |
| `v4` | PQ Phase 1 (`TRANSACTION_VERSION_PQ`, post-quantum family) | planned |

`v1` and `v2` are the only values defined in `src/CryptoNoteConfig.h` today.
`v3` (unshield) and `v4` (PQ) are reserved by this ladder for their
respective follow-up passes. Note these are *transaction* versions and are
orthogonal to the *block-major* fork versions (CT activates at block-major
`v6`, PQ-plain at `v7`).

### v3 unshield: scope and the balance kernel

The mechanical `v3` plumbing is small (admit version 3; relax the
output-uniformity check to allow `KeyOutput` alongside `ConfidentialOutput`;
index plain outputs in the normal global-output index so they're later
spendable as ordinary transparent ring-1 outputs; apply the fee as a plain
`·H` term once). The **audit centerpiece** is the balance kernel's new
plain-output term. General form (handles all four directions — shield,
unshield, partial, CT→CT):

```
Σ(plain_in)·H + Σ(pseudo-in_CT) − Σ(conf-out) − (Σ plain_out)·H − fee·H  ≟  Commit(0)
```

Plain inputs and plain outputs touch the **H axis only** (zero blinding on
G). **Critical invariant:** any G-component leaking from a "plain"
input/output is an inflation bug. Supply accounting stays as today, computed
from visible amounts only: `Δconfidential_supply = plain_in − plain_out −
fee`; hidden CT in/out values cancel in the pool; underflow (debit > pool) is
a hard reject. GK/range-proof count must equal `count(ConfidentialOutput)`
and **must accept 0** (a pure unshield has no confidential outputs).

**Verified against current code (this is genuinely new for v3):**
- `check_outs_valid` ([CryptoNoteFormatUtils.cpp:194](../src/CryptoNoteCore/CryptoNoteFormatUtils.cpp))
  currently *rejects* any non-`ConfidentialOutput` in a `v2` CT tx, so the
  balance kernel ([Blockchain.cpp:2968](../src/CryptoNoteCore/Blockchain.cpp))
  safely does `boost::get<ConfidentialOutput>` on every output. The
  `−(Σ plain_out)·H` term has therefore **never run in production** — it is
  the spend-from-nothing surface and must be reviewed as if it were the only
  thing in the PR.
- Mixed *inputs* already work in `v2`: the kernel's input loop handles
  `KeyInput` via `transparent_amount_to_commitment(amount)` (= `amount·H`,
  blinding 0) at [Blockchain.cpp:2954](../src/CryptoNoteCore/Blockchain.cpp).
  So "mixed inputs are nothing new for v3" is true — but it rests on the
  key-image invariant below (TODO-1/TODO-2 in the working notes), which is
  now confirmed.
- *Minor cleanup for the implementer:* the comment at
  [Core.cpp:455](../src/CryptoNoteCore/Core.cpp) refers to "transparent
  change/unshield from a CT tx" and `MIN_CT_DENOMINATION` enforcement on "v2
  mixed outputs," but `check_outs_valid` rejects plain outputs in `v2` — so
  that path is aspirational/unreachable today. Reconcile it when `v3` lands.

Adversarial tests the kernel work must include: pure unshield (0 CT out, 0 GK
proofs); partial unshield (exercises both kernel terms); the
**inflate-the-change** vector (honest `plain_out`, exited value hidden in an
inflated confidential "change" commitment — the kernel must force the change
value via the equation and reject); sign-flipped plain term; fee
double-counted; `Σ plain_out` overflow (checked add, no asserts on the
consensus path); `confidential_supply` underflow; overstated `plain_in` vs
referenced amount; and a round-trip confirming a `v3` `KeyOutput` is later
spendable as a normal `v1` ring-1 transparent spend (closes the loop to swap
funding).

### Key-image invariant across shield boundaries (double-spend safety)

Spending the same output **must** produce the same key image regardless of
which transaction form consumes it. This is what makes shield boundaries
safe: a holder cannot spend an output once via one form and again via
another, because the consensus spent-key set would collide.

The invariant rests on four properties, all of which hold in the current
code and **must be preserved by the CT→CN unshield work**:

1. **One canonical spend path per output type.** A transparent `KeyOutput`
   is consumable only by a `KeyInput`; a `ConfidentialOutput` is consumable
   only by a `ConfidentialInput`. The two never overlap: confidential
   outputs are registered in the global output index under the sentinel
   bucket `CT_CONFIDENTIAL_OUTPUT_AMOUNT` (`UINT64_MAX`), transparent
   outputs under their real amount bucket, and a `KeyInput`'s ring resolves
   only `KeyOutput` targets in its own (`amount != 0`) bucket. The unshield
   path must **not** introduce a second way to consume a confidential
   output (e.g. via a plain `KeyInput`); doing so would risk a second,
   divergent key image for the same output.

2. **Key-image determinism.** The key image is always
   `I = x · H_p(P)` over the output's one-time public key `P`, computed by
   the same `generate_key_image` primitive on every path. It depends only
   on the output keypair `(P, x)` — never on the transaction version, the
   output side (shield / unshield / CT-to-CT), the ring composition, or the
   Pedersen commitment. So a `ConfidentialInput` spending output `P` in a
   `CT → CT` transaction and a `ConfidentialInput` spending the same `P` in
   a `CT → CN` unshield emit byte-identical key images.

3. **The Triptych spend proof binds the same `x`** in both `P = xG` and
   `I = x·Hp(P)`, so a holder cannot forge an alternative key image for an
   output they own. (This is why the ring-size-1 "two independent Schnorr
   proofs" carve-out was removed — it did not bind the two, allowing fresh
   key images for the same spend.)

4. **A single, type-agnostic spent-key set.** Consensus records and checks
   key images from both `KeyInput` and `ConfidentialInput` in one set keyed
   on the raw 32 key-image bytes, with no discriminator for input type,
   amount bucket, or transaction version. A `CT → CN` spend therefore
   collides with a prior `CT → CT` spend of the same output, and the second
   to be mined is rejected as a double-spend.

For atomic swaps this yields the desired mutual-exclusion property directly:
the redeem (`CT → CN`) and refund spends of the same locked confidential
output produce the same key image, so at most one can ever confirm. Note
that the transparent output *produced* by an unshield is a fresh `KeyOutput`
with its own one-time key and its own (later) key image — spending it in a
subsequent plain transaction is a normal, distinct spend, not a re-spend of
the confidential input.

**This resolves TODO-1 and TODO-2 of the `karbo-swaps-and-ct-to-cn.md`
working notes** (the consensus-critical checks flagged "run before building
on the v3 scope"). Verified in code:
- *Generation* — `generate_key_image(P, x, I)` is the same call with no
  version branch on every path: legacy `KeyInput`
  ([CryptoNoteFormatUtils.cpp:60, Transaction.cpp:280](../src/CryptoNoteCore/CryptoNoteFormatUtils.cpp))
  and CT `ConfidentialInput`
  ([WalletGreen.cpp:2649 → TransactionBuilder.cpp:300](../src/Wallet/TransactionBuilder.cpp)).
- *Spent-set* — a single LMDB `spent_keys` table, keyed on the raw image
  bytes, written and checked for both input variants
  ([Blockchain.cpp:3857](../src/CryptoNoteCore/Blockchain.cpp); mempool
  [TransactionPool.cpp:748](../src/CryptoNoteCore/TransactionPool.cpp)).
- *Triptych linking tag* — the `ConfidentialInput.keyImage` that enters that
  shared set **is** `x·H_p(P)`; the Triptych proof binds the same `x` and
  does not fold in the commitment or use a different generator (TODO-2).

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
