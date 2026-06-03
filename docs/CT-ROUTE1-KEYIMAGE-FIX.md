# CT Route 1 — Bound Linking Tag (key-image soundness fix)

## Why

The Triptych spend proof as shipped does **not** bind the key image to the
spend key. The verifier runs three independent ring checks; the linking (U)
track uses an independent response `f_U` with witness `1/x` that is never
cross-checked against the spend response `f_P` (witness `x`). Result: for an
owned confidential output `P_l = x·G`, a prover can emit **any** key image
`I = c·Hp(P_l)` for a chosen `c ≠ x` (set `f_U = (1/c)·ξⁿ − Σσ_U[m]ξᵐ`), and
both `triptych_verify` and `triptych_verify_batch` accept it. Distinct `c` ⇒
distinct image ⇒ the same confidential output can be spent repeatedly without
colliding in the `spent_keys` set.

Confirmed empirically: `tests/forge_ki_poc.cpp` builds a forged proof against
the production `Crypto.lib` and both verifiers accept it.

The pool-liability counter (`confidential_supply`) caps *net visible* coin
extraction at total-shielded, so this is not unlimited mint-to-cash — but it is
a full **confidential double-spend** (pay multiple parties the same shielded
coin; over-subscribe the pool). Not shippable.

## Decision: Route 1 (fixed-generator linking tag)

Replace the per-key CryptoNote image `I = x·Hp(P)` (for CT inputs only) with a
**fixed-generator** image `J = x·U`, and prove it by **reusing the spend
response `f_P`** instead of an independent inverse witness. This is the
published Triptych linking construction; the binding is automatic because one
witness `x` drives both the spend equation (base `G`) and the linking equation
(base `U`).

Trade-off (accepted, consistent with the threat model "hide amounts, not the
graph"): CT rings become **confidential-output-only**. A transparent output is
spendable only via a legacy `KeyInput` (image `x·Hp(P)`); a confidential output
only via a `ConfidentialInput` (image `x·U`). No output ever has two image
formats, so a single `spent_keys` DB stays collision-correct. Transparent
ring members were weak decoys anyway (an analyst discounts them) and become
provably worthless under Route 1, so they are dropped.

This is a **hard fork** (proof wire format + key-image derivation change). CT is
testnet-only today (`CT_FORK_HEIGHT = UPGRADE_HEIGHT_V6`; testnet v6 = 400),
so fix before any mainnet activation. Old-format CT txs will not validate under
the new rules — clean break at the fork.

## Construction (authoritative)

Generators (all NUMS, pairwise-unknown DL):
- `G` — Ed25519 base point.
- `H` — Pedersen value generator = `hash_to_point("CN-amount-generator")` (existing).
- `U` — **new** linking-tag generator = `hash_to_point("Karbo-CT-keyimage-generator-v1")`,
  cofactor-cleared to the prime-order subgroup. dlog unknown wrt `G` and `H`.

Per CT input, public statement (ring size `N ∈ {4,8,16}`, `n = log2 N`):
- Ring `(P_k, C_k)`, k=0..N-1 — all **confidential outputs** (sentinel bucket).
- Pseudo-output commitment `C' = v·H + r'·G`.
- Key image / linking tag `J = x·U`.

Witnesses: index `l`, `x` (with `P_l = x·G`), `z = r_real − r_pseudo`
(with `C_l − C' = z·G`).

GK bit-decomposition (unchanged): `I_bits[j], A[j], B[j]` and responses
`z[j], za[j], zb[j]` prove each index bit ∈ {0,1}. Selector polynomial
`p_k(X)`; key identity `Σ_k p_k(X) = Xⁿ`.

Three tracks:

1. **P-ring** (spend): `Q_P[m] = ρ_P[m]·G + Σ_k p_{k,m}·P_k`;
   `f_P = x·ξⁿ − Σ_m ρ_P[m]·ξᵐ`.
   Verify `Σ_k p_k(ξ)·P_k = f_P·G + Σ_{m<n} ξᵐ·Q_P[m]`. ⇒ `P_l = x·G`.

2. **M-ring** (amount balance, unchanged): `Q_M[m] = ρ_M[m]·G + Σ_k p_{k,m}·M_k`,
   `M_k = C_k − C'`; `f_M = z·ξⁿ − Σ_m ρ_M[m]·ξᵐ`.
   Verify `Σ_k p_k(ξ)·M_k = f_M·G + Σ_{m<n} ξᵐ·Q_M[m]`. ⇒ `C_l − C' = z·G`
   (pseudo commits to the real value — no amount inflation).

3. **Linking** (replaces the U-ring): `Q_J[m] = ρ_P[m]·U`  ← **reuses ρ_P[m]**.
   **No new response — reuses `f_P`.**
   Verify `ξⁿ·J = f_P·U + Σ_{m<n} ξᵐ·Q_J[m]`. ⇒ `J = x·U`.

Soundness of the binding (special-soundness extraction over n+1 challenges):
`f_P = x·ξⁿ − Σρ_P[m]ξᵐ` is forced by the P-ring (so its `ξⁿ` coefficient is
`x`). Substituting into the linking equation gives, as a polynomial identity in
`ξ`: `ξⁿ·J = x·ξⁿ·U − Σρ_P[m]ξᵐ·U + Σξᵐ·Q_J[m]`. The `ξⁿ` coefficient forces
`J = x·U`; `Q_J` only spans `m<n`, so the prover cannot inject a `ξⁿ` term to
move `J`. A forged `J = c·U`, `c≠x`, contradicts the extracted identity ⇒
rejected. ZK preserved: `ρ_P[m]` random ⇒ `Q_P[m]`, `Q_J[m]` uniform
(Chaum–Pedersen-style shared blinding).

Fiat-Shamir transcript ξ (domain `"Triptych-KarboCT-v2"` — bump from v1):
`domain ‖ message ‖ ring_size ‖ {P_k} ‖ {C_k} ‖ C' ‖ J ‖ {I_bits} ‖ {A} ‖ {B}
‖ {Q_P} ‖ {Q_M} ‖ {Q_J}`. (Replace `Q_U` with `Q_J`; drop nothing else.)

## Wire / struct changes

`TriptychSignature`: rename `Q_U → Q_J` (same slot, `n` points); **remove `f_U`**.
New body per CT input: `n` header + 6·n points (I_bits,A,B,Q_P,Q_M,Q_J) +
(3n+2) scalars (z,za,zb,f_P,f_M). One scalar smaller than before.

## Implementation checklist (consensus-critical) — LANDED

- [x] `crypto`: added `U` generator (`keyimage_generator_U`) + `triptych_key_image(x) → J = x·U` (canonical helper).
- [x] `crypto/triptych.{h,cpp}`: struct `Q_U→Q_J`, dropped `f_U`; `triptych_sign`
      (J=x·U, Q_J=ρ_P·U, reuse f_P, dropped σ_U/U_k=Hp(P_k)/sc_invert); `triptych_verify`
      (linking eq); `triptych_collect_claims`/batch (linking equation terms
      `{ξⁿ,J} − {f_P,U} − Σ{ξᵐ,Q_J[m]}`); transcript domain `Triptych-KarboCT-v2`.
- [x] `include/CryptoNote.h` + `CryptoNoteSerialization.cpp` `CTInputSignature`: dropped `f_U`, `Q_U→Q_J` (binary + JSON).
- [x] `Wallet/TransactionBuilder.cpp`: CT input key image = `x·U` via `triptych_key_image`; KeyInput stays `x·Hp(P)`.
- [x] `Blockchain.cpp checkConfidentialTransaction`: **confidential-only rings** —
      every ring member must resolve to a `ConfidentialOutput` in the sentinel
      bucket; transparent-`KeyOutput` ring-member branch removed.
- [x] `TransactionValidation.cpp`: ConfidentialInput ring members `amount == CT_CONFIDENTIAL_OUTPUT_AMOUNT`.
- [x] `Core.cpp` shape check: `Q_U→Q_J`.
- [x] `Rpc/BuiltinExplorer.cpp`: `Q_U→Q_J`, dropped `f_U`.
- [x] Tests: `test_triptych.cpp`, `test_mixed_v2_roundtrip.cpp`, `fuzz_ct_serializer.cpp`,
      `CoreTests/CryptoNoteBoostSerialization.h` updated; `forge_ki_poc.cpp` rewritten + registered
      as CTest target `ForgeKeyImagePoC`.

## Verification gates — ALL PASSING

1. `forge_ki_poc` (J=x·U): honest image ACCEPTS; 8 forged `J=c·U`, `c≠x` →
   **rejected** by both `triptych_verify` and `triptych_verify_batch`. ✔
2. `triptych_tests` 57/57 (honest all sizes/indices, key-image consistency,
   hidden-inflation rejected, tampering, batch). ✔
   `gk_proof_tests` 82/82, `tx_balance_tests` 27/27, `ct_integration_tests` 53/53. ✔
3. `V3ChainIntegration` 1/1: v2 shield → v3 unshield → CT→CT (ring 4) →
   confidential-input unshield → **cross-version double-spend rejected on the
   shared key-image set**. ✔  `CTFuzz`: 200k mutations, no crash. ✔
4. Full solution builds clean (daemon, simplewallet, greenwallet, walletd, all tests).

## Still open (follow-ups, non-blocking)

- External cryptographer sign-off on the linking construction before mainnet.
- Wallet decoy-selection policy for confidential-only rings (ring-size ramp vs
  pool depth right after CT activation).
- Testnet reset / fork-height bump (proof wire format changed — old CT txs won't validate).

## Notes for the PQ family (v4)

The GK one-of-many *membership* engine is reusable. The linking tag is **not**
— `x·U` has no clean lattice analogue. Treat the PQ linking tag as a separate,
independently-reviewed design; do not assume this binding trick transfers.
