// Copyright (c) 2016-2026, The Karbo developers
//
// Triptych-style linkable one-out-of-many spend proof for confidential
// transaction inputs. Replaces the linear-size MLSAG with a logarithmic
// (in ring size) Groth-Kohlweiss-descended construction.
//
// Algorithmic references (the C++ implementation here is original; the
// underlying protocol is academic prior art):
//   - Jens Groth and Markulf Kohlweiss, "One-out-of-Many Proofs:
//     Or How to Leak a Secret and Spend a Coin," EUROCRYPT 2015.
//     ePrint 2014/764. Source for the bit-decomposition selector
//     polynomial p_k(X), the Q-polynomial track, and the bit-commitment
//     proof (the I_bits/A/B + z/za/zb response structure).
//   - Sarang Noether, Brandon Goodell, Surae Noether, "Triptych:
//     logarithmic-sized linkable ring signatures with applications,"
//     2020. ePrint 2020/018. Source for the logarithmic linkable-tag idea.
//     NOTE: we use the published fixed-generator linking tag (J = x·U bound
//     by reusing the spend response), NOT the per-key Hp(P) + independent
//     inverse-witness hybrid that an earlier revision used — that hybrid did
//     not bind the tag to x and allowed forged key images (now fixed; see
//     docs/CT-ROUTE1-KEYIMAGE-FIX.md).
//
// Public statement, per CT input:
//   Ring (P_k, C_k) for k = 0..N-1 with N = 2^n in {4, 8, 16}.
//   Pseudo-output commitment C'.
//   Linking tag (CryptoNote key image) I.
//
//   The prover knows (l, x, z) with:
//     P_l   = x * G                                 (spend authorization)
//     C_l   = C' + z * G                            (commitment balance,
//                                                    z = r_real - r_pseudo)
//     J     = x * U                                 (fixed-generator key image)
//
// U is a single global NUMS generator (hash-to-point of a domain string,
// dlog unknown wrt G and H). The proof reveals nothing about l beyond ring
// membership. J is consensus-checked elsewhere against the global spent set.
//
// LINKING-TAG BINDING (the load-bearing soundness property): the linking
// track does NOT use an independent response. It REUSES the spend response
// f_P (witness x), so the SAME x drives both P_l = x·G and J = x·U. The
// earlier construction used an independent f_U (witness 1/x) over a per-key
// U-ring (U_k = Hp(P_k)); that response was never tied to f_P, so a holder
// could emit any J' = c·Hp(P_l) for chosen c and double-spend. See
// docs/CT-ROUTE1-KEYIMAGE-FIX.md and tests/forge_ki_poc.cpp.
//
// Algebra (rings R ∈ {P, M}, base G, where M_k := C_k - C'):
//
//   Σ_k p_k(X) · R_k = R_l · X^n + Σ_{m<n} X^m · ψ_R[m]
//
// where p_k is the GK selector polynomial (degree n, leading coefficient
// 1 iff k = l) and Σ_k p_k(X) = X^n identically. The prover commits:
//
//   Q_P[m] = ρ_P[m] · G + ψ_P[m]      (P-ring, G-base — standard GK)
//   Q_M[m] = ρ_M[m] · G + ψ_M[m]      (M-ring, G-base — standard GK)
//   Q_J[m] = ρ_P[m] · U               (linking track — REUSES ρ_P[m], U-base)
//
// After Fiat-Shamir challenge x_chal, prover responds:
//
//   f_P = x · x_chal^n  −  Σ_m ρ_P[m] · x_chal^m
//   f_M = z · x_chal^n  −  Σ_m ρ_M[m] · x_chal^m
//
// Verifier checks two ring identities plus the linking identity:
//
//   Σ_k p_k(x_chal) · P_k = f_P · G + Σ_m x_chal^m · Q_P[m]
//   Σ_k p_k(x_chal) · M_k = f_M · G + Σ_m x_chal^m · Q_M[m]
//   x_chal^n · J          = f_P · U + Σ_m x_chal^m · Q_J[m]
//
// The linking identity holds iff J = x·U with the SAME x extracted from the
// P-ring: substituting f_P, the x_chal^n coefficient forces J = x·U, and
// Q_J spans only m<n so the prover cannot inject an x_chal^n term to move J.
//
// Soundness sketch (informal — full proof mirrors Groth-Kohlweiss with the
// extra Triptych row): the GK extractor pulls (l, x, z) from any prover
// that satisfies all three equations with non-negligible probability over
// the Fiat-Shamir challenge. Hidden inflation would require z s.t. M_l
// commits to a non-zero value mod L, which would break the M-ring
// extractor — equivalent to breaking the discrete log on G.
//
// Fiat-Shamir transcript (one canonical serialization, NO ad-hoc hashing
// elsewhere). The challenge commits to:
//   - domain separator "Triptych-KarboCT-v2"   (separation from GK/MLSAG)
//   - tx prefix hash (message)                 (binds proof to the tx)
//   - n as one byte                            (ring-size domain split)
//   - every ring pubkey P_k in order
//   - every ring commitment C_k in order
//   - C' (pseudo-output commitment)
//   - J (key image / linking tag, = x·U)
//   - I_bits[j], A[j], B[j]  for j = 0..n−1   (bit-decomposition commits)
//   - Q_P[m], Q_M[m], Q_J[m] for m = 0..n−1   (poly-coefficient commits)
//
// Independence from the GK denomination proof: separate domain separator,
// separate transcript, separate challenges. The only shared input is the
// tx prefix hash, which both proofs commit to as their tx-context binding.
//
// This is deliberate and load-bearing. The two proofs answer different
// questions about the same transaction:
//   - Triptych: "I know a spend key for one of these ring members and the
//     pseudo-commitment opens to the same amount."
//   - GK: "Each output commitment opens to one of the 64 canonical
//     denominations."
// Both must commit to the *same* transaction identity, otherwise an attacker
// could swap a valid Triptych from tx A with a valid GK from tx B. The
// prefix hash is exactly that identity. The proofs do NOT share verifier
// challenges, batched α scalars, or any other internal randomness — the
// domain tags ("Triptych-KarboCT-v2", "GKBatchTranscriptV1", etc.) keep
// the proof systems algebraically independent so a soundness break in one
// cannot be leveraged against the other. Future refactoring must preserve
// this property: do NOT merge the transcripts or pull challenges across.
//
// Timing side channel during signing (NOT verification):
//   triptych_sign() branches on the bits of `true_index` to build the I_bits
//   commitments, the bit-commitment Q polynomials, the selector-polynomial
//   coefficients, and the secret-scalar fixed-generator multiply J = x·U.
//   An adversary who can observe per-signature wall-clock from inside the
//   prover's host could in principle narrow the ring's anonymity set over
//   many signatures and learn statistical bits of the spend key. This matches
//   the academic Triptych reference and ref10's `ge_scalarmult`, which is also
//   variable-time on secret-scalar operations elsewhere in the wallet.
//
// Threat model: signing happens locally in the user's wallet process.
// Realistic exploitation requires a co-located observer (malicious hypervisor,
// shared host, side-channel-capable malware) AND many signatures from the
// same spend key. For a typical desktop wallet this is out of scope.
// A future constant-time crypto migration would close this; it is not a
// targeted fix because the dependency surface (ref10) is variable-time
// throughout, so a piecemeal patch buys little.

#pragma once

#include <cstddef>
#include <vector>
#include <CryptoTypes.h>

namespace Crypto {

// Per-input Triptych signature. Vector lengths follow this rule:
//
//   ring_size ∈ {4, 8, 16}  (n_bits = log2(ring_size))
//     I_bits, A, B, z, za, zb : exactly n_bits entries
//     Q_P, Q_M, Q_J           : exactly n_bits entries
//
// f_P, f_M are always present (two response scalars). There is no separate
// image response: the linking track reuses f_P, which is what binds J = x·U
// to the spend key.
//
// No ring-size-1 branch: a Schnorr-only shape at ring size 1 would not
// bind the same witness x in P = x·G and J = x·U, so a holder could
// emit fresh key images for the same spend. Transparent shielding
// (coinbase included) goes through v2 KeyInput with a legacy ring
// signature, so a ConfidentialInput with ring size 1 is never needed.
struct TriptychSignature {
  std::vector<EllipticCurvePoint>  I_bits;   // commitments to secret index bits l_j
  std::vector<EllipticCurvePoint>  A;        // bitness aux commitments
  std::vector<EllipticCurvePoint>  B;        // bitness aux commitments
  std::vector<EllipticCurvePoint>  Q_P;      // P-ring polynomial coefficients (G-base)
  std::vector<EllipticCurvePoint>  Q_M;      // M-ring polynomial coefficients (G-base)
  std::vector<EllipticCurvePoint>  Q_J;      // linking-track coefficients ρ_P[m]·U (U-base)
  std::vector<EllipticCurveScalar> z;        // bit-commitment responses
  std::vector<EllipticCurveScalar> za;       // opening responses for x·I_bits + A
  std::vector<EllipticCurveScalar> zb;       // opening responses for (x−z)·I_bits + B
  EllipticCurveScalar              f_P;      // spend witness response (REUSED to bind the key image)
  EllipticCurveScalar              f_M;      // balance witness response
  // No independent image response: the linking track reuses f_P. An independent
  // inverse witness (the old f_U) left the key image unbound — a holder could
  // forge fresh images for the same output. See docs/CT-ROUTE1-KEYIMAGE-FIX.md.
};

// Generate a Triptych spend proof for a CT input.
//
// message:         transaction prefix hash (Fiat-Shamir context binding)
// ring_pubkeys:    one-time public keys P_k of ring members (size = ring_size)
// ring_commits:    Pedersen commitments C_k of ring members (size = ring_size)
// pseudo_commit:   pseudo-output commitment C' = v·H + r'·G
// ring_size:       number of ring members; MUST be in {4, 8, 16}.
// true_index:      index l of the real input within the ring
// spend_privkey:   secret spend key x such that P_l = x·G
// real_blinding:   blinding factor r of the real input's commitment C_l
// pseudo_blinding: blinding factor r' of the pseudo-output commitment C'
// key_image:       [out] linking tag J = x · U
// sig:             [out] Triptych signature (variable arrays sized to log2(ring_size))
//
// Returns false on bad inputs (bad points, index out of range, ring_size not
// a supported power of two, spend_privkey not in [1, L)).
bool triptych_sign(
  const Hash& message,
  const PublicKey ring_pubkeys[],
  const EllipticCurvePoint ring_commits[],
  const EllipticCurvePoint& pseudo_commit,
  size_t ring_size,
  size_t true_index,
  const SecretKey& spend_privkey,
  const EllipticCurveScalar& real_blinding,
  const EllipticCurveScalar& pseudo_blinding,
  KeyImage& key_image,
  TriptychSignature& sig);

// Verify a Triptych spend proof.
//
// Returns true iff:
//   - ring_size is one of the supported powers of two
//   - every response scalar is in canonical range [0, L)
//   - every committed point is in the prime-order subgroup
//   - the three ring identities hold under the Fiat-Shamir challenge
//
// Does NOT check the global spent-key set — that is consensus state and
// stays with the caller (Blockchain validation).
bool triptych_verify(
  const Hash& message,
  const PublicKey ring_pubkeys[],
  const EllipticCurvePoint ring_commits[],
  const EllipticCurvePoint& pseudo_commit,
  size_t ring_size,
  const KeyImage& key_image,
  const TriptychSignature& sig);

// Returns true iff ring_size is one of the supported full-Triptych
// shapes (4, 8, or 16). Exposed so callers (TransactionBuilder,
// validation) can reject early without ever entering the proof path
// on a malformed shape.
bool triptych_ring_size_supported(size_t ring_size);

// Canonical CT key image / linking tag: J = x · U, where U is the fixed
// global NUMS generator and x is the spend secret of the output being
// consumed. Deterministic in x alone (independent of P, ring, tx), so the
// same output always yields the same J -> double-spend detection via the
// single global spent-key set. triptych_sign() computes the identical value
// internally; wallets call this to populate ConfidentialInput.keyImage so the
// tx prefix hash matches the proof transcript.
//
// Returns false if spend_privkey is not a canonical scalar in [1, L).
bool triptych_key_image(const SecretKey& spend_privkey, KeyImage& key_image);

// Batched verification of `count` Triptych spend proofs that all share a
// single Fiat-Shamir message (typically the tx prefix hash of one
// transaction). For each proof i, parallel arrays describe its inputs:
//   ring_pubkeys[i]   — pointer to the ring of size ring_sizes[i]
//   ring_commits[i]   — parallel ring of commitment points
//   pseudo_commits[i] — pseudo-output commitment for input i
//   ring_sizes[i]     — must be 4, 8, or 16
//   key_images[i]     — linking tag for input i
//   sigs[i]           — Triptych proof struct
//
// Soundness: α is derived from a Fiat-Shamir transcript that commits to
// every proof in the batch (key images, pseudo commits, ring contents,
// and every byte of every TriptychSignature). The prover cannot
// pre-compute α before constructing the proofs, so any single broken
// equation flips the combined sum to non-identity with overwhelming
// probability (~2⁻²⁵²). The derivation is fully deterministic across
// nodes — consensus verification is reproducible.
//
// Returns true iff every proof verifies. On false, the caller is
// expected to fall back to per-input triptych_verify() to pinpoint
// which proof failed — the batched path has no per-proof diagnostic.
//
// On invalid structural input (bad ring size, malformed proof shape,
// scalars out of range, points off the prime-order subgroup) the
// function fails fast and returns false without proceeding to the MSM.
bool triptych_verify_batch(
  const Hash& message,
  const PublicKey* const* ring_pubkeys,
  const EllipticCurvePoint* const* ring_commits,
  const EllipticCurvePoint* pseudo_commits,
  const size_t* ring_sizes,
  const KeyImage* key_images,
  const TriptychSignature* sigs,
  size_t count);

} // namespace Crypto
