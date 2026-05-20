// Copyright (c) 2016-2026, The Karbo developers
//
// Groth-Kohlweiss one-of-many membership proof for confidential transactions.
// Proves knowledge of the opening of one commitment in a ring of N=64
// denomination commitments using a binary decomposition (n=6 bits).
//
// Proof size: 24 points x 32 + 19 scalars x 32 = 1376 bytes.
// I commits to the secret index bits, A/B are the bitness proof commitments,
// and Q commits to the non-leading polynomial coefficients. The degree-6
// leading coefficient (= D[l] = r*G) is absorbed into scalar f.
//
// Reference: Groth & Kohlweiss, "One-out-of-Many Proofs", EUROCRYPT 2015.

#pragma once

#include <cstddef>
#include <cstdint>
#include <CryptoTypes.h>
#include "crypto-ops.h"

namespace Crypto {

static const size_t GK_N = 64;  // ring size (number of denominations)
static const size_t GK_n = 6;   // bit decomposition width (2^6 = 64)

struct GKProof {
  ge_p3 I[6];               // commitments to secret index bits l_j
  ge_p3 A[6];               // bit randomness commitments
  ge_p3 B[6];               // bit value commitments
  ge_p3 Q[6];               // polynomial coefficient commitments (m=0..5)
  EllipticCurveScalar z[6]; // per-bit response scalars
  EllipticCurveScalar za[6];// opening responses for I^x * A
  EllipticCurveScalar zb[6];// opening responses for I^(x-z) * B
  EllipticCurveScalar f;    // final evaluation scalar
};

// Prove that commitment C opens to one of the 64 canonical denominations.
//
// C:                  the Pedersen commitment (v*H + r*G)
// v:                  the committed denomination value (atomic units)
// r:                  the blinding factor
// denomination_index: index in DENOMINATIONS[] (0..63)
// tx_hash:            transaction hash for Fiat-Shamir binding
// proof:              output proof
//
// Returns true on success.
bool gk_prove(const EllipticCurvePoint& C,
              uint64_t v,
              const EllipticCurveScalar& r,
              size_t denomination_index,
              const Hash& tx_hash,
              GKProof& proof);

// Verify a GK one-of-many membership proof.
//
// C:       the Pedersen commitment being proven
// proof:   the GK proof
// tx_hash: transaction hash (must match what the prover used)
//
// Returns true if the proof is valid.
bool gk_verify(const EllipticCurvePoint& C,
               const GKProof& proof,
               const Hash& tx_hash);

// Batched GK proof verification.
//
// Verifies n proofs together — equivalent to looping gk_verify(commitments[i],
// proofs[i], tx_hash) for i=0..n-1, but ~1.5× faster by collapsing the per-
// proof linear-combination checks into a single multi-scalar multiplication
// (Pippenger windowed bucket method, c=4) with random-coefficient batching.
//
// Soundness: α scalars are derived deterministically from a Fiat-Shamir
// transcript that commits to every commitment + proof byte in the batch
// (domain "GKBatchTranscriptV1" — see gk_verify_batch_dispatch). Consensus
// validation MUST be deterministic: two honest nodes verifying the same
// transaction must reach the same accept/reject verdict, otherwise a single
// tx could split the network. Sampling random α at verify time would give
// a vanishing but non-zero false-accept probability that could disagree
// across nodes. Mirrors triptych_verify_batch's transcript shape.
//
// Independence from the Triptych spend proof: separate domain separators
// ("GKBatchTranscriptV1" / "Triptych-KarboCT-v1"), separate per-proof
// challenges, separate batched α derivations. The only shared input is
// tx_hash (the tx prefix hash), which both proofs commit to as their
// transaction-identity binding — without that shared anchor an attacker
// could swap a valid Triptych from tx A with a valid GK from tx B and
// present a Frankenstein transaction. DO NOT collapse the two transcripts
// or share challenges; the proof systems must remain algebraically
// independent so a soundness break in one cannot leverage the other.
//
// The original gk_verify is unchanged and still callable; the validator uses
// the batched path for speed, and the per-proof path remains available for
// diagnostic fall-back when a batch fails (to pinpoint which output broke).
//
// Timing side channel during proving (not verification): gk_prove() branches
// on the bits of `denomination_index` exactly as triptych_sign branches on
// `true_index` bits. See the discussion in triptych.h — same threat model,
// same accepted-risk classification.
//
// Returns true iff all n proofs verify.
bool gk_verify_batch(const EllipticCurvePoint* commitments,
                     const GKProof* proofs,
                     size_t n,
                     const Hash& tx_hash);

// Reference (naive) batched verification: same contract as gk_verify_batch
// but uses sequential s*P + ge_scalarmult_base inside, instead of Pippenger.
// Kept exported so tests can cross-check the two implementations agree.
// Production code should always call gk_verify_batch; this variant is
// 1.2-1.5× slower at every batch size we measure.
bool gk_verify_batch_naive(const EllipticCurvePoint* commitments,
                           const GKProof* proofs,
                           size_t n,
                           const Hash& tx_hash);

// Computes V[k]*H from scratch (one variable-base scalarmult per k) and
// writes the 32-byte compressed encoding into out[k].
//
// Exposed solely so the unit test BakedVkHTableMatchesFromScratch can
// verify that the literals in gk_denomination_table.h agree with the
// from-scratch result on every build. The runtime path uses the baked
// constants directly and never calls this function.
//
// Returns true on success, false if the canonical H point fails to
// decode or any scalarmult fails.
bool gk_compute_vkH_table_from_scratch(unsigned char out[64][32]);

} // namespace Crypto
