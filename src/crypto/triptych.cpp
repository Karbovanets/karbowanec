// Copyright (c) 2016-2026, The Karbo developers
//
// Triptych-style linkable one-out-of-many spend proof. See triptych.h for
// the public statement, algebra, and Fiat-Shamir transcript definition.
//
// This file deliberately funnels every challenge through one function
// (compute_challenge); call sites never hash on their own. The linking
// track reuses the spend response f_P (no independent inverse witness),
// which is what binds the key image J = x·U to the spend key x.

#include "triptych.h"
#include "crypto.h"
#include "hash.h"
#include "msm.h"
#include "pedersen.h"
#include "random.h"
#include "crypto-util.h"
#include "CryptoNoteConfig.h"

#include <array>
#include <cassert>
#include <cstring>
#include <vector>

extern "C" {
#include "crypto-ops.h"
}

namespace Crypto {

// ── Constants and shape helpers ─────────────────────────────────────────

namespace {

// log2(N) for the supported ring sizes. Returns 0 for any unsupported
// shape — callers MUST validate ring_size with
// triptych_ring_size_supported() before allocating buffers.
inline size_t log2_ring(size_t ring_size) {
  switch (ring_size) {
    case 4:  return 2;
    case 8:  return 3;
    case 16: return 4;
    default: return 0;
  }
}

} // anonymous namespace

// Triptych supports power-of-two ring sizes 4, 8, 16. A ring-size-1
// Schnorr carve-out was considered for v5+ coinbase but rejected as
// unsound: the simpler "two independent Schnorr proofs" shape would not
// bind the same x to both P = xG and J = x·U, letting a holder forge fresh
// key images. Transparent shielding (coinbase included)
// goes through v2 KeyInput with a legacy ring signature, so a
// ConfidentialInput never needs ring size 1.
//
// CT_MAX_RING_SIZE in CryptoNoteConfig.h must stay ≤ 255 so a single
// byte is enough to fit ring_size in the Fiat-Shamir transcript.
static_assert(CryptoNote::parameters::CT_MAX_RING_SIZE <= 255,
              "Triptych transcript writes ring_size as one byte");
bool triptych_ring_size_supported(size_t ring_size) {
  return ring_size == 4 || ring_size == 8 || ring_size == 16;
}

// ── Scalar / point primitives ───────────────────────────────────────────

namespace {

// Generate a uniform scalar in [0, L) (Ed25519 group order).
void random_scalar(EllipticCurveScalar& res) {
  unsigned char tmp[64];
  Random::randomBytes(64, tmp);
  sc_reduce(tmp);
  std::memcpy(&res, tmp, 32);
  sodium_memzero(tmp, 64);
}

void p3_to_bytes(unsigned char out[32], const ge_p3* p) {
  ge_p3_tobytes(out, p);
}

bool subgroup_check_p3(const ge_p3& p) {
  EllipticCurvePoint point;
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&point), &p);
  return point_valid_for_pedersen(point);
}

bool p2_to_p3(ge_p3* out, const ge_p2* in) {
  unsigned char bytes[32];
  ge_tobytes(bytes, in);
  return ge_frombytes_vartime(out, bytes) == 0;
}

void point_add(ge_p3* out, const ge_p3* a, const ge_p3* b) {
  ge_cached b_cached;
  ge_p3_to_cached(&b_cached, b);
  ge_p1p1 r;
  ge_add(&r, a, &b_cached);
  ge_p1p1_to_p3(out, &r);
}

bool point_equal(const ge_p3& a, const ge_p3& b) {
  unsigned char a_bytes[32], b_bytes[32];
  p3_to_bytes(a_bytes, &a);
  p3_to_bytes(b_bytes, &b);
  return std::memcmp(a_bytes, b_bytes, 32) == 0;
}

bool scalarmult_p3(ge_p3* out, const unsigned char s[32], const ge_p3* P) {
  ge_p2 r;
  ge_scalarmult(&r, s, P);
  return p2_to_p3(out, &r);
}

void point_identity(ge_p3* out) {
  static const unsigned char identity_bytes[32] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  ge_frombytes_vartime(out, identity_bytes);
}

// Fixed global NUMS generator U for the linking tag (key image) J = x·U.
// hash-to-point of a domain string, cofactor-cleared into the prime-order
// subgroup. dlog wrt G and H is unknown (nothing-up-my-sleeve), which is
// what makes the binding f_P·U ⇒ J = x·U sound. Same hash-to-curve method
// as pedersen_get_H()'s compute_H().
EllipticCurvePoint compute_U() {
  static const char domain[] = "Karbo-CT-keyimage-generator-v1";
  Hash h;
  ge_p2 point;
  ge_p1p1 point2;
  EllipticCurvePoint result;
  cn_fast_hash(domain, sizeof(domain) - 1, h);
  ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char*>(&h));
  ge_mul8(&point2, &point);
  ge_p1p1_to_p2(&point, &point2);
  ge_tobytes(reinterpret_cast<unsigned char*>(&result), &point);
  return result;
}

const EllipticCurvePoint& keyimage_generator_U() {
  static const EllipticCurvePoint U_point = compute_U();
  return U_point;
}

} // anonymous namespace

// ── Fiat-Shamir transcript ─────────────────────────────────────────────
//
// Canonical serialization of every public input that contributes to the
// challenge. Maintained in a single function so every prover/verifier
// hash agrees byte-for-byte. Forgetting any component here is exactly
// the malleability class the design comment in triptych.h warns about.

namespace {

// n_bits = length of I_bits / A / B = log2(ring_size).
// n_q    = length of Q_P / Q_M / Q_J. Equals n_bits today; kept as a
//          separate parameter so the serialization width is explicit.
void compute_challenge(
  const Hash& message,
  size_t ring_size,
  size_t n_bits,
  size_t n_q,
  const PublicKey ring_pubkeys[],
  const EllipticCurvePoint ring_commits[],
  const EllipticCurvePoint& pseudo_commit,
  const KeyImage& key_image,
  const ge_p3* I_bits,
  const ge_p3* A,
  const ge_p3* B,
  const ge_p3* Q_P,
  const ge_p3* Q_M,
  const ge_p3* Q_J,
  EllipticCurveScalar& challenge)
{
  static const char domain[] = "Triptych-KarboCT-v2";
  const size_t domain_len = sizeof(domain) - 1;

  // Buffer layout:
  //   domain || message(32) || ring_size_byte(1) ||
  //   N*32 ring_pubkeys || N*32 ring_commits || 32 pseudo || 32 image ||
  //   n_bits*32 I_bits || n_bits*32 A || n_bits*32 B ||
  //   n_q*32 Q_P || n_q*32 Q_M || n_q*32 Q_J
  const size_t buf_size =
      domain_len
      + 32                       // message
      + 1                        // ring_size byte
      + 32 * ring_size           // ring_pubkeys
      + 32 * ring_size           // ring_commits
      + 32                       // pseudo_commit
      + 32                       // key_image
      + 32 * n_bits              // I_bits
      + 32 * n_bits              // A
      + 32 * n_bits              // B
      + 32 * n_q                 // Q_P
      + 32 * n_q                 // Q_M
      + 32 * n_q;                // Q_J

  std::vector<unsigned char> buf(buf_size);
  unsigned char* ptr = buf.data();

  std::memcpy(ptr, domain, domain_len);
  ptr += domain_len;

  std::memcpy(ptr, &message, 32);
  ptr += 32;

  *ptr++ = static_cast<unsigned char>(ring_size);

  for (size_t k = 0; k < ring_size; ++k) {
    std::memcpy(ptr, &ring_pubkeys[k], 32);
    ptr += 32;
  }
  for (size_t k = 0; k < ring_size; ++k) {
    std::memcpy(ptr, &ring_commits[k], 32);
    ptr += 32;
  }

  std::memcpy(ptr, &pseudo_commit, 32);
  ptr += 32;
  std::memcpy(ptr, &key_image, 32);
  ptr += 32;

  for (size_t j = 0; j < n_bits; ++j) { p3_to_bytes(ptr, &I_bits[j]); ptr += 32; }
  for (size_t j = 0; j < n_bits; ++j) { p3_to_bytes(ptr, &A[j]);      ptr += 32; }
  for (size_t j = 0; j < n_bits; ++j) { p3_to_bytes(ptr, &B[j]);      ptr += 32; }
  for (size_t m = 0; m < n_q;    ++m) { p3_to_bytes(ptr, &Q_P[m]);    ptr += 32; }
  for (size_t m = 0; m < n_q;    ++m) { p3_to_bytes(ptr, &Q_M[m]);    ptr += 32; }
  for (size_t m = 0; m < n_q;    ++m) { p3_to_bytes(ptr, &Q_J[m]);    ptr += 32; }

  assert(ptr == buf.data() + buf_size);

  cn_fast_hash(buf.data(), buf_size, reinterpret_cast<Hash&>(challenge));
  sc_reduce32(challenge.data);
}

} // anonymous namespace

// ── Selector polynomial coefficients ────────────────────────────────────
//
// p_k(X) = product_{j=0..n-1} f_{j, bit_j(k)}(X)
// f_{j,1}(X) = l_j·X + a_j        (bit set    in k)
// f_{j,0}(X) = (1−l_j)·X − a_j    (bit clear in k)
//
// Output: poly_coeffs[k][i] = coefficient of X^i in p_k(X), for i ∈ [0, n].
// For k = l: leading coefficient is 1 (every factor contributes its X term).
// For k ≠ l: leading coefficient is 0 (at least one factor is X-free).

namespace {

void compute_poly_coeffs(
  size_t ring_size,
  size_t n,
  const int bits[],
  const EllipticCurveScalar a[],
  std::vector<std::vector<EllipticCurveScalar>>& poly_coeffs)
{
  unsigned char zero[32];
  sc_0(zero);

  poly_coeffs.assign(ring_size, std::vector<EllipticCurveScalar>(n + 1));

  for (size_t k = 0; k < ring_size; ++k) {
    std::vector<std::array<unsigned char, 32>> poly(n + 1);
    for (auto& c : poly) std::memset(c.data(), 0, 32);
    poly[0][0] = 1;  // constant polynomial 1

    size_t current_degree = 0;

    for (size_t j = 0; j < n; ++j) {
      int k_j = (k >> j) & 1;
      int l_j = bits[j];

      unsigned char factor_const[32];
      unsigned char factor_linear[32];

      if (k_j == 1) {
        std::memcpy(factor_const, a[j].data, 32);
        std::memset(factor_linear, 0, 32);
        if (l_j) factor_linear[0] = 1;
      } else {
        sc_sub(factor_const, zero, a[j].data);
        std::memset(factor_linear, 0, 32);
        if (!l_j) factor_linear[0] = 1;
      }

      std::vector<std::array<unsigned char, 32>> new_poly(n + 1);
      for (auto& c : new_poly) std::memset(c.data(), 0, 32);

      for (size_t i = 0; i <= current_degree + 1; ++i) {
        unsigned char term1[32], term2[32];

        sc_mul(term1, factor_const, poly[i].data());

        if (i > 0) {
          sc_mul(term2, factor_linear, poly[i - 1].data());
          sc_add(new_poly[i].data(), term1, term2);
        } else {
          std::memcpy(new_poly[i].data(), term1, 32);
        }
      }

      current_degree++;
      poly = std::move(new_poly);
    }

    for (size_t i = 0; i <= n; ++i) {
      std::memcpy(poly_coeffs[k][i].data, poly[i].data(), 32);
    }
  }
}

} // anonymous namespace

// ── Prover ──────────────────────────────────────────────────────────────

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
  TriptychSignature& sig)
{
  if (!triptych_ring_size_supported(ring_size)) return false;
  if (true_index >= ring_size) return false;
  if (sc_check(reinterpret_cast<const unsigned char*>(&spend_privkey)) != 0) return false;
  if (sc_isnonzero(reinterpret_cast<const unsigned char*>(&spend_privkey)) == 0) return false;
  if (!ct_public_key_valid(ring_pubkeys[true_index])) return false;

  const size_t n = log2_ring(ring_size);

  // ── Step 1: compute key image J = x · U (fixed generator) ─────────────
  // Decode U once; reused as the linking-track base in Step 6.
  ge_p3 U_p3;
  if (ge_frombytes_vartime(&U_p3,
      reinterpret_cast<const unsigned char*>(&keyimage_generator_U())) != 0) return false;
  {
    ge_p2 image_p2;
    ge_scalarmult(&image_p2, reinterpret_cast<const unsigned char*>(&spend_privkey), &U_p3);
    ge_tobytes(reinterpret_cast<unsigned char*>(&key_image), &image_p2);
    EllipticCurvePoint ki_as_point;
    std::memcpy(ki_as_point.data, &key_image, 32);
    if (!point_valid_for_pedersen(ki_as_point)) return false;
  }

  // ── Step 2: blinding-difference scalar z = r_real − r_pseudo ──────────
  EllipticCurveScalar z_witness;
  sc_sub(reinterpret_cast<unsigned char*>(&z_witness),
         reinterpret_cast<const unsigned char*>(&real_blinding),
         reinterpret_cast<const unsigned char*>(&pseudo_blinding));

  // ── Step 3: prepare ring point caches ─────────────────────────────────
  // We decode every ring pubkey/commit once and compute M_k = C_k − C_pseudo.
  // The linking track no longer uses a per-key U_k = Hp(P_k) ring; it uses
  // the single fixed generator U (decoded above) with the SPEND response.
  // Reject early on any structurally-bad point.

  ge_p3 pseudo_p3;
  if (ge_frombytes_vartime(&pseudo_p3, reinterpret_cast<const unsigned char*>(&pseudo_commit)) != 0)
    return false;
  ge_cached pseudo_cached;
  ge_p3_to_cached(&pseudo_cached, &pseudo_p3);

  std::vector<ge_p3> P(ring_size);
  std::vector<ge_p3> M(ring_size);
  for (size_t k = 0; k < ring_size; ++k) {
    if (!ct_public_key_valid(ring_pubkeys[k])) return false;
    if (ge_frombytes_vartime(&P[k], reinterpret_cast<const unsigned char*>(&ring_pubkeys[k])) != 0)
      return false;

    ge_p3 C_k_p3;
    if (ge_frombytes_vartime(&C_k_p3, reinterpret_cast<const unsigned char*>(&ring_commits[k])) != 0)
      return false;
    ge_p1p1 diff;
    ge_sub(&diff, &C_k_p3, &pseudo_cached);
    ge_p1p1_to_p3(&M[k], &diff);
  }

  // ── Step 4: bit-decomposition phase (standard GK) ─────────────────────
  // Allocate sig vectors and fresh randomness for bit commitments.
  sig.I_bits.resize(n);
  sig.A.resize(n);
  sig.B.resize(n);
  sig.Q_P.resize(n);
  sig.Q_M.resize(n);
  sig.Q_J.resize(n);
  sig.z.resize(n);
  sig.za.resize(n);
  sig.zb.resize(n);

  std::vector<int> bits(n);
  for (size_t j = 0; j < n; ++j) bits[j] = (true_index >> j) & 1;

  std::vector<EllipticCurveScalar> r_j(n), a_j(n), s_j(n), t_j(n);
  for (size_t j = 0; j < n; ++j) {
    random_scalar(r_j[j]);
    random_scalar(a_j[j]);
    random_scalar(s_j[j]);
    random_scalar(t_j[j]);
  }

  ge_p3 H_p3;
  if (ge_frombytes_vartime(&H_p3,
      reinterpret_cast<const unsigned char*>(&pedersen_get_H())) != 0)
    return false;

  std::vector<ge_p3> I_bits_p3(n), A_p3(n), B_p3(n);
  for (size_t j = 0; j < n; ++j) {
    ge_p3 rG;
    ge_scalarmult_base(&rG, r_j[j].data);
    if (bits[j]) {
      point_add(&I_bits_p3[j], &rG, &H_p3);
    } else {
      I_bits_p3[j] = rG;
    }

    ge_p3 sG, aH;
    ge_scalarmult_base(&sG, s_j[j].data);
    if (!scalarmult_p3(&aH, a_j[j].data, &H_p3)) return false;
    point_add(&A_p3[j], &sG, &aH);

    ge_p3 tG;
    ge_scalarmult_base(&tG, t_j[j].data);
    if (bits[j]) {
      point_add(&B_p3[j], &tG, &aH);
    } else {
      B_p3[j] = tG;
    }
  }

  // ── Step 5: selector polynomial coefficients ──────────────────────────
  std::vector<std::vector<EllipticCurveScalar>> poly_coeffs;
  compute_poly_coeffs(ring_size, n, bits.data(), a_j.data(), poly_coeffs);

  // ── Step 6: Q polynomials ─────────────────────────────────────────────
  //   Q_P[m] = ρ_P[m]·G + Σ_k p_{k,m}·P_k     (P-ring, standard GK)
  //   Q_M[m] = ρ_M[m]·G + Σ_k p_{k,m}·M_k     (M-ring, standard GK)
  //   Q_J[m] = ρ_P[m]·U                        (linking track — REUSES ρ_P[m])
  // Reusing ρ_P[m] (not a fresh σ) is what binds the key image to the spend
  // key: the same blinding appears in Q_P (G-base) and Q_J (U-base), and the
  // SAME f_P response closes both, forcing J = x·U with the P-ring's x.
  std::vector<EllipticCurveScalar> rho_P(n), rho_M(n);
  std::vector<ge_p3> Q_P_p3(n), Q_M_p3(n), Q_J_p3(n);

  for (size_t m = 0; m < n; ++m) {
    random_scalar(rho_P[m]);
    random_scalar(rho_M[m]);

    ge_p3 sum_P, sum_M;
    ge_scalarmult_base(&sum_P, rho_P[m].data);
    ge_scalarmult_base(&sum_M, rho_M[m].data);

    for (size_t k = 0; k < ring_size; ++k) {
      const unsigned char* coeff = poly_coeffs[k][m].data;
      if (!sc_isnonzero(coeff)) continue;

      ge_p3 t_P, t_M;
      if (!scalarmult_p3(&t_P, coeff, &P[k])) return false;
      if (!scalarmult_p3(&t_M, coeff, &M[k])) return false;
      point_add(&sum_P, &sum_P, &t_P);
      point_add(&sum_M, &sum_M, &t_M);
    }

    Q_P_p3[m] = sum_P;
    Q_M_p3[m] = sum_M;
    // Linking track: Q_J[m] = ρ_P[m]·U.
    if (!scalarmult_p3(&Q_J_p3[m], rho_P[m].data, &U_p3)) return false;
  }

  // ── Step 7: Fiat-Shamir challenge ─────────────────────────────────────
  EllipticCurveScalar x_chal;
  compute_challenge(
    message, ring_size, /*n_bits=*/n, /*n_q=*/n,
    ring_pubkeys, ring_commits, pseudo_commit, key_image,
    I_bits_p3.data(), A_p3.data(), B_p3.data(),
    Q_P_p3.data(), Q_M_p3.data(), Q_J_p3.data(),
    x_chal);

  // ── Step 8: bit-commitment responses (z_j, za_j, zb_j) ────────────────
  for (size_t j = 0; j < n; ++j) {
    // z[j] = l_j·x + a_j
    if (bits[j]) {
      sc_add(sig.z[j].data, x_chal.data, a_j[j].data);
    } else {
      std::memcpy(sig.z[j].data, a_j[j].data, 32);
    }

    unsigned char term[32];

    // za[j] = r_j·x + s_j
    sc_mul(term, r_j[j].data, x_chal.data);
    sc_add(sig.za[j].data, term, s_j[j].data);

    // zb[j] = r_j·(x − z[j]) + t_j
    unsigned char x_minus_z[32];
    sc_sub(x_minus_z, x_chal.data, sig.z[j].data);
    sc_mul(term, r_j[j].data, x_minus_z);
    sc_add(sig.zb[j].data, term, t_j[j].data);
  }

  // ── Step 9: f_P, f_M responses (no independent image response) ────────
  //   f_P = x · x_chal^n  − Σ_m ρ_P[m] · x_chal^m   (also closes the linking eq)
  //   f_M = z · x_chal^n  − Σ_m ρ_M[m] · x_chal^m
  unsigned char x_pow[5][32];                   // up to X^4 for ring=16
  std::memset(x_pow[0], 0, 32);
  x_pow[0][0] = 1;
  if (n >= 1) std::memcpy(x_pow[1], x_chal.data, 32);
  for (size_t i = 2; i <= n; ++i) {
    sc_mul(x_pow[i], x_pow[i - 1], x_chal.data);
  }

  sc_mul(sig.f_P.data, reinterpret_cast<const unsigned char*>(&spend_privkey), x_pow[n]);
  sc_mul(sig.f_M.data, z_witness.data,                                        x_pow[n]);

  for (size_t m = 0; m < n; ++m) {
    unsigned char term[32];
    sc_mul(term, rho_P[m].data, x_pow[m]);
    sc_sub(sig.f_P.data, sig.f_P.data, term);
    sc_mul(term, rho_M[m].data, x_pow[m]);
    sc_sub(sig.f_M.data, sig.f_M.data, term);
  }

  // ── Step 10: serialize the proof's points into the on-wire struct ─────
  for (size_t j = 0; j < n; ++j) {
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.I_bits[j]), &I_bits_p3[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.A[j]),      &A_p3[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.B[j]),      &B_p3[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.Q_P[j]),    &Q_P_p3[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.Q_M[j]),    &Q_M_p3[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.Q_J[j]),    &Q_J_p3[j]);
  }

  // ── Cleanup: scrub witness-derived state ──────────────────────────────
  sodium_memzero(&z_witness, sizeof(z_witness));
  for (auto& s : r_j)     sodium_memzero(&s, sizeof(s));
  for (auto& s : a_j)     sodium_memzero(&s, sizeof(s));
  for (auto& s : s_j)     sodium_memzero(&s, sizeof(s));
  for (auto& s : t_j)     sodium_memzero(&s, sizeof(s));
  for (auto& s : rho_P)   sodium_memzero(&s, sizeof(s));
  for (auto& s : rho_M)   sodium_memzero(&s, sizeof(s));

  return true;
}

// ── Canonical key image: J = x · U ────────────────────────────────────────
bool triptych_key_image(const SecretKey& spend_privkey, KeyImage& key_image) {
  if (sc_check(reinterpret_cast<const unsigned char*>(&spend_privkey)) != 0) return false;
  if (sc_isnonzero(reinterpret_cast<const unsigned char*>(&spend_privkey)) == 0) return false;
  ge_p3 U_p3;
  if (ge_frombytes_vartime(&U_p3,
      reinterpret_cast<const unsigned char*>(&keyimage_generator_U())) != 0) return false;
  ge_p2 J_p2;
  ge_scalarmult(&J_p2, reinterpret_cast<const unsigned char*>(&spend_privkey), &U_p3);
  ge_tobytes(reinterpret_cast<unsigned char*>(&key_image), &J_p2);
  return true;
}

// ── Verifier ────────────────────────────────────────────────────────────

bool triptych_verify(
  const Hash& message,
  const PublicKey ring_pubkeys[],
  const EllipticCurvePoint ring_commits[],
  const EllipticCurvePoint& pseudo_commit,
  size_t ring_size,
  const KeyImage& key_image,
  const TriptychSignature& sig)
{
  if (!triptych_ring_size_supported(ring_size)) return false;
  const size_t n = log2_ring(ring_size);
  // triptych_ring_size_supported() guarantees ring_size ∈ {4, 8, 16};
  // every proof vector has exactly n entries. No Schnorr carve-out:
  // ring-size-1 ConfidentialInputs are not a valid shape on the wire.

  // Shape check.
  if (sig.I_bits.size() != n) return false;
  if (sig.A.size()      != n) return false;
  if (sig.B.size()      != n) return false;
  if (sig.Q_P.size()    != n) return false;
  if (sig.Q_M.size()    != n) return false;
  if (sig.Q_J.size()    != n) return false;
  if (sig.z.size()      != n) return false;
  if (sig.za.size()     != n) return false;
  if (sig.zb.size()     != n) return false;

  // Scalar range checks.
  if (sc_check(sig.f_P.data) != 0) return false;
  if (sc_check(sig.f_M.data) != 0) return false;
  for (size_t j = 0; j < n; ++j) {
    if (sc_check(sig.z[j].data)  != 0) return false;
    if (sc_check(sig.za[j].data) != 0) return false;
    if (sc_check(sig.zb[j].data) != 0) return false;
  }

  // Key image subgroup / non-identity check. The linking equation has J on
  // its LHS (x_chal^n · J); an off-subgroup J would let a malicious prover
  // forge the linking-tag binding.
  {
    EllipticCurvePoint ki_as_point;
    std::memcpy(ki_as_point.data, &key_image, 32);
    if (!point_valid_for_pedersen(ki_as_point)) return false;
  }
  ge_p3 J_p3;
  if (ge_frombytes_vartime(&J_p3, reinterpret_cast<const unsigned char*>(&key_image)) != 0)
    return false;

  // Decode all proof points; each must be subgroup-valid (rejects torsion
  // attacks that could otherwise sneak forged components past identity).
  std::vector<ge_p3> I_bits_p3(n), A_p3(n), B_p3(n);
  std::vector<ge_p3> Q_P_p3(n), Q_M_p3(n), Q_J_p3(n);
  for (size_t j = 0; j < n; ++j) {
    if (ge_frombytes_vartime(&I_bits_p3[j], reinterpret_cast<const unsigned char*>(&sig.I_bits[j])) != 0) return false;
    if (ge_frombytes_vartime(&A_p3[j],      reinterpret_cast<const unsigned char*>(&sig.A[j]))      != 0) return false;
    if (ge_frombytes_vartime(&B_p3[j],      reinterpret_cast<const unsigned char*>(&sig.B[j]))      != 0) return false;

    if (!subgroup_check_p3(I_bits_p3[j])) return false;
    if (!subgroup_check_p3(A_p3[j]))      return false;
    if (!subgroup_check_p3(B_p3[j]))      return false;
  }
  for (size_t m = 0; m < n; ++m) {
    if (ge_frombytes_vartime(&Q_P_p3[m], reinterpret_cast<const unsigned char*>(&sig.Q_P[m])) != 0) return false;
    if (ge_frombytes_vartime(&Q_M_p3[m], reinterpret_cast<const unsigned char*>(&sig.Q_M[m])) != 0) return false;
    if (ge_frombytes_vartime(&Q_J_p3[m], reinterpret_cast<const unsigned char*>(&sig.Q_J[m])) != 0) return false;

    if (!subgroup_check_p3(Q_P_p3[m])) return false;
    if (!subgroup_check_p3(Q_M_p3[m])) return false;
    if (!subgroup_check_p3(Q_J_p3[m])) return false;
  }

  // Fixed linking-tag generator U (for the J = x·U linking equation).
  ge_p3 U_p3;
  if (ge_frombytes_vartime(&U_p3,
      reinterpret_cast<const unsigned char*>(&keyimage_generator_U())) != 0)
    return false;

  // Decode ring inputs; recompute M_k = C_k − C_pseudo. No per-key U_k ring.
  ge_p3 pseudo_p3;
  if (ge_frombytes_vartime(&pseudo_p3, reinterpret_cast<const unsigned char*>(&pseudo_commit)) != 0)
    return false;
  if (!point_valid_for_pedersen(pseudo_commit)) return false;
  ge_cached pseudo_cached;
  ge_p3_to_cached(&pseudo_cached, &pseudo_p3);

  std::vector<ge_p3> P(ring_size);
  std::vector<ge_p3> M(ring_size);
  for (size_t k = 0; k < ring_size; ++k) {
    if (!ct_public_key_valid(ring_pubkeys[k])) return false;
    if (ge_frombytes_vartime(&P[k], reinterpret_cast<const unsigned char*>(&ring_pubkeys[k])) != 0) return false;

    if (!point_valid_for_pedersen(ring_commits[k])) return false;
    ge_p3 C_k_p3;
    if (ge_frombytes_vartime(&C_k_p3, reinterpret_cast<const unsigned char*>(&ring_commits[k])) != 0) return false;
    ge_p1p1 diff;
    ge_sub(&diff, &C_k_p3, &pseudo_cached);
    ge_p1p1_to_p3(&M[k], &diff);
  }

  // Recompute the Fiat-Shamir challenge from the same canonical buffer
  // the prover built. Any mismatch (tampered proof, swapped pseudo
  // commit, swapped key image, swapped tx prefix) flips x_chal and the
  // ring identities below fail by overwhelming probability.
  EllipticCurveScalar x_chal;
  compute_challenge(
    message, ring_size, /*n_bits=*/n, /*n_q=*/n,
    ring_pubkeys, ring_commits, pseudo_commit, key_image,
    I_bits_p3.data(), A_p3.data(), B_p3.data(),
    Q_P_p3.data(), Q_M_p3.data(), Q_J_p3.data(),
    x_chal);

  ge_p3 H_p3;
  if (ge_frombytes_vartime(&H_p3,
      reinterpret_cast<const unsigned char*>(&pedersen_get_H())) != 0)
    return false;

  // Bit-commitment equations:
  //   x_chal · I_bits[j] + A[j] == za[j] · G + z[j] · H
  //   (x_chal − z[j]) · I_bits[j] + B[j] == zb[j] · G
  for (size_t j = 0; j < n; ++j) {
    ge_p3 lhs, rhs, term;

    if (!scalarmult_p3(&lhs, x_chal.data, &I_bits_p3[j])) return false;
    point_add(&lhs, &lhs, &A_p3[j]);

    ge_scalarmult_base(&rhs, sig.za[j].data);
    if (!scalarmult_p3(&term, sig.z[j].data, &H_p3)) return false;
    point_add(&rhs, &rhs, &term);
    if (!point_equal(lhs, rhs)) return false;

    unsigned char x_minus_z[32];
    sc_sub(x_minus_z, x_chal.data, sig.z[j].data);
    if (!scalarmult_p3(&lhs, x_minus_z, &I_bits_p3[j])) return false;
    point_add(&lhs, &lhs, &B_p3[j]);

    ge_scalarmult_base(&rhs, sig.zb[j].data);
    if (!point_equal(lhs, rhs)) return false;
  }

  // p_k(x_chal) for every k. Same product as the prover, evaluated at
  // x_chal: if (k>>j)&1 then z[j] else (x_chal − z[j]).
  std::vector<EllipticCurveScalar> pk(ring_size);
  for (size_t k = 0; k < ring_size; ++k) {
    unsigned char product[32];
    sc_0(product);
    product[0] = 1;

    for (size_t j = 0; j < n; ++j) {
      int k_j = (k >> j) & 1;
      unsigned char factor[32];
      if (k_j == 1) {
        std::memcpy(factor, sig.z[j].data, 32);
      } else {
        sc_sub(factor, x_chal.data, sig.z[j].data);
      }
      sc_mul(product, product, factor);
    }
    std::memcpy(pk[k].data, product, 32);
  }

  // Powers of x_chal: X^0 .. X^n. X^n is needed by the linking equation;
  // the Q-term aggregation uses X^0 .. X^{n-1}.
  unsigned char x_pow[5][32];                   // n ≤ 4 ⇒ X^0..X^4
  std::memset(x_pow[0], 0, 32);
  x_pow[0][0] = 1;
  if (n >= 1) std::memcpy(x_pow[1], x_chal.data, 32);
  for (size_t i = 2; i <= n; ++i) {
    sc_mul(x_pow[i], x_pow[i - 1], x_chal.data);
  }

  // P/M ring-identity check (base G):
  //   Σ_k p_k(x_chal)·R_k  ?=  f_R·G + Σ_{m<n} x_chal^m · Q_R[m]
  auto check_ring_G = [&](const std::vector<ge_p3>& R,
                          const std::vector<ge_p3>& Q_R,
                          const EllipticCurveScalar& f_R) -> bool {
    ge_p3 lhs;
    point_identity(&lhs);
    for (size_t k = 0; k < ring_size; ++k) {
      if (!sc_isnonzero(pk[k].data)) continue;
      ge_p3 term;
      if (!scalarmult_p3(&term, pk[k].data, &R[k])) return false;
      point_add(&lhs, &lhs, &term);
    }
    ge_p3 rhs;
    ge_scalarmult_base(&rhs, f_R.data);
    for (size_t m = 0; m < n; ++m) {
      ge_p3 term;
      if (!scalarmult_p3(&term, x_pow[m], &Q_R[m])) return false;
      point_add(&rhs, &rhs, &term);
    }
    return point_equal(lhs, rhs);
  };

  // P-ring: proves P_l = x·G with witness x.
  if (!check_ring_G(P, Q_P_p3, sig.f_P))  return false;
  // M-ring: proves M_l = z·G ⇔ C_l − C_pseudo commits to zero (amount balance).
  if (!check_ring_G(M, Q_M_p3, sig.f_M))  return false;

  // Linking equation: x_chal^n · J  ?=  f_P·U + Σ_{m<n} x_chal^m · Q_J[m].
  // REUSES f_P (the spend response), so J = x·U is bound to the SAME x the
  // P-ring proves for P_l. The X^n coefficient pins J = x·U; Q_J spans only
  // m<n, so the prover cannot inject an X^n term to move J off x·U. This is
  // the binding the independent-f_U construction lacked.
  {
    ge_p3 lhs;
    if (!scalarmult_p3(&lhs, x_pow[n], &J_p3)) return false;
    ge_p3 rhs;
    if (!scalarmult_p3(&rhs, sig.f_P.data, &U_p3)) return false;
    for (size_t m = 0; m < n; ++m) {
      ge_p3 term;
      if (!scalarmult_p3(&term, x_pow[m], &Q_J_p3[m])) return false;
      point_add(&rhs, &rhs, &term);
    }
    if (!point_equal(lhs, rhs)) return false;
  }

  return true;
}

// ── Batched verifier ───────────────────────────────────────────────────
//
// Per-proof: collect every verifier equation as an MSMTerm list plus G/H
// coefficients. Across proofs: scale each equation by a fresh random α
// scalar and concatenate. Final check: one Pippenger MSM over the
// combined term list, plus a single fixed-base scalarmult on G and one
// scalarmult on H.
//
// The construction mirrors gk_verify_batch's α-batching exactly; the
// only differences are the per-equation algebra (Triptych's three ring
// identities + the bit-commit equations for n≥1, or the three Schnorr
// equations for ring=1).

namespace {

// dst = -a (mod L).
void tx_sc_neg(unsigned char dst[32], const unsigned char a[32]) {
  unsigned char zero[32];
  sc_0(zero);
  sc_sub(dst, zero, a);
}

// dst += s · src (mod L).
void tx_sc_addmul(unsigned char dst[32],
                  const unsigned char s[32],
                  const unsigned char src[32]) {
  unsigned char t[32];
  sc_mul(t, s, src);
  sc_add(dst, dst, t);
}

// All equations a single Triptych proof must satisfy, plus the per-
// equation G and H coefficients (consolidated separately so the batched
// dispatch can collapse them across the whole batch).
//
// Equation count: for ring_size = N ∈ {4, 8, 16} with n = log2(N),
// each proof asserts 2n bit-commitment equations plus the P-ring, M-ring
// and linking equation, so 2n + 3 total.
struct TriptychClaim {
  std::vector<std::vector<MSMTerm>>  equations;
  std::vector<EllipticCurveScalar>   gG;
  std::vector<EllipticCurveScalar>   gH;
};

// Returns false for any structural problem (bad ring size, bad shape,
// scalar out of range, point fails subgroup, key image off-subgroup,
// pseudo-commit off-subgroup, ring pubkey invalid). On success, fills
// `claim` and sets `H_p3_out` to the cached Pedersen H point.
//
// Mirrors triptych_verify's prechecks exactly so any input that this
// function accepts the per-input verifier would also accept structurally.
bool triptych_collect_claims(
  const Hash& message,
  const PublicKey* ring_pubkeys,
  const EllipticCurvePoint* ring_commits,
  const EllipticCurvePoint& pseudo_commit,
  size_t ring_size,
  const KeyImage& key_image,
  const TriptychSignature& sig,
  TriptychClaim& claim,
  ge_p3& H_p3_out)
{
  if (!triptych_ring_size_supported(ring_size)) return false;
  const size_t n = log2_ring(ring_size);

  // Shape and scalar-range checks (same as triptych_verify).
  if (sig.I_bits.size() != n) return false;
  if (sig.A.size()      != n) return false;
  if (sig.B.size()      != n) return false;
  if (sig.Q_P.size()    != n) return false;
  if (sig.Q_M.size()    != n) return false;
  if (sig.Q_J.size()    != n) return false;
  if (sig.z.size()      != n) return false;
  if (sig.za.size()     != n) return false;
  if (sig.zb.size()     != n) return false;

  if (sc_check(sig.f_P.data) != 0) return false;
  if (sc_check(sig.f_M.data) != 0) return false;
  for (size_t j = 0; j < n; ++j) {
    if (sc_check(sig.z[j].data)  != 0) return false;
    if (sc_check(sig.za[j].data) != 0) return false;
    if (sc_check(sig.zb[j].data) != 0) return false;
  }

  // Key image subgroup / non-identity check.
  {
    EllipticCurvePoint ki_as_point;
    std::memcpy(ki_as_point.data, &key_image, 32);
    if (!point_valid_for_pedersen(ki_as_point)) return false;
  }
  ge_p3 J_p3;
  if (ge_frombytes_vartime(&J_p3, reinterpret_cast<const unsigned char*>(&key_image)) != 0)
    return false;

  // Decode all proof points; subgroup-check each.
  std::vector<ge_p3> I_bits_p3(n), A_p3(n), B_p3(n);
  std::vector<ge_p3> Q_P_p3(n), Q_M_p3(n), Q_J_p3(n);
  for (size_t j = 0; j < n; ++j) {
    if (ge_frombytes_vartime(&I_bits_p3[j], reinterpret_cast<const unsigned char*>(&sig.I_bits[j])) != 0) return false;
    if (ge_frombytes_vartime(&A_p3[j],      reinterpret_cast<const unsigned char*>(&sig.A[j]))      != 0) return false;
    if (ge_frombytes_vartime(&B_p3[j],      reinterpret_cast<const unsigned char*>(&sig.B[j]))      != 0) return false;
    if (!subgroup_check_p3(I_bits_p3[j])) return false;
    if (!subgroup_check_p3(A_p3[j]))      return false;
    if (!subgroup_check_p3(B_p3[j]))      return false;
  }
  for (size_t m = 0; m < n; ++m) {
    if (ge_frombytes_vartime(&Q_P_p3[m], reinterpret_cast<const unsigned char*>(&sig.Q_P[m])) != 0) return false;
    if (ge_frombytes_vartime(&Q_M_p3[m], reinterpret_cast<const unsigned char*>(&sig.Q_M[m])) != 0) return false;
    if (ge_frombytes_vartime(&Q_J_p3[m], reinterpret_cast<const unsigned char*>(&sig.Q_J[m])) != 0) return false;
    if (!subgroup_check_p3(Q_P_p3[m])) return false;
    if (!subgroup_check_p3(Q_M_p3[m])) return false;
    if (!subgroup_check_p3(Q_J_p3[m])) return false;
  }

  // Fixed linking-tag generator U (for the J = x·U linking equation).
  ge_p3 U_p3;
  if (ge_frombytes_vartime(&U_p3,
      reinterpret_cast<const unsigned char*>(&keyimage_generator_U())) != 0)
    return false;

  // Decode ring inputs; recompute M_k = C_k − C_pseudo. No per-key U_k ring.
  ge_p3 pseudo_p3;
  if (ge_frombytes_vartime(&pseudo_p3, reinterpret_cast<const unsigned char*>(&pseudo_commit)) != 0)
    return false;
  if (!point_valid_for_pedersen(pseudo_commit)) return false;
  ge_cached pseudo_cached;
  ge_p3_to_cached(&pseudo_cached, &pseudo_p3);

  std::vector<ge_p3> P(ring_size), M(ring_size);
  for (size_t k = 0; k < ring_size; ++k) {
    if (!ct_public_key_valid(ring_pubkeys[k])) return false;
    if (ge_frombytes_vartime(&P[k], reinterpret_cast<const unsigned char*>(&ring_pubkeys[k])) != 0) return false;

    if (!point_valid_for_pedersen(ring_commits[k])) return false;
    ge_p3 C_k_p3;
    if (ge_frombytes_vartime(&C_k_p3, reinterpret_cast<const unsigned char*>(&ring_commits[k])) != 0) return false;
    ge_p1p1 diff;
    ge_sub(&diff, &C_k_p3, &pseudo_cached);
    ge_p1p1_to_p3(&M[k], &diff);
  }

  // Recompute the Fiat-Shamir challenge.
  EllipticCurveScalar x_chal;
  compute_challenge(
    message, ring_size, /*n_bits=*/n, /*n_q=*/n,
    ring_pubkeys, ring_commits, pseudo_commit, key_image,
    I_bits_p3.data(), A_p3.data(), B_p3.data(),
    Q_P_p3.data(), Q_M_p3.data(), Q_J_p3.data(),
    x_chal);

  // Cache the Pedersen H point for the batch dispatch.
  if (ge_frombytes_vartime(&H_p3_out,
      reinterpret_cast<const unsigned char*>(&pedersen_get_H())) != 0)
    return false;

  // Build equation lists. ring_size ∈ {4, 8, 16}; the prior ring-size-1
  // Schnorr carve-out was unsound (did not bind the same x in P = xG and
  // J = x·U) and has been removed.
  const size_t n_eq = 2 * n + 3;
  claim.equations.assign(n_eq, {});
  claim.gG.assign(n_eq, EllipticCurveScalar{});
  claim.gH.assign(n_eq, EllipticCurveScalar{});
  for (size_t e = 0; e < n_eq; ++e) {
    sc_0(claim.gG[e].data);
    sc_0(claim.gH[e].data);
  }

  unsigned char one_s[32]; sc_0(one_s); one_s[0] = 1;

  // ── Bit-commitment equations (j = 0..n-1) ────────────────────────────
  //   eq_a[j] : x_chal·I_bits[j] + A[j] − za[j]·G − z[j]·H == 0
  //   eq_b[j] : (x_chal − z[j])·I_bits[j] + B[j] − zb[j]·G == 0
  for (size_t j = 0; j < n; ++j) {
    // eq_a[j]
    {
      auto& eq = claim.equations[j];
      MSMTerm t_I;  std::memcpy(t_I.scalar.data, x_chal.data, 32); t_I.point = I_bits_p3[j]; eq.push_back(t_I);
      MSMTerm t_A;  std::memcpy(t_A.scalar.data, one_s,       32); t_A.point = A_p3[j];      eq.push_back(t_A);
      // -za[j] on G
      unsigned char neg_za[32]; tx_sc_neg(neg_za, sig.za[j].data);
      std::memcpy(claim.gG[j].data, neg_za, 32);
      // -z[j] on H
      unsigned char neg_z[32]; tx_sc_neg(neg_z, sig.z[j].data);
      std::memcpy(claim.gH[j].data, neg_z, 32);
    }
    // eq_b[j]
    {
      auto& eq = claim.equations[n + j];
      MSMTerm t_I;
      sc_sub(t_I.scalar.data, x_chal.data, sig.z[j].data);
      t_I.point = I_bits_p3[j];
      eq.push_back(t_I);
      MSMTerm t_B;  std::memcpy(t_B.scalar.data, one_s, 32); t_B.point = B_p3[j]; eq.push_back(t_B);
      // -zb[j] on G
      unsigned char neg_zb[32]; tx_sc_neg(neg_zb, sig.zb[j].data);
      std::memcpy(claim.gG[n + j].data, neg_zb, 32);
    }
  }

  // ── p_k(x_chal) for each k ────────────────────────────────────────────
  std::vector<EllipticCurveScalar> pk(ring_size);
  for (size_t k = 0; k < ring_size; ++k) {
    unsigned char product[32];
    sc_0(product); product[0] = 1;
    for (size_t j = 0; j < n; ++j) {
      int k_j = (k >> j) & 1;
      unsigned char factor[32];
      if (k_j == 1) {
        std::memcpy(factor, sig.z[j].data, 32);
      } else {
        sc_sub(factor, x_chal.data, sig.z[j].data);
      }
      sc_mul(product, product, factor);
    }
    std::memcpy(pk[k].data, product, 32);
  }

  // ── Powers x_chal^0 .. x_chal^n (X^n needed by the linking equation) ──
  std::vector<std::array<unsigned char, 32>> x_pow(n + 1);
  std::memset(x_pow[0].data(), 0, 32);
  x_pow[0][0] = 1;
  if (n >= 1) std::memcpy(x_pow[1].data(), x_chal.data, 32);
  for (size_t i = 2; i <= n; ++i) {
    sc_mul(x_pow[i].data(), x_pow[i - 1].data(), x_chal.data);
  }

  // P/M ring builder (base G). eq index is 2n + which_row.
  // Equation: Σ_k p_k(x_chal)·R_k − f_R·G − Σ_{m<n} x_chal^m·Q[m] == 0.
  auto build_ring_eq = [&](size_t eq_idx,
                           const std::vector<ge_p3>& R_pts,
                           const std::vector<ge_p3>& Q_pts,
                           const EllipticCurveScalar& f_R) {
    auto& eq = claim.equations[eq_idx];
    eq.reserve(ring_size + n);

    // Σ_k p_k(x_chal) · R_k
    for (size_t k = 0; k < ring_size; ++k) {
      if (!sc_isnonzero(pk[k].data)) continue;
      MSMTerm t;
      std::memcpy(t.scalar.data, pk[k].data, 32);
      t.point = R_pts[k];
      eq.push_back(t);
    }
    // − Σ_m x_chal^m · Q[m]
    for (size_t m = 0; m < n; ++m) {
      MSMTerm t;
      tx_sc_neg(t.scalar.data, x_pow[m].data());
      t.point = Q_pts[m];
      eq.push_back(t);
    }
    // − f_R on G
    unsigned char neg_f[32]; tx_sc_neg(neg_f, f_R.data);
    std::memcpy(claim.gG[eq_idx].data, neg_f, 32);
  };

  build_ring_eq(2 * n + 0, P, Q_P_p3, sig.f_P);
  build_ring_eq(2 * n + 1, M, Q_M_p3, sig.f_M);

  // Linking equation (eq 2n+2): x_chal^n·J − f_P·U − Σ_{m<n} x_chal^m·Q_J[m] == 0.
  // REUSES f_P, so J = x·U binds to the same x as the P-ring. U is the fixed
  // global generator (same point for every proof in the batch); we add it as a
  // per-proof term rather than a consolidated base for code simplicity.
  {
    auto& eq = claim.equations[2 * n + 2];
    eq.reserve(2 + n);
    // + x_chal^n · J
    MSMTerm tJ; std::memcpy(tJ.scalar.data, x_pow[n].data(), 32); tJ.point = J_p3; eq.push_back(tJ);
    // − f_P · U
    MSMTerm tU; tx_sc_neg(tU.scalar.data, sig.f_P.data); tU.point = U_p3; eq.push_back(tU);
    // − Σ_{m<n} x_chal^m · Q_J[m]
    for (size_t m = 0; m < n; ++m) {
      MSMTerm t;
      tx_sc_neg(t.scalar.data, x_pow[m].data());
      t.point = Q_J_p3[m];
      eq.push_back(t);
    }
  }

  return true;
}

} // anonymous namespace

bool triptych_verify_batch(
  const Hash& message,
  const PublicKey* const* ring_pubkeys,
  const EllipticCurvePoint* const* ring_commits,
  const EllipticCurvePoint* pseudo_commits,
  const size_t* ring_sizes,
  const KeyImage* key_images,
  const TriptychSignature* sigs,
  size_t count)
{
  if (count == 0) return true;
  if (ring_pubkeys == nullptr || ring_commits == nullptr ||
      pseudo_commits == nullptr || ring_sizes == nullptr ||
      key_images == nullptr || sigs == nullptr) return false;

  // Collect every per-proof claim. A structurally-bad proof rejects
  // immediately — this matches per-input verify behavior. The batched
  // dispatch is not reached on rejection.
  std::vector<TriptychClaim> claims(count);
  ge_p3 H_p3;
  for (size_t i = 0; i < count; ++i) {
    if (!triptych_collect_claims(
          message, ring_pubkeys[i], ring_commits[i], pseudo_commits[i],
          ring_sizes[i], key_images[i], sigs[i], claims[i], H_p3)) {
      return false;
    }
  }

  // Derive α per equation from a Fiat-Shamir transcript that commits to
  // EVERY proof in the batch (key images, pseudo commitments, ring
  // contents, and every byte of every TriptychSignature) — not just the
  // tx prefix hash. The α must be unpredictable to the prover at the
  // time the proofs are constructed; if α depended only on `message`
  // (which is the tx prefix hash, fixed BEFORE the proofs are written),
  // a prover could pre-compute α and then craft proofs whose individual
  // equations cancel out under the known α-weighting, passing batched
  // verification while failing per-input verification. Hashing every
  // proof byte into the transcript closes that gap: each α now depends
  // on the proofs themselves, so any change in a single proof flips
  // every α and forces all 2n+3 per-proof equations to hold
  // independently (Schwartz-Zippel false-accept ≤ 1/L ≈ 2⁻²⁵²).
  //
  // Determinism is preserved (consensus nodes derive the same α for the
  // same tx) because the input bytes are fully fixed once the
  // transaction body is on the wire. Indices are written big-endian so
  // the derivation is portable across host endianness.
  Hash batch_transcript;
  {
    static constexpr char kTranscriptDomain[] = "TriptychBatchTranscriptV2";
    constexpr size_t kTranscriptDomainLen = sizeof(kTranscriptDomain) - 1;

    // Pre-compute the buffer size so we hash everything in one pass.
    size_t buf_size = kTranscriptDomainLen + 32 /*message*/;
    for (size_t i = 0; i < count; ++i) {
      const size_t rs = ring_sizes[i];
      buf_size += 1 /*ring_size byte*/ + 32 /*key image*/ + 32 /*pseudo*/;
      buf_size += rs * (32 /*pubkey*/ + 32 /*commit*/);
      const auto& s = sigs[i];
      buf_size += (s.I_bits.size() + s.A.size() + s.B.size() +
                   s.Q_P.size()  + s.Q_M.size() + s.Q_J.size()) * 32;
      buf_size += (s.z.size() + s.za.size() + s.zb.size()) * 32;
      buf_size += 2 * 32; // f_P, f_M
    }

    std::vector<unsigned char> buf(buf_size);
    unsigned char* ptr = buf.data();
    std::memcpy(ptr, kTranscriptDomain, kTranscriptDomainLen);
    ptr += kTranscriptDomainLen;
    std::memcpy(ptr, message.data, 32);
    ptr += 32;
    for (size_t i = 0; i < count; ++i) {
      const size_t rs = ring_sizes[i];
      *ptr++ = static_cast<unsigned char>(rs);
      std::memcpy(ptr, &key_images[i], 32);  ptr += 32;
      std::memcpy(ptr, &pseudo_commits[i], 32); ptr += 32;
      for (size_t k = 0; k < rs; ++k) {
        std::memcpy(ptr, &ring_pubkeys[i][k], 32); ptr += 32;
        std::memcpy(ptr, &ring_commits[i][k], 32); ptr += 32;
      }
      const auto& s = sigs[i];
      auto copyPts = [&](const std::vector<EllipticCurvePoint>& v) {
        for (const auto& p : v) { std::memcpy(ptr, &p, 32); ptr += 32; }
      };
      auto copyScs = [&](const std::vector<EllipticCurveScalar>& v) {
        for (const auto& sc : v) { std::memcpy(ptr, &sc, 32); ptr += 32; }
      };
      copyPts(s.I_bits); copyPts(s.A); copyPts(s.B);
      copyPts(s.Q_P);    copyPts(s.Q_M); copyPts(s.Q_J);
      copyScs(s.z); copyScs(s.za); copyScs(s.zb);
      std::memcpy(ptr, &s.f_P, 32); ptr += 32;
      std::memcpy(ptr, &s.f_M, 32); ptr += 32;
    }
    assert(ptr == buf.data() + buf_size);
    cn_fast_hash(buf.data(), buf_size, batch_transcript);
  }

  size_t total_eqs = 0;
  for (const auto& c : claims) total_eqs += c.equations.size();
  std::vector<EllipticCurveScalar> alpha(total_eqs);
  {
    size_t idx = 0;
    static constexpr char kAlphaDomain[] = "TriptychBatchAlphaV2";
    constexpr size_t kAlphaDomainLen = sizeof(kAlphaDomain) - 1;
    for (size_t i = 0; i < count; ++i) {
      for (size_t e = 0; e < claims[i].equations.size(); ++e) {
        unsigned char buf[32 + 8 + 8 + kAlphaDomainLen];
        std::memcpy(buf, batch_transcript.data, 32);
        // Big-endian indices: same bytes on every host architecture.
        const uint64_t pidx = static_cast<uint64_t>(i);
        const uint64_t eidx = static_cast<uint64_t>(e);
        for (int b = 0; b < 8; ++b) {
          buf[32 + b] = static_cast<unsigned char>((pidx >> (56 - b * 8)) & 0xff);
          buf[40 + b] = static_cast<unsigned char>((eidx >> (56 - b * 8)) & 0xff);
        }
        std::memcpy(buf + 48, kAlphaDomain, kAlphaDomainLen);
        Hash h;
        cn_fast_hash(buf, sizeof(buf), h);
        std::memcpy(alpha[idx].data, h.data, 32);
        sc_reduce32(alpha[idx].data);
        ++idx;
      }
    }
  }

  // Build the combined MSM input. Scale every non-G/H term by its α;
  // accumulate α-scaled G and H scalars across all (proof, equation)
  // pairs into single totals.
  std::vector<MSMTerm> combined;
  // Rough upper bound on terms: per proof, ~(ring_size + n) per ring
  // equation × 3 ring equations + 2 per bit equation × 2n. For ring=16
  // (n=4) that's ~3·(16+4) + 2·2·4 = ~76 terms/proof; reserve enough
  // headroom to amortize allocations.
  combined.reserve(count * 96);

  unsigned char totalG[32]; sc_0(totalG);
  unsigned char totalH[32]; sc_0(totalH);

  size_t alpha_idx = 0;
  for (size_t i = 0; i < count; ++i) {
    for (size_t e = 0; e < claims[i].equations.size(); ++e) {
      const auto& a = alpha[alpha_idx++];
      for (const auto& term : claims[i].equations[e]) {
        MSMTerm scaled;
        sc_mul(scaled.scalar.data, a.data, term.scalar.data);
        scaled.point = term.point;
        combined.push_back(scaled);
      }
      tx_sc_addmul(totalG, a.data, claims[i].gG[e].data);
      tx_sc_addmul(totalH, a.data, claims[i].gH[e].data);
    }
  }

  return msm_pippenger_sum_is_identity(combined, totalG, totalH, H_p3);
}

} // namespace Crypto
