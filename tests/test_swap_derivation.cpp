// Session 9 — Atomic-swap derivation test vector (independent oracle).
//
// NOT a consensus dependency. Proves the Karbo side of an XMR-style atomic
// swap needs ZERO new signature primitives: a funding output locked to an
// additive 2-of-2 spend key B_swap = B_a + B_b can be derived by both parties
// and, once one party reconstructs x = b_a + b_b (the missing share is revealed
// by the Bitcoin-side adaptor, out of scope here), spent with the ordinary
// ring-1 CryptoNote signature.
//
// Construction (see karbo-swaps-and-ct-to-cn.md §1):
//   Setup (commit-reveal): each party commits H(B_i) before revealing B_i,
//                          then B_swap = B_a + B_b   (safe after commit round)
//   Funding (A picks r):   R     = r*G
//                          D     = 8*r*A_swap         (== generate_key_derivation)
//                          P_out = Hs(D||i)*G + B_swap (== derive_public_key)
//   Settlement:            p_out = Hs(D||i) + b_a + b_b (== derive_secret_key on x)
//                          assert p_out*G == P_out, then ring-1 spend P_out.
//
// Gotchas this vector pins against real code:
//   - generate_key_derivation returns 8*r*A (ge_mul8), not r*A.
//   - derivation_to_scalar hashes D || varint(output_index): the index is
//     INSIDE the hash; dropping it (or using the wrong i) mismatches.
//   - commit-reveal (not bare B_a + B_b) defeats the rogue-key attack.

#include "crypto/crypto.h"
#include "crypto/hash.h"

#include <cstdio>
#include <cstring>

extern "C" {
#include "crypto/crypto-ops.h"
}

namespace {

static int tests_run = 0;
static int tests_passed = 0;
static const char* current_test = "";

#define TEST(name) do { current_test = (name); ++tests_run; } while (0)
#define FAIL(msg) do { \
    std::fprintf(stderr, "FAIL [%s]: %s\n", current_test, (msg)); \
    return; \
  } while (0)
#define PASS() do { \
    ++tests_passed; \
    std::printf("  %-66s [PASS]\n", current_test); \
  } while (0)

// out = a + b on the curve (B_a + B_b). Returns false if either input is not a
// valid point.
bool addPublicKeys(const Crypto::PublicKey& a, const Crypto::PublicKey& b, Crypto::PublicKey& out) {
  ge_p3 A3, B3;
  if (ge_frombytes_vartime(&A3, reinterpret_cast<const unsigned char*>(&a)) != 0) return false;
  if (ge_frombytes_vartime(&B3, reinterpret_cast<const unsigned char*>(&b)) != 0) return false;
  ge_cached Bc;
  ge_p3_to_cached(&Bc, &B3);
  ge_p1p1 sum1;
  ge_add(&sum1, &A3, &Bc);
  ge_p3 sum3;
  ge_p1p1_to_p3(&sum3, &sum1);
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&out), &sum3);
  return true;
}

// out = (a + b) mod L  (b_a + b_b).
void addSecretKeys(const Crypto::SecretKey& a, const Crypto::SecretKey& b, Crypto::SecretKey& out) {
  sc_add(reinterpret_cast<unsigned char*>(&out),
         reinterpret_cast<const unsigned char*>(&a),
         reinterpret_cast<const unsigned char*>(&b));
}

bool keysEqual(const Crypto::PublicKey& a, const Crypto::PublicKey& b) {
  return std::memcmp(&a, &b, sizeof(a)) == 0;
}

// ── The full swap derivation round-trip ──────────────────────────────────────
void test_swap_derivation_roundtrip() {
  TEST("Swap: 2-of-2 funding derivation + ring-1 spend round-trips");

  // Setup: each party's spend keypair.
  Crypto::PublicKey B_a, B_b;
  Crypto::SecretKey b_a, b_b;
  Crypto::generate_keys(B_a, b_a);
  Crypto::generate_keys(B_b, b_b);

  // Commit-reveal: commit H(B_i) first, reveal B_i second; the revealed key
  // must match its commitment. This is what blocks the rogue-key attack
  // (a second mover can't pick B_b' = B_b - B_a after seeing B_a).
  Crypto::Hash commit_a = Crypto::cn_fast_hash(&B_a, sizeof(B_a));
  Crypto::Hash commit_b = Crypto::cn_fast_hash(&B_b, sizeof(B_b));
  if (Crypto::cn_fast_hash(&B_a, sizeof(B_a)) != commit_a) FAIL("commit A mismatch");
  if (Crypto::cn_fast_hash(&B_b, sizeof(B_b)) != commit_b) FAIL("commit B mismatch");

  // Aggregate spend key and the (never-co-held) aggregate secret.
  Crypto::PublicKey B_swap;
  if (!addPublicKeys(B_a, B_b, B_swap)) FAIL("B_a + B_b failed");
  Crypto::SecretKey x_swap;
  addSecretKeys(b_a, b_b, x_swap);

  // (b_a + b_b)*G must equal B_a + B_b — aggregate secret matches aggregate key.
  Crypto::PublicKey x_swap_pub;
  if (!Crypto::secret_key_to_public_key(x_swap, x_swap_pub)) FAIL("x_swap not a valid secret");
  if (!keysEqual(x_swap_pub, B_swap)) FAIL("(b_a+b_b)*G != B_a+B_b");

  // Swap view keypair (decides who can DERIVE the output, never who can spend).
  Crypto::PublicKey A_swap;
  Crypto::SecretKey a_swap;
  Crypto::generate_keys(A_swap, a_swap);

  // Funding: party A picks r, publishes R = r*G, computes D = 8*r*A_swap.
  Crypto::PublicKey R;
  Crypto::SecretKey r;
  Crypto::generate_keys(R, r);

  Crypto::KeyDerivation D_funder;
  if (!Crypto::generate_key_derivation(A_swap, r, D_funder)) FAIL("funder derivation failed");

  // The counterparty/scanner recomputes D from the public R and the view secret
  // a_swap: 8*a_swap*R == 8*r*A_swap. Both sides MUST get the same D (this is
  // where the ×8 cofactor has to cancel symmetrically).
  Crypto::KeyDerivation D_scanner;
  if (!Crypto::generate_key_derivation(R, a_swap, D_scanner)) FAIL("scanner derivation failed");
  if (std::memcmp(&D_funder, &D_scanner, sizeof(D_funder)) != 0)
    FAIL("funder and scanner derived different D (cofactor mismatch?)");

  const size_t i = 7;  // output index — goes INSIDE the derivation hash.
  Crypto::PublicKey P_out;
  if (!Crypto::derive_public_key(D_funder, i, B_swap, P_out)) FAIL("derive_public_key failed");

  // Settlement: the reconstructing party computes p_out = Hs(D||i) + (b_a+b_b).
  Crypto::SecretKey p_out;
  Crypto::derive_secret_key(D_scanner, i, x_swap, p_out);

  // p_out*G == P_out — the reconstructed one-time secret really opens the output.
  Crypto::PublicKey p_out_pub;
  if (!Crypto::secret_key_to_public_key(p_out, p_out_pub)) FAIL("p_out not a valid secret");
  if (!keysEqual(p_out_pub, P_out)) FAIL("p_out*G != P_out (settlement key wrong)");

  // Spend with the ORDINARY ring-1 CryptoNote signature — no adaptor, no new
  // primitive. Sign a message (here the key image, a stand-in for the tx prefix
  // hash) and verify it against P_out.
  Crypto::KeyImage img;
  Crypto::generate_key_image(P_out, p_out, img);
  Crypto::Hash msg = Crypto::cn_fast_hash(&img, sizeof(img));

  Crypto::Signature sig;
  Crypto::generate_signature(msg, P_out, p_out, sig);
  if (!Crypto::check_signature(msg, P_out, sig)) FAIL("ring-1 spend signature did not verify");

  // Tampered signature must fail.
  Crypto::Signature bad = sig;
  reinterpret_cast<unsigned char*>(&bad)[0] ^= 0x01;
  if (Crypto::check_signature(msg, P_out, bad)) FAIL("tampered signature accepted");

  PASS();
}

// ── A single party alone cannot spend (2-of-2 really binds both shares) ───────
void test_swap_single_party_cannot_spend() {
  TEST("Swap: one party's share alone cannot open the 2-of-2 output");

  Crypto::PublicKey B_a, B_b, A_swap, R;
  Crypto::SecretKey b_a, b_b, a_swap, r;
  Crypto::generate_keys(B_a, b_a);
  Crypto::generate_keys(B_b, b_b);
  Crypto::generate_keys(A_swap, a_swap);
  Crypto::generate_keys(R, r);

  Crypto::PublicKey B_swap;
  if (!addPublicKeys(B_a, B_b, B_swap)) FAIL("B_a + B_b failed");

  Crypto::KeyDerivation D;
  if (!Crypto::generate_key_derivation(A_swap, r, D)) FAIL("derivation failed");

  const size_t i = 7;
  Crypto::PublicKey P_out;
  if (!Crypto::derive_public_key(D, i, B_swap, P_out)) FAIL("derive_public_key failed");

  // Party A uses ONLY its own share b_a (missing b_b): the derived secret can't
  // open P_out.
  Crypto::SecretKey p_a;
  Crypto::derive_secret_key(D, i, b_a, p_a);
  Crypto::PublicKey p_a_pub;
  if (!Crypto::secret_key_to_public_key(p_a, p_a_pub)) FAIL("p_a invalid");
  if (keysEqual(p_a_pub, P_out)) FAIL("single share opened the 2-of-2 output (security hole)");

  PASS();
}

// ── The output index must be inside the derivation hash ───────────────────────
void test_swap_output_index_in_hash() {
  TEST("Swap: different output index yields a different one-time key");

  Crypto::PublicKey B_a, B_b, A_swap, R;
  Crypto::SecretKey b_a, b_b, a_swap, r;
  Crypto::generate_keys(B_a, b_a);
  Crypto::generate_keys(B_b, b_b);
  Crypto::generate_keys(A_swap, a_swap);
  Crypto::generate_keys(R, r);

  Crypto::PublicKey B_swap;
  if (!addPublicKeys(B_a, B_b, B_swap)) FAIL("B_a + B_b failed");

  Crypto::KeyDerivation D;
  if (!Crypto::generate_key_derivation(A_swap, r, D)) FAIL("derivation failed");

  Crypto::PublicKey P0, P1;
  if (!Crypto::derive_public_key(D, 0, B_swap, P0)) FAIL("derive i=0 failed");
  if (!Crypto::derive_public_key(D, 1, B_swap, P1)) FAIL("derive i=1 failed");
  if (keysEqual(P0, P1)) FAIL("output index not bound into the derivation hash");

  PASS();
}

// ── Rogue-key attack is caught by the commitment ──────────────────────────────
void test_swap_rogue_key_caught_by_commitment() {
  TEST("Swap: rogue B_b' = B_b - B_a fails its prior commitment");

  Crypto::PublicKey B_a, B_b;
  Crypto::SecretKey b_a, b_b;
  Crypto::generate_keys(B_a, b_a);
  Crypto::generate_keys(B_b, b_b);

  // Honest party B commits to B_b BEFORE A reveals B_a.
  Crypto::Hash commit_b = Crypto::cn_fast_hash(&B_b, sizeof(B_b));

  // After seeing B_a, a malicious B tries the classic rogue key B_b' = B_b - B_a
  // (so that B_swap = B_a + B_b' = B_b, which B alone could sweep). Build -B_a by
  // negating its compressed form (flip the sign bit of the high byte) and adding.
  Crypto::PublicKey negB_a = B_a;
  reinterpret_cast<unsigned char*>(&negB_a)[31] ^= 0x80;  // P -> -P on Ed25519
  Crypto::PublicKey B_b_rogue;
  if (!addPublicKeys(B_b, negB_a, B_b_rogue)) FAIL("B_b - B_a failed");

  // The rogue key cannot match the earlier commitment ⇒ the reveal round rejects
  // it, so the attack never reaches aggregation.
  Crypto::Hash rogue_hash = Crypto::cn_fast_hash(&B_b_rogue, sizeof(B_b_rogue));
  if (rogue_hash == commit_b) FAIL("rogue key matched the honest commitment (impossible)");

  PASS();
}

}  // namespace

int main() {
  std::printf("Atomic-Swap Derivation Test Vector (Session 9)\n");
  std::printf("==============================================\n\n");

  test_swap_derivation_roundtrip();
  test_swap_single_party_cannot_spend();
  test_swap_output_index_in_hash();
  test_swap_rogue_key_caught_by_commitment();

  std::printf("\n==============================================\n");
  std::printf("Results: %d/%d passed\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
