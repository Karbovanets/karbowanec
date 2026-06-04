// PoC / regression test for the Route 1 key-image binding fix.
//
// Before the fix: a holder could emit a SECOND distinct VALID key image for
// the same output (linking tag unbound) -> confidential double-spend.
//
// After the fix (J = x·U, linking track reuses f_P): the forged signer below
// builds a complete, otherwise-honest proof but sets the key image to J = c·U
// for an attacker-chosen c != x (keeping the real spend key x in f_P, the real
// blinding z in f_M, and honest Q_J = ρ_P·U). The verifier MUST reject, because
// the linking equation x^n·J = f_P·U + Σ x^m·Q_J[m] forces J = x·U.
//
// Pass criterion: honest verify ACCEPTS; every forged c != x is REJECTED by
// BOTH triptych_verify and triptych_verify_batch.

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

namespace forge {

static size_t log2_ring(size_t r) { return r==4?2:r==8?3:r==16?4:0; }
static void random_scalar(EllipticCurveScalar& res) {
  unsigned char tmp[64]; Random::randomBytes(64, tmp); sc_reduce(tmp); std::memcpy(&res, tmp, 32);
}
static void p3b(unsigned char o[32], const ge_p3* p){ ge_p3_tobytes(o,p); }
static bool p2_to_p3(ge_p3* o, const ge_p2* i){ unsigned char b[32]; ge_tobytes(b,i); return ge_frombytes_vartime(o,b)==0; }
static void padd(ge_p3* o, const ge_p3* a, const ge_p3* b){ ge_cached c; ge_p3_to_cached(&c,b); ge_p1p1 r; ge_add(&r,a,&c); ge_p1p1_to_p3(o,&r); }
static bool smul(ge_p3* o, const unsigned char s[32], const ge_p3* P){ ge_p2 r; ge_scalarmult(&r,s,P); return p2_to_p3(o,&r); }

// Must match triptych.cpp's compute_U() exactly.
static EllipticCurvePoint compute_U() {
  static const char domain[] = "Karbo-CT-keyimage-generator-v1";
  Hash h; ge_p2 point; ge_p1p1 point2; EllipticCurvePoint result;
  cn_fast_hash(domain, sizeof(domain) - 1, h);
  ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char*>(&h));
  ge_mul8(&point2, &point); ge_p1p1_to_p2(&point, &point2);
  ge_tobytes(reinterpret_cast<unsigned char*>(&result), &point);
  return result;
}

// Must match triptych.cpp's compute_challenge() exactly (domain v2, Q_J).
static void compute_challenge(
  const Hash& message, size_t ring_size, size_t n,
  const PublicKey rp[], const EllipticCurvePoint rc[],
  const EllipticCurvePoint& pseudo, const KeyImage& ki,
  const ge_p3* Ib, const ge_p3* A, const ge_p3* B,
  const ge_p3* QP, const ge_p3* QM, const ge_p3* QJ, EllipticCurveScalar& ch) {
  static const char domain[] = "Triptych-KarboCT-v2";
  const size_t dl = sizeof(domain)-1;
  const size_t bs = dl + 32 + 1 + 32*ring_size*2 + 32 + 32 + 32*n*6;
  std::vector<unsigned char> buf(bs); unsigned char* p = buf.data();
  std::memcpy(p,domain,dl); p+=dl;
  std::memcpy(p,&message,32); p+=32;
  *p++ = (unsigned char)ring_size;
  for (size_t k=0;k<ring_size;++k){ std::memcpy(p,&rp[k],32); p+=32; }
  for (size_t k=0;k<ring_size;++k){ std::memcpy(p,&rc[k],32); p+=32; }
  std::memcpy(p,&pseudo,32); p+=32;
  std::memcpy(p,&ki,32); p+=32;
  for (size_t j=0;j<n;++j){ p3b(p,&Ib[j]); p+=32; }
  for (size_t j=0;j<n;++j){ p3b(p,&A[j]); p+=32; }
  for (size_t j=0;j<n;++j){ p3b(p,&B[j]); p+=32; }
  for (size_t m=0;m<n;++m){ p3b(p,&QP[m]); p+=32; }
  for (size_t m=0;m<n;++m){ p3b(p,&QM[m]); p+=32; }
  for (size_t m=0;m<n;++m){ p3b(p,&QJ[m]); p+=32; }
  cn_fast_hash(buf.data(), bs, reinterpret_cast<Hash&>(ch)); sc_reduce32(ch.data);
}

static void poly_coeffs(size_t rs, size_t n, const int bits[], const EllipticCurveScalar a[],
                        std::vector<std::vector<EllipticCurveScalar>>& pc) {
  unsigned char zero[32]; sc_0(zero);
  pc.assign(rs, std::vector<EllipticCurveScalar>(n+1));
  for (size_t k=0;k<rs;++k){
    std::vector<std::array<unsigned char,32>> poly(n+1); for(auto&c:poly) std::memset(c.data(),0,32);
    poly[0][0]=1; size_t cd=0;
    for (size_t j=0;j<n;++j){
      int kj=(k>>j)&1, lj=bits[j]; unsigned char fc[32],fl[32];
      if(kj==1){ std::memcpy(fc,a[j].data,32); std::memset(fl,0,32); if(lj)fl[0]=1; }
      else { sc_sub(fc,zero,a[j].data); std::memset(fl,0,32); if(!lj)fl[0]=1; }
      std::vector<std::array<unsigned char,32>> np(n+1); for(auto&c:np) std::memset(c.data(),0,32);
      for(size_t i=0;i<=cd+1;++i){ unsigned char t1[32],t2[32]; sc_mul(t1,fc,poly[i].data());
        if(i>0){ sc_mul(t2,fl,poly[i-1].data()); sc_add(np[i].data(),t1,t2);} else std::memcpy(np[i].data(),t1,32); }
      cd++; poly=std::move(np);
    }
    for(size_t i=0;i<=n;++i) std::memcpy(pc[k][i].data, poly[i].data(),32);
  }
}

// Honest new prover, except the key image is J = image_scalar·U (set
// image_scalar = real x for the honest control, c != x for the forge).
// f_P keeps the REAL spend key; Q_J = ρ_P·U honest.
static bool sign_with_image(
  const Hash& msg, const PublicKey rp[], const EllipticCurvePoint rc[],
  const EllipticCurvePoint& pseudo, size_t rs, size_t idx,
  const SecretKey& x, const EllipticCurveScalar& r_real, const EllipticCurveScalar& r_pseudo,
  const EllipticCurveScalar& image_scalar, KeyImage& ki, TriptychSignature& sig) {
  size_t n = log2_ring(rs);
  EllipticCurvePoint U = compute_U();
  ge_p3 U_p3; if (ge_frombytes_vartime(&U_p3, reinterpret_cast<const unsigned char*>(&U))!=0) return false;
  { ge_p2 j; ge_scalarmult(&j, reinterpret_cast<const unsigned char*>(&image_scalar), &U_p3);
    ge_tobytes(reinterpret_cast<unsigned char*>(&ki), &j); }

  EllipticCurveScalar z; sc_sub(reinterpret_cast<unsigned char*>(&z),
    reinterpret_cast<const unsigned char*>(&r_real), reinterpret_cast<const unsigned char*>(&r_pseudo));

  ge_p3 pseudo_p3; if (ge_frombytes_vartime(&pseudo_p3, reinterpret_cast<const unsigned char*>(&pseudo))!=0) return false;
  ge_cached pc_cached; ge_p3_to_cached(&pc_cached,&pseudo_p3);
  std::vector<ge_p3> P(rs), M(rs);
  for (size_t k=0;k<rs;++k){
    if (ge_frombytes_vartime(&P[k], reinterpret_cast<const unsigned char*>(&rp[k]))!=0) return false;
    ge_p3 C; if (ge_frombytes_vartime(&C, reinterpret_cast<const unsigned char*>(&rc[k]))!=0) return false;
    ge_p1p1 d; ge_sub(&d,&C,&pc_cached); ge_p1p1_to_p3(&M[k],&d);
  }
  sig.I_bits.resize(n); sig.A.resize(n); sig.B.resize(n);
  sig.Q_P.resize(n); sig.Q_M.resize(n); sig.Q_J.resize(n);
  sig.z.resize(n); sig.za.resize(n); sig.zb.resize(n);
  std::vector<int> bits(n); for(size_t j=0;j<n;++j) bits[j]=(idx>>j)&1;
  std::vector<EllipticCurveScalar> rj(n),aj(n),sj(n),tj(n);
  for(size_t j=0;j<n;++j){ random_scalar(rj[j]); random_scalar(aj[j]); random_scalar(sj[j]); random_scalar(tj[j]); }
  ge_p3 H_p3; if (ge_frombytes_vartime(&H_p3, reinterpret_cast<const unsigned char*>(&pedersen_get_H()))!=0) return false;
  std::vector<ge_p3> Ib(n),Ap(n),Bp(n);
  for(size_t j=0;j<n;++j){
    ge_p3 rG; ge_scalarmult_base(&rG,rj[j].data); if(bits[j]) padd(&Ib[j],&rG,&H_p3); else Ib[j]=rG;
    ge_p3 sG,aH; ge_scalarmult_base(&sG,sj[j].data); if(!smul(&aH,aj[j].data,&H_p3)) return false; padd(&Ap[j],&sG,&aH);
    ge_p3 tG; ge_scalarmult_base(&tG,tj[j].data); if(bits[j]) padd(&Bp[j],&tG,&aH); else Bp[j]=tG;
  }
  std::vector<std::vector<EllipticCurveScalar>> pc; poly_coeffs(rs,n,bits.data(),aj.data(),pc);
  std::vector<EllipticCurveScalar> rho_P(n),rho_M(n);
  std::vector<ge_p3> QP(n),QM(n),QJ(n);
  for(size_t m=0;m<n;++m){
    random_scalar(rho_P[m]); random_scalar(rho_M[m]);
    ge_p3 sP,sM; ge_scalarmult_base(&sP,rho_P[m].data); ge_scalarmult_base(&sM,rho_M[m].data);
    for(size_t k=0;k<rs;++k){ const unsigned char* co=pc[k][m].data; if(!sc_isnonzero(co)) continue;
      ge_p3 tP,tM; if(!smul(&tP,co,&P[k])) return false; if(!smul(&tM,co,&M[k])) return false;
      padd(&sP,&sP,&tP); padd(&sM,&sM,&tM); }
    QP[m]=sP; QM[m]=sM;
    if(!smul(&QJ[m], rho_P[m].data, &U_p3)) return false;   // Q_J = ρ_P·U (honest)
  }
  EllipticCurveScalar ch;
  compute_challenge(msg,rs,n,rp,rc,pseudo,ki,Ib.data(),Ap.data(),Bp.data(),QP.data(),QM.data(),QJ.data(),ch);
  for(size_t j=0;j<n;++j){
    if(bits[j]) sc_add(sig.z[j].data,ch.data,aj[j].data); else std::memcpy(sig.z[j].data,aj[j].data,32);
    unsigned char tm[32]; sc_mul(tm,rj[j].data,ch.data); sc_add(sig.za[j].data,tm,sj[j].data);
    unsigned char xmz[32]; sc_sub(xmz,ch.data,sig.z[j].data); sc_mul(tm,rj[j].data,xmz); sc_add(sig.zb[j].data,tm,tj[j].data);
  }
  unsigned char xp[5][32]; std::memset(xp[0],0,32); xp[0][0]=1; std::memcpy(xp[1],ch.data,32);
  for(size_t i=2;i<=n;++i) sc_mul(xp[i],xp[i-1],ch.data);
  sc_mul(sig.f_P.data, reinterpret_cast<const unsigned char*>(&x), xp[n]);   // REAL x
  sc_mul(sig.f_M.data, z.data, xp[n]);
  for(size_t m=0;m<n;++m){ unsigned char tm[32];
    sc_mul(tm,rho_P[m].data,xp[m]); sc_sub(sig.f_P.data,sig.f_P.data,tm);
    sc_mul(tm,rho_M[m].data,xp[m]); sc_sub(sig.f_M.data,sig.f_M.data,tm); }
  for(size_t j=0;j<n;++j){
    p3b(reinterpret_cast<unsigned char*>(&sig.I_bits[j]),&Ib[j]);
    p3b(reinterpret_cast<unsigned char*>(&sig.A[j]),&Ap[j]);
    p3b(reinterpret_cast<unsigned char*>(&sig.B[j]),&Bp[j]);
    p3b(reinterpret_cast<unsigned char*>(&sig.Q_P[j]),&QP[j]);
    p3b(reinterpret_cast<unsigned char*>(&sig.Q_M[j]),&QM[j]);
    p3b(reinterpret_cast<unsigned char*>(&sig.Q_J[j]),&QJ[j]);
  }
  return true;
}
} // namespace forge

static void gen_keypair(PublicKey& pub, SecretKey& sec){
  unsigned char t[64]; Random::randomBytes(64,t); sc_reduce(t); std::memcpy(&sec,t,32);
  ge_p3 p; ge_scalarmult_base(&p, reinterpret_cast<const unsigned char*>(&sec));
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&pub),&p);
}
static void u64s(uint64_t v, EllipticCurveScalar& s){ std::memset(s.data,0,32); for(int i=0;i<8;++i) s.data[i]=(unsigned char)(v>>(8*i)); }

static bool verify_both(const Hash& msg, const PublicKey* pub, const EllipticCurvePoint* com,
                        const EllipticCurvePoint& pseudo, size_t N, const KeyImage& ki, const TriptychSignature& sig) {
  bool a = triptych_verify(msg, pub, com, pseudo, N, ki, sig);
  const PublicKey* rp[1]={pub}; const EllipticCurvePoint* rc[1]={com};
  EllipticCurvePoint pc[1]={pseudo}; size_t rs[1]={N}; KeyImage k[1]={ki}; TriptychSignature s[1]={sig};
  bool b = triptych_verify_batch(msg, rp, rc, pc, rs, k, s, 1);
  return a && b;
}

int main(){
  const size_t N=8, idx=3; const uint64_t amount=1000;
  std::vector<PublicKey> pub(N); std::vector<EllipticCurvePoint> com(N);
  SecretKey x; EllipticCurveScalar rr, rp, vsc; u64s(amount,vsc);
  gen_keypair(pub[idx], x);
  unsigned char t[64]; Random::randomBytes(64,t); sc_reduce(t); std::memcpy(&rr,t,32);
  pedersen_commit(vsc, rr, com[idx]);
  for(size_t i=0;i<N;++i){ if(i==idx) continue; SecretKey d; gen_keypair(pub[i],d);
    EllipticCurveScalar dr,dv; Random::randomBytes(64,t); sc_reduce(t); std::memcpy(&dr,t,32);
    Random::randomBytes(64,t); sc_reduce(t); std::memcpy(&dv,t,32); pedersen_commit(dv,dr,com[i]); }
  EllipticCurvePoint pseudo; Random::randomBytes(64,t); sc_reduce(t); std::memcpy(&rp,t,32);
  pedersen_commit(vsc, rp, pseudo);
  Hash msg; Random::randomBytes(32, msg.data);

  // Control: honest image J = x·U via the REAL library prover.
  KeyImage ki_h; TriptychSignature sig_h;
  if(!triptych_sign(msg, pub.data(), com.data(), pseudo, N, idx, x, rr, rp, ki_h, sig_h)){ printf("honest sign failed\n"); return 2; }
  bool honest_ok = verify_both(msg, pub.data(), com.data(), pseudo, N, ki_h, sig_h);
  printf("honest verify (per-input + batch): %s\n", honest_ok ? "ACCEPTED" : "REJECTED");

  // Forge attempts: J = c·U for several c != x, full fresh proof, honest f_P/Q_J.
  int forged_accepted = 0, tried = 0;
  for (int trial = 0; trial < 8; ++trial) {
    EllipticCurveScalar c; Random::randomBytes(64,t); sc_reduce(t); std::memcpy(&c,t,32);
    if (std::memcmp(&c, &x, 32) == 0) continue;
    KeyImage ki_f; TriptychSignature sig_f;
    if(!forge::sign_with_image(msg, pub.data(), com.data(), pseudo, N, idx, x, rr, rp, c, ki_f, sig_f)){ printf("forge sign failed\n"); return 2; }
    bool diff = std::memcmp(&ki_h, &ki_f, 32) != 0;
    bool ok = verify_both(msg, pub.data(), com.data(), pseudo, N, ki_f, sig_f);
    ++tried;
    if (ok && diff) ++forged_accepted;
  }
  printf("forge attempts: %d, accepted-and-distinct: %d\n", tried, forged_accepted);

  if (honest_ok && forged_accepted == 0) {
    printf("\nFIXED: honest image accepts; every forged c != x rejected (key image bound to x).\n");
    return 0;
  }
  printf("\nFAILURE: %s\n", !honest_ok ? "honest proof rejected" : "a forged key image was accepted (still VULNERABLE)");
  return 1;
}
