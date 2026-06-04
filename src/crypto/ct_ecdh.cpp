// Copyright (c) 2024-2026, The Karbo developers
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

#include <cassert>
#include <cstring>

#include "Common/Varint.h"
#include "ct_ecdh.h"
#include "crypto.h"
#include "crypto-ops.h"
#include "hash.h"
#include "pedersen.h"

namespace Crypto {

  void ct_ecdh_init() {
    // No-op: kept for API compatibility. The active CT Pedersen generator is
    // provided by pedersen_get_H() in pedersen.cpp.
  }

  // Internal helper: derive a domain-separated scalar from the shared secret,
  // varint(output_index), and a fixed ASCII domain tag.
  //
  // The domain tag is essential: without it, this function would produce the
  // same scalar as derivation_to_scalar(D, i) in crypto.cpp (which the stealth
  // address uses for P_i = derivation_to_scalar(D, i)*G + B_spend). Any passive
  // observer who knows the recipient's public address B_spend could then
  // compute r*G = P_i - B_spend and recover v from C_i = v*H + r*G by brute
  // force over the 64 canonical denominations, completely defeating CT amount
  // confidentiality.
  static void shared_secret_to_scalar(const KeyDerivation& shared_secret,
                                      size_t index,
                                      const char* domain, size_t domain_len,
                                      EllipticCurveScalar& res) {
    // sizeof(KeyDerivation) + max varint encoding of size_t + domain bytes.
    // 14 bytes is enough headroom for any domain string we use.
    static const size_t kMaxDomainLen = 32;
    assert(domain_len <= kMaxDomainLen);
    unsigned char buf[sizeof(KeyDerivation) + ((sizeof(size_t) * 8 + 6) / 7) + kMaxDomainLen];
    unsigned char* ptr = buf;
    memcpy(ptr, &shared_secret, sizeof(shared_secret));
    ptr += sizeof(shared_secret);
    char* varintBegin = reinterpret_cast<char*>(ptr);
    char* varintEnd = varintBegin;
    Tools::write_varint(varintEnd, index);
    ptr += (varintEnd - varintBegin);
    memcpy(ptr, domain, domain_len);
    ptr += domain_len;
    assert(ptr <= buf + sizeof(buf));
    hash_to_scalar(buf, ptr - buf, res);
  }

  void derive_blinding_factor(const KeyDerivation& shared_secret, size_t output_index,
                              EllipticCurveScalar& blinding_factor) {
    // r = Hs(shared_secret || varint(output_index) || "ct-blinding-v1")
    //
    // The domain tag is CRITICAL: it separates this scalar from the stealth
    // address derivation scalar used in derivation_to_scalar(). Without it,
    // r equals the value of s in P = s*G + B_spend, which allows a passive
    // observer who knows B_spend to recover the amount v from the public
    // commitment C = v*H + r*G.
    static const char domain[] = "ct-blinding-v1";
    shared_secret_to_scalar(shared_secret, output_index,
                            domain, sizeof(domain) - 1, blinding_factor);
  }

  bool pedersen_commit(uint64_t amount, const EllipticCurveScalar& blinding_factor,
                       PublicKey& commitment) {
    EllipticCurveScalar amount_scalar;
    memset(amount_scalar.data, 0, sizeof(amount_scalar.data));
    for (int i = 0; i < 8; ++i) {
      amount_scalar.data[i] = static_cast<unsigned char>((amount >> (8 * i)) & 0xFF);
    }

    EllipticCurvePoint commitment_point;
    if (!Crypto::pedersen_commit(amount_scalar, blinding_factor, commitment_point)) {
      return false;
    }

    static_assert(sizeof(commitment) == sizeof(commitment_point), "Point/PublicKey size mismatch");
    memcpy(&commitment, &commitment_point, sizeof(commitment));
    return true;
  }

  // Internal: compute the 8-byte amount mask from shared secret and output index.
  // mask = Hs(shared_secret || output_index || "amount-mask-v1")[0..7]
  static void compute_amount_mask(const KeyDerivation& shared_secret, size_t output_index, uint8_t mask[8]) {
    EllipticCurveScalar scalar;
    unsigned char buf[sizeof(KeyDerivation) + ((sizeof(size_t) * 8 + 6) / 7) + 14];
    unsigned char* ptr = buf;
    memcpy(ptr, &shared_secret, sizeof(shared_secret));
    ptr += sizeof(shared_secret);
    char* varintBegin = reinterpret_cast<char*>(ptr);
    char* end = varintBegin;
    Tools::write_varint(end, output_index);
    ptr += (end - varintBegin);
    static const char amountDomain[] = "amount-mask-v1";
    memcpy(ptr, amountDomain, sizeof(amountDomain) - 1);
    ptr += sizeof(amountDomain) - 1;
    hash_to_scalar(buf, ptr - buf, scalar);
    memcpy(mask, scalar.data, 8);
  }

  void mask_amount(const KeyDerivation& shared_secret, size_t output_index, uint64_t amount,
                   MaskedAmount& masked) {
    // Encode amount as little-endian uint64
    uint8_t amount_le[8];
    for (int i = 0; i < 8; i++) {
      amount_le[i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);
    }

    // Compute mask and XOR
    uint8_t mask[8];
    compute_amount_mask(shared_secret, output_index, mask);
    for (int i = 0; i < 8; i++) {
      masked.data[i] = amount_le[i] ^ mask[i];
    }
  }

  uint64_t unmask_amount(const KeyDerivation& shared_secret, size_t output_index,
                         const MaskedAmount& masked) {
    // Compute mask and XOR to recover amount
    uint8_t mask[8];
    compute_amount_mask(shared_secret, output_index, mask);

    uint8_t amount_le[8];
    for (int i = 0; i < 8; i++) {
      amount_le[i] = masked.data[i] ^ mask[i];
    }

    // Decode little-endian uint64
    uint64_t amount = 0;
    for (int i = 0; i < 8; i++) {
      amount |= static_cast<uint64_t>(amount_le[i]) << (8 * i);
    }
    return amount;
  }

  bool decrypt_and_verify_output(const SecretKey& view_secret_key,
                                 const PublicKey& tx_public_key,
                                 size_t output_index,
                                 const MaskedAmount& masked,
                                 const PublicKey& commitment,
                                 uint64_t& amount_out,
                                 EllipticCurveScalar& blinding_factor_out) {
    // Step 1: Re-derive shared secret = key_derivation(R, a) = 8*a*R
    KeyDerivation shared_secret;
    if (!generate_key_derivation(tx_public_key, view_secret_key, shared_secret)) {
      return false;
    }

    // Step 2: Unmask amount
    amount_out = unmask_amount(shared_secret, output_index, masked);

    // Step 3: Re-derive blinding factor
    derive_blinding_factor(shared_secret, output_index, blinding_factor_out);

    // Step 4: Recompute commitment and verify
    PublicKey expected_commitment;
    if (!pedersen_commit(amount_out, blinding_factor_out, expected_commitment)) {
      return false;
    }

    // Constant-time comparison
    return sodium_compare(commitment.data, expected_commitment.data, 32) == 0;
  }

} // namespace Crypto
