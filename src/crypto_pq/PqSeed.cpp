// Copyright (c) 2026, The Karbo developers
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

#include "PqSeed.h"

namespace CryptoPQ {

KemKeypairSeed deriveViewSeed(const SeedMaster& seedMaster) noexcept {
  // L=64 — see the spec-deviation note in PqSeed.h. Salt is 32 zero bytes
  // (the HKDF default fixed by spec §2).
  const uint8_t salt[32] = {0};
  KemKeypairSeed out{};
  // info is the domain string WITHOUT the trailing NUL.
  hkdf_sha3_256_explicit(seedMaster.data(), seedMaster.size(),
                         salt, sizeof(salt),
                         kDomainViewRoot, sizeof(kDomainViewRoot) - 1,
                         out.data(), out.size());
  return out;
}

std::pair<KemPublicKey, KemSecretKey> deriveViewKeys(const SeedMaster& seedMaster) {
  return kem_keygen_from_seed(deriveViewSeed(seedMaster));
}

SpendRoot deriveSpendRoot(const SeedMaster& seedMaster) noexcept {
  // L=32 (the HKDF default). Reserved for Phase 2.
  return hkdf_sha3_256(seedMaster.data(), seedMaster.size(),
                       kDomainSpendRoot, sizeof(kDomainSpendRoot) - 1);
}

}  // namespace CryptoPQ
