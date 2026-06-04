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

#pragma once

#include <array>
#include <cstdint>
#include <utility>

#include "PqHash.h"
#include "PqKem.h"

// Wallet seed -> view-key derivation chain for the Karbo PQ transaction family
// (spec §4). This is a CEMENTED v4 surface: recovery from a seed must always
// produce the same view keypair, so the derivation never changes.
//
//   seed_master  (32 bytes, BIP39 or CSPRNG)
//   view_seed    = HKDF-SHA3-256(seed_master, salt=0, info="karbo-pq-view-root-v1", L=64)
//   (view_pub, view_sk) = ML-KEM-768.KeyGen(seed = view_seed)
//   spend_root   = HKDF-SHA3-256(seed_master, salt=0, info="karbo-pq-spend-root-v1", L=32)
//                  // reserved; UNUSED in Phase 1
//
// SPEC DEVIATION (decided 2026-06-04): the spec text derives view_seed at L=32,
// but FIPS 203 ML-KEM.KeyGen consumes 64 bytes of randomness (d || z). The spec
// is under-specified on the 32->64 bridge. We resolve it by deriving view_seed
// directly at L=64 and feeding all 64 bytes to KeyGen — one derivation, no extra
// domain string. This is the cemented behaviour for v4.

namespace CryptoPQ {

constexpr char kDomainViewRoot[]  = "karbo-pq-view-root-v1";
constexpr char kDomainSpendRoot[] = "karbo-pq-spend-root-v1";

using SeedMaster = std::array<uint8_t, 32>;
using SpendRoot  = Hash256;  // 32 bytes, reserved

// view_seed: the 64-byte ML-KEM keypair seed (see deviation note above).
KemKeypairSeed deriveViewSeed(const SeedMaster& seedMaster) noexcept;

// Full view keypair derived deterministically from the master seed.
std::pair<KemPublicKey, KemSecretKey> deriveViewKeys(const SeedMaster& seedMaster);

// spend_root — derived and exposed for forward compatibility; NOT used by any
// Phase 1 validation or wallet path.
SpendRoot deriveSpendRoot(const SeedMaster& seedMaster) noexcept;

}  // namespace CryptoPQ
