// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

// Historical note: this file used to do `#include "crypto/crypto.cpp"` to
// amalgamate the production crypto implementation directly into the test
// binary. That was needed when the test harness wanted access to file-local
// helpers, but every symbol it actually uses is now exported through the
// Crypto library. Link against Crypto + Common in tests/CMakeLists.txt
// instead — the amalgamation just causes duplicate-symbol issues once you
// pull in the libsodium and crypto-util dependencies properly.

#include <cstring>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/random.h"

extern "C" {
#include "crypto/crypto-ops.h"
}

#include "crypto-tests.h"

bool check_scalar(const Crypto::EllipticCurveScalar &scalar) {
  // sc_check is a C helper from crypto-ops.h (extern "C"), not in the Crypto namespace.
  return sc_check(reinterpret_cast<const unsigned char*>(&scalar)) == 0;
}

// Crypto::random_scalar is a file-local helper in crypto.cpp; not visible
// without amalgamation. The test harness in main.cpp no longer invokes this
// shim (the `random_scalar` and `generate_keys` command kinds are skipped —
// see the CSPRNG-hardening note there). We keep the shim for ABI stability
// against crypto-tests.h's forward declaration, but reimplement it inline
// against the public Random:: API so it remains buildable and would Do The
// Right Thing if a future test path called it. Output is non-deterministic
// by design.
void random_scalar(Crypto::EllipticCurveScalar &res) {
  unsigned char tmp[64];
  Random::randomBytes(64, tmp);
  sc_reduce(tmp);
  std::memcpy(&res, tmp, 32);
}

void hash_to_scalar(const void *data, size_t length, Crypto::EllipticCurveScalar &res) {
  Crypto::hash_to_scalar(data, length, res);
}

// ge_* types and functions are declared in crypto-ops.h as plain C, not in
// the Crypto C++ namespace — the old `Crypto::ge_p2` references compiled
// before the codebase tightened that boundary. Use the unqualified C names
// directly.
void hash_to_point(const Crypto::Hash &h, Crypto::EllipticCurvePoint &res) {
  ge_p2 point;
  ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char *>(&h));
  ge_tobytes(reinterpret_cast<unsigned char*>(&res), &point);
}

// hash_to_ec was a `static` helper in crypto.cpp, so it's not visible once
// we stop amalgamating that translation unit. The construction is small
// enough (hash → ge_fromfe → mul8 to clear cofactor → serialize) that
// reimplementing it inline here keeps the test independent of production
// internals while exercising the same byte-level algorithm.
void hash_to_ec(const Crypto::PublicKey &key, Crypto::EllipticCurvePoint &res) {
  Crypto::Hash h;
  ge_p2 point;
  ge_p1p1 point2;
  ge_p3 tmp;
  Crypto::cn_fast_hash(std::addressof(key), sizeof(Crypto::PublicKey), h);
  ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char *>(&h));
  ge_mul8(&point2, &point);
  ge_p1p1_to_p3(&tmp, &point2);
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&res), &tmp);
}
