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

#include "PqRandom.h"

#include <cstdint>

extern "C" {
#include <oqs/rand.h>
}

namespace CryptoPQ {

void secure_random_bytes(void* out, std::size_t len) {
  // liboqs defaults to the platform CSPRNG (getrandom / BCryptGenRandom).
  OQS_randombytes(static_cast<uint8_t*>(out), len);
}

}  // namespace CryptoPQ
