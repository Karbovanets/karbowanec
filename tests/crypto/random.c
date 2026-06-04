// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
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

// Historical note: this file used to do
//     #include "crypto/random.c"
//     void setup_random(void) { memset(&state, 42, sizeof(union hash_state)); }
// to reseed the legacy Keccak-state PRNG to a known value so the test
// harness in main.cpp could verify recorded vectors from tests.txt for
// commands like `random_scalar` and `generate_keys`. The legacy
// crypto/random.c was retired when the codebase moved to a non-seedable
// OS-CSPRNG-backed implementation (src/crypto/random.h::Random::randomBytes,
// which calls secure_random_bytes → BCryptGenRandom / getrandom /
// arc4random_buf). That switch was a deliberate security hardening — see
// the comment block at the top of crypto/random.h — and it intentionally
// removes the ability to reset the PRNG to a known state.
//
// As a consequence, the `random_scalar` and `generate_keys` commands in
// tests.txt no longer have a way to match their recorded values. The
// harness in main.cpp now skips those two command kinds (with a one-shot
// log line) so the rest of the deterministic test vectors continue to
// run. setup_random() is kept as a no-op so the linkage in
// crypto-tests.h still resolves and main.cpp's call site needs no change.
//
// Reintroducing the deterministic random-output assertions would require
// adding a test-only override seam into the production Random::randomBytes
// path. That trade-off (test fidelity vs. one more #ifdef-guarded hook in
// consensus-critical code) wasn't worth the cost when CSPRNG-hardening
// landed; this comment preserves the rationale.

void setup_random(void) {
  // Intentionally empty. The OS CSPRNG cannot be reseeded.
}
