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

#include <cstdint>
#include <string>

// Human-readable PQ account number (H-I-C), spec §11.4. WALLET/UX layer only —
// consensus stores just the (block_height, tx_index) pair in pq_acct_reg.
// Format: "<height>-<txIndex>-<CCC>" where CCC is a 3-char base36 checksum =
// first 3 base36 chars of SHA3-256(LE64(height) || LE32(txIndex)). Example:
// "1234567-42-A7B". The checksum guards against typos, not adversaries.

namespace CryptoPQ {

std::string renderAccountNumber(uint64_t height, uint32_t txIndex);

// Parse + verify the checksum. Returns false on malformed input or a checksum
// mismatch.
bool parseAccountNumber(const std::string& hic, uint64_t& height, uint32_t& txIndex);

}  // namespace CryptoPQ
