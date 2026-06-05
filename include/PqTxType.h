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

// PQ transaction sub-types (spec §1.2). These live INSIDE the PQ transaction
// version (TRANSACTION_VERSION_PQ) as an inner txType byte — they do NOT consume
// top-level transaction versions. A plain (v1) transaction has no txType.
//
//   TX_PQ       — PQ inputs -> PQ outputs (the normal confidential-of-traces send)
//   TX_BRIDGE   — classical inputs -> PQ outputs (one-way legacy migration)
//   TX_FREE_REG — zero-fee account-number registration (no inputs/outputs)

namespace CryptoNote {

enum PqTxType : uint8_t {
  TX_PQ       = 0x01,
  TX_BRIDGE   = 0x02,
  TX_FREE_REG = 0x03,
};

}  // namespace CryptoNote
