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

#include "PqAccountNumber.h"

#include <array>
#include <cstdint>

#include "PqHash.h"

namespace CryptoPQ {

namespace {

const char* kBase36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// 3 base36 chars (46656 values) from the leading hash bytes.
std::string checksum3(uint64_t height, uint32_t txIndex) {
  std::array<uint8_t, 12> buf{};
  for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>((height >> (8 * i)) & 0xFF);
  for (int i = 0; i < 4; ++i) buf[8 + i] = static_cast<uint8_t>((txIndex >> (8 * i)) & 0xFF);
  Hash256 h = sha3_256(buf.data(), buf.size());
  uint32_t v = (static_cast<uint32_t>(h[0]) << 16) |
               (static_cast<uint32_t>(h[1]) << 8) |
                static_cast<uint32_t>(h[2]);
  v %= 36u * 36u * 36u;
  std::string out(3, '0');
  for (int i = 2; i >= 0; --i) { out[i] = kBase36[v % 36]; v /= 36; }
  return out;
}

bool parseUint(const std::string& s, uint64_t& out) {
  if (s.empty() || s.size() > 20) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<uint64_t>(c - '0');
  }
  out = v;
  return true;
}

}  // namespace

std::string renderAccountNumber(uint64_t height, uint32_t txIndex) {
  return std::to_string(height) + "-" + std::to_string(txIndex) + "-" +
         checksum3(height, txIndex);
}

bool parseAccountNumber(const std::string& hic, uint64_t& height, uint32_t& txIndex) {
  std::size_t d1 = hic.find('-');
  if (d1 == std::string::npos) return false;
  std::size_t d2 = hic.find('-', d1 + 1);
  if (d2 == std::string::npos) return false;

  uint64_t h = 0, t = 0;
  if (!parseUint(hic.substr(0, d1), h)) return false;
  if (!parseUint(hic.substr(d1 + 1, d2 - d1 - 1), t)) return false;
  if (t > 0xFFFFFFFFull) return false;
  std::string cks = hic.substr(d2 + 1);
  if (cks.size() != 3) return false;

  if (checksum3(h, static_cast<uint32_t>(t)) != cks) return false;
  height = h;
  txIndex = static_cast<uint32_t>(t);
  return true;
}

}  // namespace CryptoPQ
