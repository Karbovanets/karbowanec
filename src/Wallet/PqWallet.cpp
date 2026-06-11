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

#include "PqWallet.h"

#include <algorithm>
#include <cctype>

#include "crypto_pq/PqHash.h"

namespace CryptoNote {

namespace {
// Any PQ address (base58 ~4300 chars, bech32m ~5000) is vastly longer than a
// classical Karbo address (~98, ~187 with payment id). This length floor cheaply
// rejects classical strings before any decode work; it sits comfortably below
// the shortest real PQ address.
constexpr std::size_t kMinPqAddressChars = 300;
}  // namespace

CryptoPQ::SeedMaster pqSeedMasterFromSpendSecret(const Crypto::SecretKey& spendSecretKey) noexcept {
  // HKDF default instantiation (salt = 0x00*32, L = 32). The classical 32-byte
  // spend scalar is the IKM; the domain string isolates the PQ master seed from
  // any other use of the spend key.
  CryptoPQ::Hash256 okm = CryptoPQ::hkdf_sha3_256(
      spendSecretKey.data, sizeof(spendSecretKey.data),
      kPqWalletSeedDomain, sizeof(kPqWalletSeedDomain) - 1);
  CryptoPQ::SeedMaster seed{};
  std::copy(okm.begin(), okm.end(), seed.begin());
  return seed;
}

PqWalletKeys derivePqWalletKeys(const Crypto::SecretKey& spendSecretKey) {
  PqWalletKeys keys;
  keys.seedMaster = pqSeedMasterFromSpendSecret(spendSecretKey);

  auto view = CryptoPQ::deriveViewKeys(keys.seedMaster);
  keys.viewPub = view.first;
  keys.viewSk  = view.second;

  auto spend = CryptoPQ::deriveSpendKeys(keys.seedMaster);
  keys.spendPub = spend.first;
  keys.spendSk  = spend.second;

  return keys;
}

PqAddress pqWalletAddress(const PqWalletKeys& keys, uint64_t networkPrefix) {
  return makePqAddress(networkPrefix, keys.viewPub, keys.spendPub);
}

PqAddress pqWalletAddress(const Crypto::SecretKey& spendSecretKey, uint64_t networkPrefix) {
  return pqWalletAddress(derivePqWalletKeys(spendSecretKey), networkPrefix);
}

CryptoPQ::PqScanKeys pqScanKeys(const PqWalletKeys& keys) {
  return CryptoPQ::PqScanKeys{ keys.viewSk, keys.spendPub };
}

bool isPqAddressString(const std::string& s) {
  if (s.size() < kMinPqAddressChars) {
    return false;
  }
  PqAddress out;
  return parsePqAddress(s, out, nullptr);
}

namespace {
// First `n` base36 chars (uppercase) of a 32-byte hash, big-endian.
std::string hashToBase36(const CryptoPQ::Hash256& h, size_t n) {
  static const char* kDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  // Accumulate from the leading bytes; we only need a few digits.
  uint64_t acc = 0;
  for (size_t i = 0; i < 8; ++i) acc = (acc << 8) | h[i];
  std::string out;
  for (size_t i = 0; i < n; ++i) {
    out.push_back(kDigits[acc % 36]);
    acc /= 36;
  }
  std::reverse(out.begin(), out.end());
  return out;
}

std::string accountChecksum(uint32_t height, uint32_t txIndex) {
  uint8_t buf[12];
  for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>((static_cast<uint64_t>(height) >> (8 * i)) & 0xFF);
  for (int i = 0; i < 4; ++i) buf[8 + i] = static_cast<uint8_t>((txIndex >> (8 * i)) & 0xFF);
  CryptoPQ::Hash256 h = CryptoPQ::sha3_256(buf, sizeof(buf));
  return hashToBase36(h, 3);
}
}  // namespace

std::string pqAccountNumber(uint32_t height, uint32_t txIndex) {
  return std::to_string(height) + "-" + std::to_string(txIndex) + "-" + accountChecksum(height, txIndex);
}

bool parsePqAccountNumber(const std::string& in, uint32_t& height, uint32_t& txIndex) {
  // Trim whitespace.
  size_t b = in.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return false;
  size_t e = in.find_last_not_of(" \t\r\n");
  std::string s = in.substr(b, e - b + 1);

  size_t d1 = s.find('-');
  if (d1 == std::string::npos) return false;
  size_t d2 = s.find('-', d1 + 1);
  if (d2 == std::string::npos) return false;

  const std::string hStr = s.substr(0, d1);
  const std::string iStr = s.substr(d1 + 1, d2 - d1 - 1);
  const std::string chk = s.substr(d2 + 1);
  if (hStr.empty() || iStr.empty() || chk.empty()) return false;

  try {
    unsigned long long h = std::stoull(hStr);
    unsigned long long i = std::stoull(iStr);
    if (h > 0xFFFFFFFFull || i > 0xFFFFFFFFull) return false;
    uint32_t hh = static_cast<uint32_t>(h);
    uint32_t ii = static_cast<uint32_t>(i);
    std::string expect = accountChecksum(hh, ii);
    // Case-insensitive checksum compare.
    if (chk.size() != expect.size()) return false;
    for (size_t k = 0; k < chk.size(); ++k) {
      if (std::toupper(static_cast<unsigned char>(chk[k])) != expect[k]) return false;
    }
    height = hh;
    txIndex = ii;
    return true;
  } catch (...) {
    return false;
  }
}

bool parsePqAddress(const std::string& s, PqAddress& out, PqAddressEncoding* encoding) {
  if (decodePqAddress(s, out, PqAddressEncoding::Base58)) {
    if (encoding) *encoding = PqAddressEncoding::Base58;
    return true;
  }
  if (decodePqAddress(s, out, PqAddressEncoding::Bech32m)) {
    if (encoding) *encoding = PqAddressEncoding::Bech32m;
    return true;
  }
  return false;
}

}  // namespace CryptoNote
