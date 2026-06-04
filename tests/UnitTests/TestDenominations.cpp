// Copyright (c) 2018-2026, Karbo developers
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

#include "gtest/gtest.h"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <vector>

#include "Denominations.h"

namespace {

// --- Denomination table sanity ---

TEST(Denominations, TableHas64Entries) {
  ASSERT_EQ(CryptoNote::DENOMINATION_COUNT, 64u);
  ASSERT_EQ(CryptoNote::DENOMINATIONS.size(), 64u);
}

TEST(Denominations, TableIsSortedAscending) {
  for (size_t i = 1; i < CryptoNote::DENOMINATIONS.size(); ++i) {
    EXPECT_LT(CryptoNote::DENOMINATIONS[i - 1], CryptoNote::DENOMINATIONS[i])
      << "at index " << i;
  }
}

// All assertions below are expressed relative to MIN_CT_DENOMINATION so the
// suite tracks the canonical atomic-unit scale (0.01 KRB = 1e10 au up to
// 100,000 KRB = 1e17 au) without needing to be edited if the scale moves.

namespace {
constexpr uint64_t U = CryptoNote::MIN_CT_DENOMINATION;          // 1e10
constexpr uint64_t TOP = U * 10000000ull;                        // 1e17 (index 63)
}

TEST(Denominations, FirstIsMinLastIsHundredThousandKrb) {
  EXPECT_EQ(CryptoNote::DENOMINATIONS.front(), U);
  EXPECT_EQ(CryptoNote::DENOMINATIONS.back(), TOP);
}

// --- isCanonicalDenomination ---

TEST(Denominations, AllTableEntriesAreCanonical) {
  for (auto d : CryptoNote::DENOMINATIONS) {
    EXPECT_TRUE(CryptoNote::isCanonicalDenomination(d)) << d;
  }
}

TEST(Denominations, NonCanonicalAmountsRejected) {
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(0));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(1));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(U - 1));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(11 * U));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(15 * U));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(99 * U));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(101 * U));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(TOP + U));
  EXPECT_FALSE(CryptoNote::isCanonicalDenomination(2 * TOP));
}

// --- denominationIndex ---

TEST(Denominations, IndexOfFirstAndLast) {
  EXPECT_EQ(CryptoNote::denominationIndex(U), 0);
  EXPECT_EQ(CryptoNote::denominationIndex(TOP), 63);
}

TEST(Denominations, IndexOfKnownValues) {
  // 5 in each decade: 5e10 → idx 4, 5e11 → idx 13, 5e12 → idx 22, 5e16 → idx 58
  EXPECT_EQ(CryptoNote::denominationIndex(5 * U), 4);
  EXPECT_EQ(CryptoNote::denominationIndex(50 * U), 13);
  EXPECT_EQ(CryptoNote::denominationIndex(500 * U), 22);
  EXPECT_EQ(CryptoNote::denominationIndex(5000000 * U), 58);
}

TEST(Denominations, IndexOfNonCanonicalReturnsMinusOne) {
  EXPECT_EQ(CryptoNote::denominationIndex(0), -1);
  EXPECT_EQ(CryptoNote::denominationIndex(11 * U), -1);
  EXPECT_EQ(CryptoNote::denominationIndex(2 * TOP), -1);
}

// --- decomposeAmount ---

TEST(Denominations, DecomposeMinimum) {
  auto v = CryptoNote::decomposeAmount(U);
  ASSERT_EQ(v.size(), 1u);
  EXPECT_EQ(v[0], U);
}

TEST(Denominations, DecomposeMaxSingle) {
  auto v = CryptoNote::decomposeAmount(TOP);
  ASSERT_EQ(v.size(), 1u);
  EXPECT_EQ(v[0], TOP);
}

TEST(Denominations, DecomposeEleven) {
  // 11 * U = 10*U + U  (i.e. 0.11 KRB = 0.10 + 0.01)
  auto v = CryptoNote::decomposeAmount(11 * U);
  ASSERT_EQ(v.size(), 2u);
  EXPECT_EQ(v[0], 10 * U);
  EXPECT_EQ(v[1], U);

  uint64_t sum = std::accumulate(v.begin(), v.end(), uint64_t{0});
  EXPECT_EQ(sum, 11 * U);
}

TEST(Denominations, DecomposeComplex) {
  // 1234567 * U = 1e6*U + 2e5*U + 3e4*U + 4e3*U + 5e2*U + 6e1*U + 7*U  (7 entries)
  auto v = CryptoNote::decomposeAmount(1234567ull * U);
  ASSERT_EQ(v.size(), 7u);

  std::vector<uint64_t> expected = {
    1000000ull * U, 200000ull * U, 30000ull * U,
    4000ull * U, 500ull * U, 60ull * U, 7ull * U
  };
  EXPECT_EQ(v, expected);

  uint64_t sum = std::accumulate(v.begin(), v.end(), uint64_t{0});
  EXPECT_EQ(sum, 1234567ull * U);
}

TEST(Denominations, DecomposeZeroThrows) {
  EXPECT_THROW(CryptoNote::decomposeAmount(0), std::invalid_argument);
}

TEST(Denominations, DecomposeAllSameDigit) {
  // 9999999 * U = 9e6*U + 9e5*U + ... + 9*U  (7 entries)
  auto v = CryptoNote::decomposeAmount(9999999ull * U);
  ASSERT_EQ(v.size(), 7u);

  std::vector<uint64_t> expected = {
    9000000ull * U, 900000ull * U, 90000ull * U,
    9000ull * U, 900ull * U, 90ull * U, 9ull * U
  };
  EXPECT_EQ(v, expected);

  uint64_t sum = std::accumulate(v.begin(), v.end(), uint64_t{0});
  EXPECT_EQ(sum, 9999999ull * U);
}

TEST(Denominations, DecomposeAllDenominationsAreCanonical) {
  auto v = CryptoNote::decomposeAmount(1234567ull * U);
  for (auto d : v) {
    EXPECT_TRUE(CryptoNote::isCanonicalDenomination(d)) << d;
  }
}

TEST(Denominations, DecomposeLargeMultipleOfMax) {
  // 3 * TOP decomposes into three copies of TOP (the largest denom).
  auto v = CryptoNote::decomposeAmount(3 * TOP);
  ASSERT_EQ(v.size(), 3u);
  for (auto d : v) {
    EXPECT_EQ(d, TOP);
  }
}

} // anonymous namespace
