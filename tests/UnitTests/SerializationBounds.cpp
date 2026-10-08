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

// Element counts and string lengths in binary input are supplied by the peer.
// These tests check that they are never trusted to size an allocation before
// the data backing them has actually been read.

#include "gtest/gtest.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Common/MemoryInputStream.h"
#include "Common/StringOutputStream.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"

using namespace CryptoNote;

namespace {

void appendVarint(std::vector<uint8_t>& out, uint64_t value) {
  while (value >= 0x80) {
    out.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
    value >>= 7;
  }
  out.push_back(static_cast<uint8_t>(value));
}

template <typename T>
bool tryDeserializeVector(const std::vector<uint8_t>& blob, std::vector<T>& out) {
  try {
    Common::MemoryInputStream stream(blob.data(), blob.size());
    BinaryInputStreamSerializer serializer(stream);
    return CryptoNote::serialize(out, "arr", serializer);
  } catch (const std::exception&) {
    return false;
  }
}

template <typename T>
std::vector<uint8_t> serializeVector(std::vector<T>& in) {
  std::string out;
  Common::StringOutputStream stream(out);
  BinaryOutputStreamSerializer serializer(stream);
  CryptoNote::serialize(in, "arr", serializer);
  return std::vector<uint8_t>(out.begin(), out.end());
}

// Allocator that records the largest single request and refuses huge ones, so
// pre-sizing from a declared count is directly observable.
std::size_t g_peakRequestBytes = 0;
const std::size_t kAllocatorRefusalBytes = 64u << 20;

template <typename T>
struct TrackingAllocator {
  using value_type = T;

  TrackingAllocator() = default;
  template <typename U> TrackingAllocator(const TrackingAllocator<U>&) {}

  T* allocate(std::size_t n) {
    const std::size_t bytes = n * sizeof(T);
    g_peakRequestBytes = std::max(g_peakRequestBytes, bytes);
    if (bytes > kAllocatorRefusalBytes) {
      throw std::bad_alloc();
    }
    return static_cast<T*>(::operator new(bytes));
  }

  void deallocate(T* p, std::size_t) { ::operator delete(p); }

  template <typename U> bool operator==(const TrackingAllocator<U>&) const { return true; }
  template <typename U> bool operator!=(const TrackingAllocator<U>&) const { return false; }
};

typedef std::vector<Crypto::Hash, TrackingAllocator<Crypto::Hash>> TrackedHashes;

bool tryDeserializeTracked(const std::vector<uint8_t>& blob, TrackedHashes& out) {
  try {
    Common::MemoryInputStream stream(blob.data(), blob.size());
    BinaryInputStreamSerializer serializer(stream);
    return CryptoNote::serializeContainer(out, "arr", serializer);
  } catch (const std::exception&) {
    return false;
  }
}

bool tryDeserializeKeyInput(const std::vector<uint8_t>& blob, KeyInput& out) {
  try {
    Common::MemoryInputStream stream(blob.data(), blob.size());
    BinaryInputStreamSerializer serializer(stream);
    CryptoNote::serialize(out, serializer);
    return stream.endOfStream();
  } catch (const std::exception&) {
    return false;
  }
}

}

TEST(SerializationBounds, HugeCountIsNotPreAllocated) {
  std::vector<uint8_t> blob;
  appendVarint(blob, uint64_t(1) << 40);
  blob.insert(blob.end(), 4, 0x00);

  g_peakRequestBytes = 0;
  TrackedHashes hashes;
  EXPECT_FALSE(tryDeserializeTracked(blob, hashes));
  EXPECT_LT(g_peakRequestBytes, std::size_t(1) << 20);
}

TEST(SerializationBounds, HugeVectorCountIsRejectedWithoutAllocating) {
  std::vector<uint8_t> blob;
  appendVarint(blob, uint64_t(1) << 60);
  blob.insert(blob.end(), 4, 0x00);

  std::vector<Crypto::Hash> hashes;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(tryDeserializeVector(blob, hashes));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(SerializationBounds, CountBeyondSizeTypeIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, std::numeric_limits<uint64_t>::max());
  blob.insert(blob.end(), 4, 0x00);

  std::vector<Crypto::Hash> hashes;
  EXPECT_FALSE(tryDeserializeVector(blob, hashes));
}

TEST(SerializationBounds, CountJustBeyondAvailableBytesIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 3);
  for (int i = 0; i < 2; ++i) {
    blob.insert(blob.end(), sizeof(Crypto::Hash), static_cast<uint8_t>(i));
  }

  std::vector<Crypto::Hash> hashes;
  EXPECT_FALSE(tryDeserializeVector(blob, hashes));
}

TEST(SerializationBounds, HonestCountStillFillsTheContainer) {
  TrackedHashes original(2000);
  for (std::size_t i = 0; i < original.size(); ++i) {
    for (std::size_t j = 0; j < sizeof(Crypto::Hash); ++j) {
      original[i].data[j] = static_cast<uint8_t>(i + j);
    }
  }
  std::string out;
  Common::StringOutputStream stream(out);
  BinaryOutputStreamSerializer writer(stream);
  ASSERT_TRUE(CryptoNote::serializeContainer(original, "arr", writer));

  TrackedHashes restored;
  ASSERT_TRUE(tryDeserializeTracked(std::vector<uint8_t>(out.begin(), out.end()), restored));
  ASSERT_EQ(original.size(), restored.size());
  EXPECT_EQ(0, std::memcmp(original.back().data, restored.back().data, sizeof(Crypto::Hash)));
}

TEST(SerializationBounds, DeserializingReplacesExistingContent) {
  std::vector<uint32_t> original = { 1, 2, 3 };
  const std::vector<uint8_t> blob = serializeVector(original);

  std::vector<uint32_t> restored = { 7, 8, 9, 10, 11 };
  ASSERT_TRUE(tryDeserializeVector(blob, restored));
  EXPECT_EQ(original, restored);
}

TEST(SerializationBounds, LargeButHonestVectorIsAccepted) {
  std::vector<uint32_t> original(50000);
  for (size_t i = 0; i < original.size(); ++i) {
    original[i] = static_cast<uint32_t>(i);
  }
  const std::vector<uint8_t> blob = serializeVector(original);

  std::vector<uint32_t> restored;
  ASSERT_TRUE(tryDeserializeVector(blob, restored));
  EXPECT_EQ(original, restored);
}

TEST(SerializationBounds, HugeStringLengthIsRejectedWithoutAllocating) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 100 * 1024 * 1024);
  blob.insert(blob.end(), 16, 'a');

  std::string value = "unchanged";
  bool ok = true;
  try {
    Common::MemoryInputStream stream(blob.data(), blob.size());
    BinaryInputStreamSerializer serializer(stream);
    serializer(value, "str");
  } catch (const std::exception&) {
    ok = false;
  }
  EXPECT_FALSE(ok);
  EXPECT_EQ("unchanged", value);
}

TEST(SerializationBounds, LargeStringRoundTrips) {
  std::string original(300000, '\0');
  for (size_t i = 0; i < original.size(); ++i) {
    original[i] = static_cast<char>(i * 7);
  }

  std::string out;
  Common::StringOutputStream outStream(out);
  BinaryOutputStreamSerializer writer(outStream);
  writer(original, "str");

  std::string restored;
  Common::MemoryInputStream inStream(out.data(), out.size());
  BinaryInputStreamSerializer reader(inStream);
  reader(restored, "str");
  EXPECT_EQ(original, restored);
  EXPECT_TRUE(inStream.endOfStream());
}

TEST(SerializationBounds, KeyInputWithHugeOffsetCountIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 1000);                 // amount
  appendVarint(blob, uint64_t(1) << 40);    // key_offsets count
  appendVarint(blob, 1);

  KeyInput input;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(tryDeserializeKeyInput(blob, input));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(SerializationBounds, KeyInputRoundTrips) {
  KeyInput original;
  original.amount = 123456789;
  for (uint32_t i = 0; i < 5000; ++i) {
    original.outputIndexes.push_back(i * 131);
  }
  std::memset(&original.keyImage, 0x5a, sizeof(original.keyImage));

  BinaryArray ba = toBinaryArray(original);
  KeyInput restored;
  restored.outputIndexes = { 42, 43 };
  ASSERT_TRUE(tryDeserializeKeyInput(std::vector<uint8_t>(ba.begin(), ba.end()), restored));
  EXPECT_EQ(original.amount, restored.amount);
  EXPECT_EQ(original.outputIndexes, restored.outputIndexes);
  EXPECT_EQ(0, std::memcmp(&original.keyImage, &restored.keyImage, sizeof(original.keyImage)));
}

TEST(SerializationBounds, TinyTransactionBlobWithHugeInputCountIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 1);                    // version
  appendVarint(blob, 0);                    // unlockTime
  appendVarint(blob, uint64_t(1) << 55);    // inputs count

  Transaction tx;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(fromBinaryArray(tx, BinaryArray(blob.begin(), blob.end())));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(SerializationBounds, TinyTransactionBlobWithHugeKeyOffsetCountIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 1);                    // version
  appendVarint(blob, 0);                    // unlockTime
  appendVarint(blob, 1);                    // inputs count
  blob.push_back(0x02);                     // KeyInput tag
  appendVarint(blob, 1000);                 // amount
  appendVarint(blob, uint64_t(1) << 50);    // key_offsets count

  Transaction tx;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(fromBinaryArray(tx, BinaryArray(blob.begin(), blob.end())));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(SerializationBounds, TinyBlockBlobWithHugeInputCountIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 1);                    // majorVersion
  appendVarint(blob, 0);                    // minorVersion
  appendVarint(blob, 0);                    // timestamp
  blob.insert(blob.end(), 32, 0x00);        // previousBlockHash
  blob.insert(blob.end(), 4, 0x00);         // nonce
  appendVarint(blob, 1);                    // miner tx version
  appendVarint(blob, 0);                    // miner tx unlockTime
  appendVarint(blob, uint64_t(1) << 55);    // miner tx inputs count

  Block block;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(fromBinaryArray(block, BinaryArray(blob.begin(), blob.end())));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}
