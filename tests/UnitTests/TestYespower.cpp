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

#include "gtest/gtest.h"

#include <cstdint>
#include <string>
#include <vector>

#include "Common/StringTools.h"
#include "crypto/hash.h"

namespace {

// Deterministic filler so the vectors don't depend on any RNG implementation.
void fill(uint8_t* out, size_t size, uint32_t state) {
  for (size_t i = 0; i < size; ++i) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    out[i] = static_cast<uint8_t>(state >> 24);
  }
}

struct YespowerVector {
  size_t length;
  uint32_t dataTag;   // 0 = all-zero data
  uint32_t seedTag;   // 0 = all-zero seed
  const char* expected;
};

// Known answers for the PoW parameter set used by y_slow_hash (N = 2048, r = 32,
// 32-byte personalization seed).
const YespowerVector vectors[] = {
  {    1, 0x00000001, 0x00000002,
    "148211a616b471aafb1fb74fc266f372914edc47070ed23d52fd506ad4dbcb3b" },
  {   32, 0x00000003, 0x00000004,
    "256b833209cdb41dbacebfd474779b1044b4d870f7e1ee909f35dcb6323afb29" },
  {   76, 0x00000005, 0x00000006,
    "8fbfbadc502eb8f6bb584131beb53ea041a23c5f92ddf9a6ec023d9f1ee5270f" },
  {   76, 0x00000000, 0x00000000,
    "f436a602e56d5ed74bebb28db44b5b9a1f51de9b4ac8aa5265100df1b914ec40" },
  {   77, 0x00000007, 0x00000008,
    "b6464ccbb01b722c3ef966f8685b82289cb8b0bb27d220ff5a940f593f337d17" },
  {   78, 0x00000009, 0x0000000a,
    "8672dcdc7043873ea658363f678e8c59bca5fe484b50f995f120e67ca958abfb" },
  {   79, 0x0000000b, 0x0000000c,
    "13c6d6decf212f000a46c02c894a6b46ec7c33202e811f5074fa1d910372f69b" },
  {   80, 0x0000000d, 0x0000000e,
    "43cf090cfc01feb8c2197aad21011243d3280189be0f2531adada9c04c4e3832" },
  {   80, 0x0000000d, 0x0000000f,
    "43cf090cfc01feb8c2197aad21011243d3280189be0f2531adada9c04c4e3832" },
  {   80, 0x00000000, 0x00000010,
    "7ce87a4df515b4fd1c1de69af2c1fbd5805ade6cb7e92394ea46d813e3c81cdb" },
  {   81, 0x00000011, 0x00000012,
    "c61320d20e1d2e82b42703e568685c9c7d809bcf8253c838b3e7e301d7f103b2" },
  {  160, 0x00000013, 0x00000014,
    "2d206629dcce931c4cfc8ff0273b5d54f48440ecac13cb7dbeab52ae048787db" },
  {  255, 0x00000015, 0x00000016,
    "a9642805e924db2a5dce044c6245a98542f3a21d85cadbfff2b2b1fe2dfb674d" },
  {  256, 0x00000017, 0x00000000,
    "f74b3b511ccd871148fcb9fa90422657e471278dc4a09109a5ddf90935eb2d03" },
  { 1023, 0x00000019, 0x0000001a,
    "b643bf425f6cfb8f9912bd54c2bd5d612d108dd5c2b380f6dcd9695d87ba2c19" },
  { 4096, 0x0000001b, 0x0000001c,
    "c9526e5e5fb7e0cba79e13e48f3963550e07b860ac45a5aefe926694c579251e" },
  { 81920, 0x0000001d, 0x0000001e,
    "f891b5cdfb63702a1259b1f4068c9c7b5c3944734b6eb5038aa6ecf6f63ce3f5" },
};

void prepare(const YespowerVector& v, std::vector<uint8_t>& data, Crypto::Hash& seed) {
  data.assign(v.length, 0);
  if (v.dataTag != 0 && !data.empty()) {
    fill(data.data(), data.size(), v.dataTag * 0x9e3779b9u);
  }

  seed = Crypto::Hash();
  if (v.seedTag != 0) {
    fill(seed.data, sizeof(seed.data), v.seedTag * 0x85ebca6bu);
  }
}

}

TEST(Yespower, knownAnswers) {
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    const YespowerVector& v = vectors[i];
    std::vector<uint8_t> data;
    Crypto::Hash seed;
    prepare(v, data, seed);

    Crypto::Hash hash;
    ASSERT_TRUE(Crypto::y_slow_hash(data.data(), data.size(), seed, hash)) << "vector " << i;
    EXPECT_EQ(std::string(v.expected), Common::podToHex(hash)) << "vector " << i;
  }
}

TEST(Yespower, knownAnswersExplicitLocal) {
  yespower_local_t local;
  ASSERT_EQ(0, yespower_init_local(&local));

  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    const YespowerVector& v = vectors[i];
    std::vector<uint8_t> data;
    Crypto::Hash seed;
    prepare(v, data, seed);

    yespower_params_t params = { 2048, 32, seed.data, sizeof(seed) };
    Crypto::Hash hash;
    ASSERT_EQ(0, yespower(&local, data.data(), data.size(), &params, reinterpret_cast<yespower_binary_t*>(hash.data))) << "vector " << i;
    EXPECT_EQ(std::string(v.expected), Common::podToHex(hash)) << "vector " << i;
  }

  ASSERT_EQ(0, yespower_free_local(&local));
}
