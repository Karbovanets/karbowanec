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

#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <thread>

#include "gtest/gtest.h"

#include "crypto/crypto.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/IMinerHandler.h"
#include "CryptoNoteCore/Miner.h"
#include "Logging/LoggerGroup.h"

namespace {

// Hands out templates that can never be solved and records the keys used.
class NeverSolvingMinerHandler : public CryptoNote::IMinerHandler {
public:
  bool handle_block_found(CryptoNote::Block&) override { return false; }

  bool get_block_template(CryptoNote::Block& b, const CryptoNote::AccountKeys& acc, CryptoNote::Difficulty& diffic,
                          uint32_t& height, const CryptoNote::BinaryArray&) override {
    std::lock_guard<std::mutex> lk(m_lock);
    b = CryptoNote::Block();
    b.majorVersion = CryptoNote::BLOCK_MAJOR_VERSION_1;
    diffic = std::numeric_limits<CryptoNote::Difficulty>::max();
    height = 0;
    m_lastKeys = acc;
    ++m_templates;
    return true;
  }

  bool getBlockLongHash(Crypto::cn_context&, const CryptoNote::Block&, Crypto::Hash& res) override {
    std::memset(&res, 0xff, sizeof(res));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return true;
  }

  CryptoNote::AccountKeys lastKeys() {
    std::lock_guard<std::mutex> lk(m_lock);
    return m_lastKeys;
  }

  std::atomic<int> m_templates{0};

private:
  std::mutex m_lock;
  CryptoNote::AccountKeys m_lastKeys{};
};

CryptoNote::AccountKeys makeKeys() {
  CryptoNote::AccountKeys keys{};
  Crypto::generate_keys(keys.address.spendPublicKey, keys.spendSecretKey);
  Crypto::generate_keys(keys.address.viewPublicKey, keys.viewSecretKey);
  return keys;
}

bool sameSpendSecret(const CryptoNote::AccountKeys& a, const CryptoNote::AccountKeys& b) {
  return std::memcmp(&a.spendSecretKey, &b.spendSecretKey, sizeof(a.spendSecretKey)) == 0;
}

class MinerKeysTest : public ::testing::Test {
protected:
  MinerKeysTest() : m_currency(CryptoNote::CurrencyBuilder(m_logger).currency()), m_miner(m_currency, m_handler, m_logger) {}

  Logging::LoggerGroup m_logger;
  CryptoNote::Currency m_currency;
  NeverSolvingMinerHandler m_handler;
  CryptoNote::miner m_miner;
};

}

TEST_F(MinerKeysTest, stopWipesKeys) {
  const CryptoNote::AccountKeys keys = makeKeys();
  ASSERT_TRUE(m_miner.start(keys, 1));
  ASSERT_TRUE(m_miner.is_mining());
  EXPECT_TRUE(m_miner.hasMiningKeys());
  EXPECT_TRUE(sameSpendSecret(m_handler.lastKeys(), keys));

  ASSERT_TRUE(m_miner.stop());
  EXPECT_FALSE(m_miner.is_mining());
  EXPECT_FALSE(m_miner.hasMiningKeys());
}

TEST_F(MinerKeysTest, restartAfterStopUsesNewKeys) {
  ASSERT_TRUE(m_miner.start(makeKeys(), 1));
  ASSERT_TRUE(m_miner.stop());
  ASSERT_FALSE(m_miner.hasMiningKeys());

  const CryptoNote::AccountKeys keys = makeKeys();
  ASSERT_TRUE(m_miner.start(keys, 1));
  EXPECT_TRUE(m_miner.hasMiningKeys());
  ASSERT_TRUE(m_miner.on_block_chain_update());
  EXPECT_TRUE(sameSpendSecret(m_handler.lastKeys(), keys));
  ASSERT_TRUE(m_miner.stop());
}

TEST_F(MinerKeysTest, pauseKeepsKeysForResume) {
  const CryptoNote::AccountKeys keys = makeKeys();
  ASSERT_TRUE(m_miner.start(keys, 1));

  // Stopping with mining still requested (e.g. all peers disconnected) must keep the keys.
  ASSERT_TRUE(m_miner.stop(true));
  EXPECT_FALSE(m_miner.is_mining());
  EXPECT_TRUE(m_miner.is_mining_requested());
  EXPECT_TRUE(m_miner.hasMiningKeys());

  m_miner.on_synchronized();
  ASSERT_TRUE(m_miner.is_mining());
  ASSERT_TRUE(m_miner.on_block_chain_update());
  EXPECT_TRUE(sameSpendSecret(m_handler.lastKeys(), keys));
  ASSERT_TRUE(m_miner.stop());
  EXPECT_FALSE(m_miner.hasMiningKeys());
}

TEST_F(MinerKeysTest, startWhenSynchronizedArmsWithoutMining) {
  const CryptoNote::AccountKeys keys = makeKeys();
  ASSERT_TRUE(m_miner.startWhenSynchronized(keys, 1));
  EXPECT_FALSE(m_miner.is_mining());
  EXPECT_TRUE(m_miner.is_mining_requested());
  EXPECT_TRUE(m_miner.hasMiningKeys());
  EXPECT_EQ(0, m_handler.m_templates.load());

  m_miner.on_synchronized();
  ASSERT_TRUE(m_miner.is_mining());
  EXPECT_TRUE(sameSpendSecret(m_handler.lastKeys(), keys));
  ASSERT_TRUE(m_miner.stop());
  EXPECT_FALSE(m_miner.hasMiningKeys());
}

TEST_F(MinerKeysTest, stopWhileArmedDisarmsAndWipesKeys) {
  ASSERT_TRUE(m_miner.startWhenSynchronized(makeKeys(), 1));
  EXPECT_FALSE(m_miner.stop());
  EXPECT_FALSE(m_miner.is_mining_requested());
  EXPECT_FALSE(m_miner.hasMiningKeys());

  m_miner.on_synchronized();
  EXPECT_FALSE(m_miner.is_mining());
}
