// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

// End-to-end driver for the redefined block-major v6 Proof-of-Work
// (windowed sequential full-block sampling; see docs/POW-V6.md). It grows a
// synthetic chain across the v5→v6 activation boundary, then forces a
// reorganization deeper than the coinbase unlock window so that the v6 PoW's
// alternative-chain record path (buildPowRecordFromEntry) is exercised in
// addition to the main-chain cache/DB paths.
//
// The chain is mined at difficulty 1 (a testnet currency skips the mainnet
// difficulty floor), so every structurally valid, correctly signed block
// satisfies the PoW target regardless of nonce. That is deliberate: it lets the
// test drive the daemon's real getBlockLongHash for both chains without solving
// an alt-context nonce, while still failing loudly if the v6 PoW pipeline
// crashes, cannot assemble a record, or returns false.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Blockchain.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/Difficulty.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

// Upgrade schedule for the test currency (see runV6Scenario). Blocks strictly
// above each height carry the next version, matching Blockchain's `>` bands.
//
// V5 must activate high enough that the FIRST v5 block's height exceeds the
// coinbase unlock window + 1: the legacy v5 PoW (getBlockLongHashV5) computes
// `maxHeight = currentHeight - 1 - unlockWindow` and would unsigned-underflow
// (sampling nonexistent heights → PoW returns false → miner spins) for a v5
// block at height <= unlockWindow+1. Real testnet uses v5=80 for the same
// reason; mainnet v5=700000 is never near the boundary. v6 has an explicit
// young-chain clamp and does not share this constraint.
constexpr uint32_t V2_HEIGHT = 1;
constexpr uint32_t V3_HEIGHT = 2;
constexpr uint32_t V4_HEIGHT = 3;
constexpr uint32_t V5_HEIGHT = 12;
constexpr uint32_t V6_HEIGHT = 16;

uint8_t versionForHeight(uint32_t h) {
  if (h > V6_HEIGHT) return CryptoNote::BLOCK_MAJOR_VERSION_6;
  if (h > V5_HEIGHT) return CryptoNote::BLOCK_MAJOR_VERSION_5;
  if (h > V4_HEIGHT) return CryptoNote::BLOCK_MAJOR_VERSION_4;
  if (h > V3_HEIGHT) return CryptoNote::BLOCK_MAJOR_VERSION_3;
  if (h > V2_HEIGHT) return CryptoNote::BLOCK_MAJOR_VERSION_2;
  return CryptoNote::BLOCK_MAJOR_VERSION_1;
}

bool submitBlock(CryptoNote::Core& core, const CryptoNote::Block& block,
                 bool expectMainChain, bool expectSwitchToAlt, const std::string& label) {
  CryptoNote::block_verification_context bvc{};
  core.handle_incoming_block(block, bvc, false, false);

  if (!expect(!bvc.m_verification_failed, label + ": verification failed")) return false;
  if (!expect(!bvc.m_marked_as_orphaned, label + ": block marked as orphan")) return false;
  if (!expect(bvc.m_added_to_main_chain == expectMainChain, label + ": unexpected m_added_to_main_chain")) return false;
  if (!expect(bvc.m_switched_to_alt_chain == expectSwitchToAlt, label + ": unexpected m_switched_to_alt_chain")) return false;
  return true;
}

// Version-aware, signature-aware nonce search over the daemon's real PoW.
// Uses the public (empty-alt-chain) getBlockLongHash, which is exactly what a
// main-chain-extending miner computes. For difficulty 1 it returns after a
// single signed attempt, so it is also correct for alt blocks in this test.
bool mineBlock(CryptoNote::Blockchain& bc, const CryptoNote::AccountKeys& keys,
               CryptoNote::Block& blk, CryptoNote::Difficulty diff) {
  Crypto::cn_context ctx;
  blk.nonce = 0;
  uint64_t attempts = 0;
  const uint64_t kMaxAttempts = 2000000;  // safety cap; diff-1 returns immediately
  while (true) {
    signBlockV5(blk, keys);  // no-op for < v5; PoW hashes the signed blob
    Crypto::Hash h;
    if (bc.getBlockLongHash(ctx, blk, h) && CryptoNote::check_hash(h, diff)) {
      return true;
    }
    if (++attempts >= kMaxAttempts) {
      std::cerr << "[diag] mineBlock gave up after " << attempts
                << " attempts (diff=" << diff << ")" << std::endl;
      return false;
    }
    ++blk.nonce;
    if (blk.nonce == 0) ++blk.timestamp;
  }
}

// Build (but do not submit) the next block extending `prevHash` at `height`.
bool buildBlock(CryptoNote::Core& core, const CryptoNote::Currency& currency,
                test_generator& generator, const CryptoNote::AccountBase& miner,
                const Crypto::Hash& prevHash, uint32_t height, uint64_t timestamp,
                CryptoNote::Difficulty diff, CryptoNote::Block& out) {
  uint64_t alreadyGenerated = 0;
  try {
    alreadyGenerated = generator.getAlreadyGeneratedCoins(prevHash);
  } catch (const std::exception&) {
    return false;
  }

  std::vector<size_t> blockSizes;
  try {
    generator.getLastNBlockSizes(blockSizes, prevHash, currency.rewardBlocksWindow());
  } catch (const std::exception&) {
    return false;
  }

  generator.defaultMajorVersion = versionForHeight(height);
  generator.defaultMinorVersion = CryptoNote::BLOCK_MINOR_VERSION_0;

  std::list<CryptoNote::Transaction> txList;
  if (!generator.constructBlock(out, height, prevHash, miner, timestamp,
                                alreadyGenerated, blockSizes, txList)) {
    return false;
  }

  // constructBlock mined+signed at difficulty 1 already. Re-mine to the chain's
  // real difficulty if needed, then re-record generator metadata under the
  // (possibly new) block hash.
  if (diff > 1) {
    if (!mineBlock(core.get_blockchain_storage(), miner.getAccountKeys(), out, diff)) {
      return false;
    }
  }
  generator.addBlock(out, 0, 0, blockSizes, alreadyGenerated);
  return true;
}

bool runV6Scenario() {
  Logging::ConsoleLogger logger(Logging::WARNING);
  const CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(V2_HEIGHT)
      .upgradeHeightV3(V3_HEIGHT)
      .upgradeHeightV4(V4_HEIGHT)
      .upgradeHeightV5(V5_HEIGHT)
      .upgradeHeightV6(V6_HEIGHT)
      .currency();

  const std::filesystem::path dataDir("pow_v6_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);
  if (!expect(!ec, "could not create data directory")) return false;

  System::Dispatcher dispatcher;
  CryptoNote::Core core(currency, nullptr, logger, dispatcher, 0, false);
  CryptoNote::CoreConfig coreConfig;
  coreConfig.configFolder = dataDir.string();
  CryptoNote::MinerConfig minerConfig;

  auto cleanup = [&]() {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
  };

  if (!expect(core.init(coreConfig, minerConfig, false), "core.init failed")) {
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  test_generator generator(currency);
  // Wire the PoW sink so V5+ blocks hash via Blockchain::getBlockLongHash.
  generator.setBlockchain(&core.get_blockchain_storage());

  CryptoNote::AccountBase miner;
  miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  CryptoNote::Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "failed to load genesis block")) {
    cleanup();
    return false;
  }
  std::vector<size_t> emptySizes;
  generator.addBlock(genesis, 0, 0, emptySizes, 0);

  // ── Grow the main chain across the v5→v6 boundary ──────────────────────────
  const uint32_t MAIN_TIP_INDEX = 50;                 // final block index on main
  const uint64_t startTimestamp =
      static_cast<uint64_t>(std::time(nullptr)) - 48ull * 60 * 60;

  std::vector<CryptoNote::Block> mainChain;
  mainChain.push_back(genesis);

  uint32_t sawV6 = 0;
  for (uint32_t h = 1; h <= MAIN_TIP_INDEX; ++h) {
    const Crypto::Hash prevHash = get_block_hash(mainChain.back());
    const uint64_t timestamp = startTimestamp + uint64_t(h) * currency.difficultyTarget();
    const CryptoNote::Difficulty diff =
        core.get_blockchain_storage().getDifficultyForNextBlock(prevHash);
    std::cerr << "[diag] building main h=" << h
              << " v=" << int(versionForHeight(h)) << " diff=" << diff << std::endl;

    CryptoNote::Block block;
    if (!expect(buildBlock(core, currency, generator, miner, prevHash, h, timestamp, diff, block),
                "failed to build main block at height " + std::to_string(h))) {
      cleanup();
      return false;
    }
    if (!expect(block.majorVersion == versionForHeight(h),
                "main block has wrong major version at height " + std::to_string(h))) {
      cleanup();
      return false;
    }
    if (!submitBlock(core, block, true, false, "main block h=" + std::to_string(h))) {
      cleanup();
      return false;
    }
    if (block.majorVersion >= CryptoNote::BLOCK_MAJOR_VERSION_6) ++sawV6;
    mainChain.push_back(block);
  }

  if (!expect(core.getCurrentBlockchainHeight() == MAIN_TIP_INDEX + 1, "unexpected main height")) {
    cleanup();
    return false;
  }
  if (!expect(sawV6 >= 30, "expected a substantial run of v6 blocks")) {
    cleanup();
    return false;
  }
  const Crypto::Hash oldMainTip = get_block_hash(mainChain.back());

  // ── Deep reorg past the unlock window (exercises the alt-record path) ───────
  // Fork well below the tip so that, once the alt chain overtakes, the alt
  // tip's sampling window ([lo, tip-1-unlockWindow]) covers alt-chain heights.
  const uint32_t FORK_INDEX = 25;
  // Main and alt carry identical per-height difficulty (all 1), so alt cumulative
  // difficulty exceeds the main tip exactly one block past the main tip height.
  const uint32_t ALT_TIP_INDEX = MAIN_TIP_INDEX + 1;
  CryptoNote::Block altPrev = mainChain[FORK_INDEX];
  std::vector<CryptoNote::Block> altChain;

  for (uint32_t h = FORK_INDEX + 1; h <= ALT_TIP_INDEX; ++h) {
    const Crypto::Hash prevHash = get_block_hash(altPrev);
    // A distinct timestamp offset keeps alt block hashes off the main chain.
    const uint64_t timestamp =
        startTimestamp + uint64_t(h) * currency.difficultyTarget() + 7;
    const CryptoNote::Difficulty diff =
        core.get_blockchain_storage().getDifficultyForNextBlock(prevHash);
    if (!expect(diff == 1, "alt phase requires difficulty 1 at height " + std::to_string(h))) {
      cleanup();
      return false;
    }

    CryptoNote::Block block;
    if (!expect(buildBlock(core, currency, generator, miner, prevHash, h, timestamp, diff, block),
                "failed to build alt block at height " + std::to_string(h))) {
      cleanup();
      return false;
    }

    // The alt chain overtakes the main chain only when its tip exceeds the main
    // cumulative difficulty; with equal per-block difficulty that is the final,
    // length-exceeding block.
    const bool shouldSwitch = (h == ALT_TIP_INDEX);
    if (!submitBlock(core, block, shouldSwitch, shouldSwitch,
                     "alt block h=" + std::to_string(h))) {
      cleanup();
      return false;
    }

    altChain.push_back(block);
    altPrev = block;
  }

  // ── Post-reorg assertions ──────────────────────────────────────────────────
  const Crypto::Hash newMainTip = get_block_hash(altChain.back());
  uint32_t topHeight = 0;
  Crypto::Hash topHash{};
  core.get_blockchain_top(topHeight, topHash);

  if (!expect(core.getCurrentBlockchainHeight() == ALT_TIP_INDEX + 1, "unexpected height after reorg")) {
    cleanup();
    return false;
  }
  if (!expect(topHeight == ALT_TIP_INDEX && topHash == newMainTip, "unexpected tip after reorg")) {
    cleanup();
    return false;
  }
  if (!expect(core.getBlockIdByHeight(MAIN_TIP_INDEX) != oldMainTip,
              "old main tip still present after reorg")) {
    cleanup();
    return false;
  }

  // Re-validate the whole active chain by replaying it into a fresh Core. This
  // recomputes every v6 PoW from the DB record path (no in-RAM alt entries),
  // proving the record cache and DB reconstruction agree byte-for-byte.
  {
    CryptoNote::Core core2(currency, nullptr, logger, dispatcher, 0, false);
    CryptoNote::CoreConfig cc2;
    const std::filesystem::path dataDir2("pow_v6_test_data_replay");
    std::filesystem::remove_all(dataDir2, ec);
    std::filesystem::create_directories(dataDir2, ec);
    cc2.configFolder = dataDir2.string();
    CryptoNote::MinerConfig mc2;
    bool ok = core2.init(cc2, mc2, false);
    // Replay active chain [1 .. ALT_TIP_INDEX].
    for (uint32_t hgt = 1; ok && hgt <= ALT_TIP_INDEX; ++hgt) {
      CryptoNote::Block b;
      Crypto::Hash id = core.getBlockIdByHeight(hgt);
      ok = core.getBlockByHash(id, b);
      if (ok) {
        CryptoNote::block_verification_context bvc{};
        core2.handle_incoming_block(b, bvc, false, false);
        ok = bvc.m_added_to_main_chain && !bvc.m_verification_failed;
      }
    }
    ok = ok && core2.getCurrentBlockchainHeight() == ALT_TIP_INDEX + 1;
    core2.deinit();
    std::filesystem::remove_all(dataDir2, ec);
    if (!expect(ok, "replay of reorged chain into a fresh node failed")) {
      cleanup();
      return false;
    }
  }

  cleanup();
  return true;
}

}  // namespace

int main() {
  if (!runV6Scenario()) {
    return 1;
  }
  std::cout << "[PASS] block-major v6 PoW: activation + deep reorg" << std::endl;
  return 0;
}
