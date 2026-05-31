// v3 CT->CN unshield — chain-integration harness (real Core, real PoW path).
//
// Milestone 1 (this file): stand up a real `Core` on a testnet Currency with
// low hard-fork heights and drive it, lockstep, through CT activation
// (block-major v6). Blocks are built with test_generator (which produces the
// correct per-version structure, including the v2/v3 merge-mining parent block
// and the coinbase) and submitted through the production block-accept pipeline
// (handle_incoming_block_blob). The core independently re-validates each block:
// difficulty (getDifficultyForNextBlock) and proof-of-work (getBlockLongHash,
// i.e. cn_slow_hash for v1-v4 and the yespower memory-mix for v5+).
//
// This is the regression test for the low-height testnet difficulty-zero bug
// ("difficulty overhead"): without the V3/V4 next-difficulty floor, the chain
// could not cross the v3/v4/v5 forks at low height. It is also the scaffold the
// remaining Session-8 vectors build on (round-trip spend of a v3 KeyOutput as a
// v1 ring member; cross-version double-spend on the shared key-image set; full
// checkConfidentialTransaction acceptance), which add real v2/v3 transaction
// construction on top of this mined chain.
//
// Blocks are mined at the test difficulty of 1, so the nonce search is skipped
// (any hash satisfies difficulty 1) — but the core still COMPUTES the real
// longhash for every block, so the v5+ PoW path is genuinely exercised.

#include <cstdio>
#include <cstring>
#include <string>

#include <boost/filesystem.hpp>

#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"

#include "crypto/crypto.h"
#include "crypto/hash.h"

#include "TestGenerator/TestGenerator.h"

using namespace CryptoNote;

namespace {

int tests_run = 0, tests_passed = 0;
const char* current_test = "";

#define TEST(name) do { current_test = (name); ++tests_run; } while (0)
#define PASS() do { ++tests_passed; std::printf("  %-64s [PASS]\n", current_test); return true; } while (0)

// Low testnet hard-fork schedule. V2==V3==V4 collapses the merge-mined v2/v3
// ranges to empty so the chain goes v1 -> v4 -> v5 -> v6 (all simple
// hashing-blob PoW, no merge-mining parent-block PoW). The per-block version
// rule (block.majorVersion == getBlockMajorVersionForHeight(height)) is what's
// enforced while mining; the detector's checkUpgradeHeight only runs at
// init/reinit, which this single-session chain never hits. v5 sits above the
// mined-money unlock window + 1 (10 + 1) as the v5+ longhash requires.
//   v1: 0-2   v4: 3-12   v5: 13-14   v6: 15+
Currency makeTestnetCurrency(Logging::ILogger& logger) {
  return CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(2)
      .upgradeHeightV3(2)
      .upgradeHeightV4(2)
      .upgradeHeightV5(12)
      .upgradeHeightV6(14)
      .currency();
}

bool test_mine_through_ct_activation() {
  TEST("Chain integration: mine testnet through every fork to v6 (CT) via real core");

  // Raise to Logging::INFO to see the core's per-block accept/reject reasons.
  Logging::ConsoleLogger logger(Logging::ERROR);
  Currency currency = makeTestnetCurrency(logger);

  boost::filesystem::path dataDir =
      boost::filesystem::temp_directory_path() /
      boost::filesystem::unique_path("karbo-v3-itest-%%%%-%%%%");
  boost::filesystem::create_directories(dataDir);

  bool ok = false;
  {
    cryptonote_protocol_stub protocolStub;
    System::Dispatcher dispatcher;
    Core c(currency, &protocolStub, logger, dispatcher, 0, false);

    CoreConfig coreConfig;
    coreConfig.configFolder = dataDir.string();
    coreConfig.configFolderDefaulted = false;
    MinerConfig minerConfig;

    if (!c.init(coreConfig, minerConfig, /*load_existing=*/false)) {
      std::fprintf(stderr, "FAIL [%s]: core init failed\n", current_test);
    } else {
      test_generator gen(currency);
      // Wire the live chain so the generator can compute v5+ longhash if it ever
      // needs to (mining at difficulty 1 skips the nonce search, but this keeps
      // the generator correct for any difficulty).
      gen.setBlockchain(&c.get_blockchain_storage());

      AccountBase miner;
      miner.generate();
      const AccountKeys& minerKeys = miner.getAccountKeys();

      // Build the generator's genesis and make the core adopt it, so blocks the
      // generator builds chain onto the same genesis the core validates against.
      Block genesis;
      ok = gen.constructBlock(genesis, miner, /*timestamp=*/1000000000ULL);
      if (!ok) {
        std::fprintf(stderr, "FAIL [%s]: genesis construction failed\n", current_test);
      } else {
        if (c.getBlockIdByHeight(0) != get_block_hash(genesis)) {
          c.set_genesis_block(genesis);
        }

        // v6 first appears at height upgradeHeightV6 + 1 == 15; mine past it.
        const uint32_t kTargetHeight = 20;
        Block prev = genesis;
        for (uint32_t h = 1; h <= kTargetHeight && ok; ++h) {
          // test_generator stamps blk.majorVersion from defaultMajorVersion, not
          // per height — set it to what the core expects for this height so the
          // block crosses each fork (v1->v2->v3->v4->v5->v6) and is accepted.
          const uint8_t ver = c.getBlockMajorVersionForHeight(h);
          Block blk;
          // constructBlockManually (vs constructBlock) skips the block-size
          // convergence loop and, at difficulty 1, the construction-time nonce
          // search — it stamps the requested major version (so each fork is
          // crossed) and sets up the v2/v3 merge-mining parent block. The core
          // computes and validates the real longhash on submission.
          if (!gen.constructBlockManually(blk, prev, miner, test_generator::bf_major_ver, ver)) {
            std::fprintf(stderr, "FAIL [%s]: constructBlockManually failed at height %u (v%d)\n",
                         current_test, h, static_cast<int>(ver));
            ok = false;
            break;
          }

          // v5+ is "signed proof-of-work": the miner signs cn_fast_hash(hashing
          // blob) with the coinbase output's one-time secret key. test_generator
          // doesn't sign, so do it here (mirrors Miner.cpp). At difficulty 1 the
          // nonce stays 0, so signing once over the final blob is sufficient.
          if (ver >= BLOCK_MAJOR_VERSION_5) {
            BinaryArray hashingBlob;
            get_block_hashing_blob(blk, hashingBlob);
            Crypto::Hash sigHash = Crypto::cn_fast_hash(hashingBlob.data(), hashingBlob.size());
            Crypto::PublicKey txPub = getTransactionPublicKeyFromExtra(blk.baseTransaction.extra);
            Crypto::KeyDerivation derivation;
            Crypto::generate_key_derivation(txPub, minerKeys.viewSecretKey, derivation);
            Crypto::SecretKey ephSec;
            Crypto::derive_secret_key(derivation, 0, minerKeys.spendSecretKey, ephSec);
            const Crypto::PublicKey& ephPub = boost::get<KeyOutput>(blk.baseTransaction.outputs[0].target).key;
            Crypto::generate_signature(sigHash, ephPub, ephSec, blk.signature);
          }
          block_verification_context bvc = boost::value_initialized<block_verification_context>();
          c.handle_incoming_block_blob(toBinaryArray(blk), bvc, false, false);
          if (!bvc.m_added_to_main_chain) {
            std::fprintf(stderr,
                "FAIL [%s]: block %u (v%d) rejected (verification_failed=%d, already_exists=%d)\n",
                current_test, h, static_cast<int>(blk.majorVersion),
                bvc.m_verification_failed ? 1 : 0, bvc.m_already_exists ? 1 : 0);
            ok = false;
            break;
          }
          prev = blk;
        }

        if (ok) {
          uint32_t tip = c.getCurrentBlockchainHeight() - 1;
          uint8_t tipVersion = c.getBlockMajorVersionForHeight(tip);
          if (tipVersion < BLOCK_MAJOR_VERSION_6) {
            std::fprintf(stderr, "FAIL [%s]: tip height %u is only v%d, expected >= v6\n",
                         current_test, tip, static_cast<int>(tipVersion));
            ok = false;
          } else if (!currency.isConfidentialTransactionsActivated(tip)) {
            std::fprintf(stderr, "FAIL [%s]: CT not activated at tip height %u\n", current_test, tip);
            ok = false;
          } else {
            std::printf("  mined to height %u (v%d), CT active, confidential supply %llu\n",
                        tip, static_cast<int>(tipVersion),
                        static_cast<unsigned long long>(c.get_blockchain_storage().getConfidentialSupply()));
          }
        }
      }
    }

    c.deinit();
  }

  boost::system::error_code ec;
  boost::filesystem::remove_all(dataDir, ec);

  if (!ok) return false;
  PASS();
}

}  // namespace

int main() {
  std::printf("v3 Chain-Integration Tests (real Core, real PoW path)\n");
  std::printf("=====================================================\n\n");

  test_mine_through_ct_activation();

  std::printf("\n=====================================================\n");
  std::printf("Results: %d/%d passed\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
