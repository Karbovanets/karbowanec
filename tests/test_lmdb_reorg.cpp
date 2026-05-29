#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"
#include "Wallet/TransactionBuilder.h"
#include "liblmdb/lmdb.h"

#include <ctime>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <list>
#include <memory>
#include <stdexcept>
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

#pragma pack(push, 1)
struct LegacyDbBlockMeta {
  uint8_t  hash[32];
  uint8_t  prevHash[32];
  uint64_t timestamp;
  uint64_t cumulativeDifficulty;
  uint64_t alreadyGeneratedCoins;
  uint32_t blockCumulativeSize;
  uint32_t height;
  uint16_t txCount;
  uint8_t  majorVersion;
  uint8_t  minorVersion;
};
#pragma pack(pop)
static_assert(sizeof(LegacyDbBlockMeta) == 100, "LegacyDbBlockMeta must be 100 bytes");

void encodeBE32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(value & 0xFF);
}

bool writeLegacyBlockMeta(const std::filesystem::path& dataDir, uint32_t height) {
  MDB_env* env = nullptr;
  MDB_txn* txn = nullptr;
  MDB_dbi blockMetaDbi = 0;

  int rc = mdb_env_create(&env);
  if (rc != 0) return false;

  rc = mdb_env_set_maxdbs(env, 16);
  if (rc == 0) rc = mdb_env_set_mapsize(env, size_t(1) << 20);
  if (rc == 0) rc = mdb_env_open(env, dataDir.string().c_str(), MDB_NORDAHEAD, 0664);
  if (rc == 0) rc = mdb_txn_begin(env, nullptr, 0, &txn);
  if (rc == 0) rc = mdb_dbi_open(txn, "block_meta", MDB_CREATE, &blockMetaDbi);

  LegacyDbBlockMeta legacy{};
  for (size_t i = 0; i < sizeof(legacy.hash); ++i) {
    legacy.hash[i] = static_cast<uint8_t>(i + 1);
    legacy.prevHash[i] = static_cast<uint8_t>(0xF0 - i);
  }
  legacy.timestamp = 123456;
  legacy.cumulativeDifficulty = 789;
  legacy.alreadyGeneratedCoins = 456;
  legacy.blockCumulativeSize = 321;
  legacy.height = height;
  legacy.txCount = 2;
  legacy.majorVersion = CryptoNote::BLOCK_MAJOR_VERSION_1;
  legacy.minorVersion = CryptoNote::BLOCK_MINOR_VERSION_0;

  uint8_t keyBuf[4];
  encodeBE32(keyBuf, height);
  MDB_val key{sizeof(keyBuf), keyBuf};
  MDB_val value{sizeof(legacy), &legacy};
  if (rc == 0) rc = mdb_put(txn, blockMetaDbi, &key, &value, 0);

  if (rc == 0) {
    rc = mdb_txn_commit(txn);
    txn = nullptr;
  }

  if (txn != nullptr) {
    mdb_txn_abort(txn);
  }
  if (env != nullptr) {
    mdb_env_close(env);
  }

  return rc == 0;
}

bool runLegacyMetaReadScenario() {
  const std::filesystem::path dataDir =
      std::filesystem::path("lmdb_legacy_meta_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);
  if (ec) {
    std::cerr << "[FAIL] could not create legacy metadata test directory: " << ec.message() << std::endl;
    return false;
  }

  constexpr uint32_t legacyHeight = 60000;
  if (!expect(writeLegacyBlockMeta(dataDir, legacyHeight), "failed to write legacy block_meta record")) {
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  CryptoNote::LMDBBlockchainDB db;
  if (!expect(db.open(dataDir.string()), "failed to open legacy metadata DB")) {
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  CryptoNote::DbBlockMeta meta{};
  if (!expect(db.getBlockMeta(legacyHeight, meta), "failed to decode legacy block_meta record")) {
    db.close();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(meta.height == legacyHeight, "legacy block_meta height mismatch") ||
      !expect(meta.majorVersion == CryptoNote::BLOCK_MAJOR_VERSION_1, "legacy block_meta major version mismatch") ||
      !expect(meta.minorVersion == CryptoNote::BLOCK_MINOR_VERSION_0, "legacy block_meta minor version mismatch") ||
      !expect(meta.confidentialSupply == 0, "legacy block_meta confidential supply should default to zero") ||
      !expect(meta.pqPlainSupply == 0, "legacy block_meta PQ plain supply should default to zero")) {
    db.close();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  std::vector<CryptoNote::DbBlockMeta> metas;
  if (!expect(db.getBlockMetaRange(legacyHeight, legacyHeight, metas), "failed to range-read legacy block_meta record") ||
      !expect(metas.size() == 1, "legacy block_meta range read returned wrong count") ||
      !expect(metas.front().majorVersion == CryptoNote::BLOCK_MAJOR_VERSION_1, "legacy block_meta range major version mismatch")) {
    db.close();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  db.close();
  std::filesystem::remove_all(dataDir, ec);
  return true;
}

bool submitBlock(CryptoNote::Core& core,
                 const CryptoNote::Block& block,
                 bool expectMainChain,
                 bool expectSwitchToAlt,
                 const std::string& label) {
  CryptoNote::block_verification_context bvc{};
  core.handle_incoming_block(block, bvc, false, false);

  if (!expect(!bvc.m_verification_failed, label + ": verification failed")) return false;
  if (!expect(!bvc.m_marked_as_orphaned, label + ": block marked as orphan")) return false;
  if (!expect(bvc.m_added_to_main_chain == expectMainChain, label + ": unexpected m_added_to_main_chain")) return false;
  if (!expect(bvc.m_switched_to_alt_chain == expectSwitchToAlt, label + ": unexpected m_switched_to_alt_chain")) return false;
  return true;
}

bool buildMainBlock(CryptoNote::Core& core,
                    const CryptoNote::Currency& currency,
                    test_generator& generator,
                    const CryptoNote::AccountBase& miner,
                    uint64_t timestamp,
                    CryptoNote::Block& out) {
  uint32_t chainHeight = core.getCurrentBlockchainHeight();
  Crypto::Hash tailHash = core.get_tail_id();

  uint64_t alreadyGenerated = 0;
  if (!core.getAlreadyGeneratedCoins(tailHash, alreadyGenerated)) {
    return false;
  }

  std::vector<size_t> blockSizes;
  if (!core.getBackwardBlocksSizes(chainHeight - 1, blockSizes, currency.rewardBlocksWindow())) {
    return false;
  }

  std::list<CryptoNote::Transaction> txList;
  if (!generator.constructBlock(out, chainHeight, tailHash, miner, timestamp,
                                alreadyGenerated, blockSizes, txList)) {
    return false;
  }

  const CryptoNote::difficulty_type difficulty = core.getNextBlockDifficulty();
  if (difficulty > 1) {
    fillNonce(out, difficulty);
  }

  // Re-index with the final hash (constructBlock() indexed an internal nonce variant).
  generator.addBlock(out, 0, 0, blockSizes, alreadyGenerated);
  return true;
}

bool buildAlternativeBlock(CryptoNote::Core& core,
                           const CryptoNote::Currency& currency,
                           test_generator& generator,
                           const CryptoNote::AccountBase& miner,
                           const CryptoNote::Block& prev,
                           CryptoNote::Block& out) {
  const Crypto::Hash prevHash = get_block_hash(prev);
  const uint32_t nextHeight = get_block_height(prev) + 1;
  const uint64_t timestamp = prev.timestamp + currency.difficultyTarget();

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

  std::list<CryptoNote::Transaction> txList;
  if (!generator.constructBlock(out, nextHeight, prevHash, miner, timestamp,
                                alreadyGenerated, blockSizes, txList)) {
    return false;
  }

  const CryptoNote::difficulty_type difficulty =
      core.get_blockchain_storage().getDifficultyForNextBlock(prevHash);
  if (difficulty > 1) {
    fillNonce(out, difficulty);
  }

  // Re-index with the final hash (constructBlock() indexed an internal nonce variant).
  generator.addBlock(out, 0, 0, blockSizes, alreadyGenerated);
  return true;
}

bool runReorgScenario() {
  Logging::ConsoleLogger logger;
  const CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).currency();

  const std::filesystem::path dataDir =
      std::filesystem::path("lmdb_reorg_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);
  if (ec) {
    std::cerr << "[FAIL] could not create data directory: " << ec.message() << std::endl;
    return false;
  }

  System::Dispatcher dispatcher;
  CryptoNote::Core core(currency, nullptr, logger, dispatcher, 0, false);
  CryptoNote::CoreConfig coreConfig;
  coreConfig.configFolder = dataDir.string();
  CryptoNote::MinerConfig minerConfig;

  if (!expect(core.init(coreConfig, minerConfig, false), "core.init failed")) {
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  test_generator generator(currency);
  CryptoNote::AccountBase miner;
  miner.generate();

  std::vector<CryptoNote::Block> mainChain;
  mainChain.reserve(16);

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  CryptoNote::Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "failed to load genesis block")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  // Seed generator metadata with genesis so backward-size walks from forks work.
  std::vector<size_t> emptySizes;
  generator.addBlock(genesis, 0, 0, emptySizes, 0);
  mainChain.push_back(genesis);

  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  const uint64_t startTimestamp = now - 24 * 60 * 60; // keep synthetic chain well behind wall clock
  for (size_t i = 0; i < 15; ++i) {
    CryptoNote::Block block;
    const uint64_t timestamp = (i == 0) ? startTimestamp : (mainChain.back().timestamp + currency.difficultyTarget());
    if (!expect(buildMainBlock(core, currency, generator, miner, timestamp, block),
                "failed to construct main-chain block")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }

    if (!expect(submitBlock(core, block, true, false, "submit main block"),
                "main block submit checks failed")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }

    mainChain.push_back(block);
  }

  if (!expect(core.getCurrentBlockchainHeight() == 16, "unexpected main chain height after growth")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  const Crypto::Hash oldMainTipHash = get_block_hash(mainChain.back());
  const Crypto::Hash oldMainTipCoinbase = getObjectHash(mainChain.back().baseTransaction);

  const CryptoNote::Block forkBase = mainChain[9]; // height 9
  CryptoNote::Block altPrev = forkBase;
  std::vector<CryptoNote::Block> altChain;
  altChain.reserve(7);

  for (size_t i = 0; i < 7; ++i) {
    CryptoNote::Block altBlock;
    if (!expect(buildAlternativeBlock(core, currency, generator, miner, altPrev, altBlock),
                "failed to construct alt-chain block")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }

    const bool shouldSwitch = (i == 6);
    if (!expect(submitBlock(core, altBlock, shouldSwitch, shouldSwitch, "submit alt block"),
                "alt block submit checks failed")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }

    altChain.push_back(altBlock);
    altPrev = altBlock;
  }

  uint32_t topHeight = 0;
  Crypto::Hash topHash = Crypto::Hash();
  core.get_blockchain_top(topHeight, topHash);

  const Crypto::Hash newMainTipHash = get_block_hash(altChain.back());
  const Crypto::Hash newMainTipCoinbase = getObjectHash(altChain.back().baseTransaction);

  if (!expect(core.getCurrentBlockchainHeight() == 17, "unexpected height after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(topHeight == 16, "unexpected top height after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(topHash == newMainTipHash, "unexpected top hash after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(core.getBlockIdByHeight(16) == newMainTipHash, "main-chain tip id lookup mismatch")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(core.getBlockIdByHeight(15) != oldMainTipHash, "old main tip still visible at height 15")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  Crypto::Hash locatedBlock = Crypto::Hash();
  uint32_t locatedHeight = 0;
  if (!expect(!core.getBlockContainingTx(oldMainTipCoinbase, locatedBlock, locatedHeight),
              "old-branch coinbase is still indexed as main-chain tx")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(core.getBlockContainingTx(newMainTipCoinbase, locatedBlock, locatedHeight),
              "new main tip coinbase is missing from tx index")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(locatedBlock == newMainTipHash && locatedHeight == 16,
              "new main tip coinbase resolved to wrong block")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  core.rollbackBlockchain(9);
  core.get_blockchain_top(topHeight, topHash);

  const Crypto::Hash expectedRollbackTip = get_block_hash(mainChain[9]);
  if (!expect(core.getCurrentBlockchainHeight() == 10, "unexpected height after rollback")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(topHeight == 9 && topHash == expectedRollbackTip, "rollback tip mismatch")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(!core.getBlockContainingTx(newMainTipCoinbase, locatedBlock, locatedHeight),
              "alt-branch coinbase is still indexed after rollback")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return true;
}

// ─── Reorg with mid-flight mempool eviction ─────────────────────────────────
//
// Regression test for the alt-chain snapshot fix
// (commit "Snapshot alt-block txs so CT reorg is self-contained").
//
// The bug class: handle_alternative_block used to store only the Block header
// in BlockEntry, and switch_to_alternative_blockchain replayed alt blocks via
// pushBlock(b, hash, bvc) → loadTransactions() → take_tx, which looks the tx
// bodies up by hash in the local mempool. If the pool churned between alt-block
// acceptance and the eventual reorg (TTL eviction, mined-block clearance,
// restart), a valid non-coinbase alt chain would fail to switch in.
//
// This scenario covers the regression with a v1 plain transparent spend tx.
// The snapshot codepath in handle_alternative_block / switch_to_alternative_
// blockchain / pushBlock(b, txs, hash, bvc) is bit-identical for v1 plain and
// v2 CT transactions — the snapshot stores Transaction objects whose ctProofs
// and signatures variants live inside the same serialized blob. A CT-version
// of this test would additionally exercise the CT proof validators downstream;
// see test_ct_integration for that coverage. CT-specific structural rules are
// independent of the snapshot mechanism itself.
//
// Flow:
//   1. Build main chain past the coinbase unlock window so block 1's coinbase
//      output is mature.
//   2. Construct a v1 spend that consumes that coinbase output, send it to a
//      different account. Add it to the mempool via handle_incoming_tx.
//   3. Fork at height N, where N is before the height containing the spent
//      coinbase. (Actually we fork well after — but the spent coinbase is from
//      *before* the fork point so it exists on both chains.)
//   4. Build alt block at fork+1 *embedding the spend tx*. Submit it via
//      handle_incoming_block. This is the moment handle_alternative_block
//      snapshots the tx into BlockEntry.transactions.
//   5. *** Evict the spend tx from the mempool. *** This is what the fix
//      protects against — pool churn between alt acceptance and reorg.
//   6. Build remaining alt blocks (coinbase-only) until cumulative difficulty
//      wins and the reorg fires.
//   7. The final alt block triggers switch_to_alternative_blockchain. Without
//      the fix, loadTransactions would call take_tx for the spend hash, fail
//      (evicted), and the entire reorg would be rolled back. With the fix,
//      the snapshot is replayed from BlockEntry.transactions and the reorg
//      succeeds.

// Submit an already-built transaction to the core mempool. Returns true on
// successful admission, false otherwise.
bool submitTxToPool(CryptoNote::Core& core, const CryptoNote::Transaction& tx) {
  CryptoNote::tx_verification_context tvc{};
  CryptoNote::BinaryArray txBlob;
  if (!CryptoNote::toBinaryArray(tx, txBlob)) return false;
  // handle_incoming_tx is the legacy entry point but it's still wired and is
  // exactly what a peer-relayed tx hits before the block-import path runs.
  if (!core.handle_incoming_tx(txBlob, tvc, /*keeped_by_block=*/false)) return false;
  return tvc.m_added_to_pool;
}

// Build a v1 plain transparent spend that consumes all KeyOutput outputs of a
// coinbase transaction. The coinbase is block-1's reward, which is mature once
// the main chain has grown past the unlock window. Sends (totalAmount - fee)
// to `receiver`.
//
// The coinbase may have multiple outputs due to digit decomposition (maxOuts=10
// in test_generator::constructBlock). We build one no-mixin TxBuildInput per
// output — each has a ring of size 1 containing only the real spend target.
bool buildSpendOfBlock1Coinbase(CryptoNote::Core& core,
                                const CryptoNote::Currency& currency,
                                const CryptoNote::Block& block1,
                                const CryptoNote::AccountBase& miner,
                                const CryptoNote::AccountBase& receiver,
                                CryptoNote::Transaction& outTx) {
  const Crypto::Hash coinbaseHash = CryptoNote::getObjectHash(block1.baseTransaction);
  const Crypto::PublicKey coinbaseTxPubKey =
      CryptoNote::getTransactionPublicKeyFromExtra(block1.baseTransaction.extra);

  // get_tx_outputs_gindexs returns one global index per output, each index
  // into that output's per-amount bucket. Parallel array to baseTransaction.outputs.
  std::vector<uint32_t> globalIndexes;
  if (!core.get_tx_outputs_gindexs(coinbaseHash, globalIndexes)) return false;
  if (globalIndexes.size() != block1.baseTransaction.outputs.size()) return false;
  if (globalIndexes.empty()) return false;

  // Build one input descriptor per KeyOutput in the coinbase. Each input has
  // a ring of size 1 (no decoys). Ring size 1 (mixin=0) is always allowed by
  // check_tx_mixin: the txMixin==1 exception bypasses the minimum-mixin gate.
  uint64_t totalAmount = 0;
  std::vector<CryptoNote::TxBuildInput> sources;
  for (size_t i = 0; i < block1.baseTransaction.outputs.size(); ++i) {
    const auto& txOut = block1.baseTransaction.outputs[i];
    if (txOut.target.type() != typeid(CryptoNote::KeyOutput)) continue;

    const Crypto::PublicKey targetKey =
        boost::get<CryptoNote::KeyOutput>(txOut.target).key;

    CryptoNote::TxBuildInput src;
    src.keyInfo.amount = txOut.amount;
    // Ring has one member: the real output itself (no decoys).
    src.keyInfo.outputs.push_back(
        CryptoNote::TransactionTypes::GlobalOutput{targetKey, globalIndexes[i]});
    // realOutput.transactionIndex: index into keyInfo.outputs of the real member.
    // Always 0 here since the ring has only one member.
    src.keyInfo.realOutput.transactionPublicKey = coinbaseTxPubKey;
    src.keyInfo.realOutput.transactionIndex    = 0;
    // realOutput.outputInTransaction: slot index inside the coinbase tx. This
    // drives generate_key_image_helper's derive_secret_key call, which must
    // match the derivation index used when the coinbase output was created.
    src.keyInfo.realOutput.outputInTransaction = static_cast<uint32_t>(i);
    src.senderKeys = miner.getAccountKeys();

    sources.push_back(std::move(src));
    totalAmount += txOut.amount;
  }

  if (sources.empty()) return false;
  const uint64_t fee = currency.minimumFee();
  if (totalAmount <= fee) return false;
  const uint64_t sendAmount = totalAmount - fee;

  std::vector<CryptoNote::TxBuildOutput> destinations(1);
  destinations[0].destination = receiver.getAccountKeys().address;
  destinations[0].amount      = sendAmount;

  Crypto::SecretKey txSecretKey;
  try {
    auto itx = CryptoNote::buildTransaction(sources, destinations,
                                            miner.getAccountKeys().viewSecretKey,
                                            /*extra=*/"", /*unlockTimestamp=*/0,
                                            /*sizeLimit=*/0, txSecretKey);
    return CryptoNote::fromBinaryArray(outTx, itx->getTransactionData());
  } catch (const std::exception& e) {
    std::cerr << "[FAIL] buildSpendOfBlock1Coinbase: buildTransaction threw: "
              << e.what() << std::endl;
    return false;
  }
}

bool buildAlternativeBlockWithTxs(CryptoNote::Core& core,
                                  const CryptoNote::Currency& currency,
                                  test_generator& generator,
                                  const CryptoNote::AccountBase& miner,
                                  const CryptoNote::Block& prev,
                                  const std::list<CryptoNote::Transaction>& embeddedTxs,
                                  CryptoNote::Block& out) {
  const Crypto::Hash prevHash = get_block_hash(prev);
  const uint32_t nextHeight = get_block_height(prev) + 1;
  const uint64_t timestamp = prev.timestamp + currency.difficultyTarget();

  uint64_t alreadyGenerated = 0;
  try { alreadyGenerated = generator.getAlreadyGeneratedCoins(prevHash); }
  catch (const std::exception&) { return false; }

  std::vector<size_t> blockSizes;
  try { generator.getLastNBlockSizes(blockSizes, prevHash, currency.rewardBlocksWindow()); }
  catch (const std::exception&) { return false; }

  if (!generator.constructBlock(out, nextHeight, prevHash, miner, timestamp,
                                alreadyGenerated, blockSizes, embeddedTxs)) {
    return false;
  }

  const CryptoNote::difficulty_type difficulty =
      core.get_blockchain_storage().getDifficultyForNextBlock(prevHash);
  if (difficulty > 1) {
    fillNonce(out, difficulty);
  }

  generator.addBlock(out, 0, 0, blockSizes, alreadyGenerated);
  return true;
}

bool buildMainBlockWithTxs(CryptoNote::Core& core,
                           const CryptoNote::Currency& currency,
                           test_generator& generator,
                           const CryptoNote::AccountBase& miner,
                           uint64_t timestamp,
                           const std::list<CryptoNote::Transaction>& embeddedTxs,
                           CryptoNote::Block& out) {
  uint32_t chainHeight = core.getCurrentBlockchainHeight();
  Crypto::Hash tailHash = core.get_tail_id();

  uint64_t alreadyGenerated = 0;
  if (!core.getAlreadyGeneratedCoins(tailHash, alreadyGenerated)) return false;

  std::vector<size_t> blockSizes;
  if (!core.getBackwardBlocksSizes(chainHeight - 1, blockSizes,
                                   currency.rewardBlocksWindow())) {
    return false;
  }

  if (!generator.constructBlock(out, chainHeight, tailHash, miner, timestamp,
                                alreadyGenerated, blockSizes, embeddedTxs)) {
    return false;
  }

  const CryptoNote::difficulty_type difficulty = core.getNextBlockDifficulty();
  if (difficulty > 1) {
    fillNonce(out, difficulty);
  }

  generator.addBlock(out, 0, 0, blockSizes, alreadyGenerated);
  return true;
}

bool runReorgWithTxEvictionScenario() {
  Logging::ConsoleLogger logger;
  const CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).currency();

  const std::filesystem::path dataDir =
      std::filesystem::path("lmdb_reorg_txevict_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);
  if (ec) {
    std::cerr << "[FAIL] could not create txevict data directory: " << ec.message() << std::endl;
    return false;
  }

  System::Dispatcher dispatcher;
  CryptoNote::Core core(currency, nullptr, logger, dispatcher, 0, false);
  CryptoNote::CoreConfig coreConfig;
  coreConfig.configFolder = dataDir.string();
  CryptoNote::MinerConfig minerConfig;

  if (!expect(core.init(coreConfig, minerConfig, false), "txevict core.init failed")) {
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  test_generator generator(currency);
  CryptoNote::AccountBase miner;
  miner.generate();
  CryptoNote::AccountBase receiver;
  receiver.generate();

  std::vector<CryptoNote::Block> mainChain;
  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  CryptoNote::Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "txevict: failed to load genesis")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  std::vector<size_t> emptySizes;
  generator.addBlock(genesis, 0, 0, emptySizes, 0);
  mainChain.push_back(genesis);

  // Grow main chain to enough height that block 1's coinbase is mature.
  // unlockWindow defaults to 10; growing to 16 leaves a 14-block margin.
  const size_t totalMainBlocks = currency.minedMoneyUnlockWindow() + 6;
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  const uint64_t startTimestamp = now - 24 * 60 * 60;
  for (size_t i = 0; i < totalMainBlocks; ++i) {
    CryptoNote::Block block;
    const uint64_t timestamp = (i == 0)
        ? startTimestamp
        : (mainChain.back().timestamp + currency.difficultyTarget());
    if (!expect(buildMainBlock(core, currency, generator, miner, timestamp, block),
                "txevict: failed to construct main-chain block")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }
    if (!expect(submitBlock(core, block, true, false, "txevict: submit main block"),
                "txevict: main block submit checks failed")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }
    mainChain.push_back(block);
  }

  // Block 1's coinbase is now well past the unlock window. Build the spend tx.
  const CryptoNote::Block& block1 = mainChain[1];
  CryptoNote::Transaction spendTx;
  if (!expect(buildSpendOfBlock1Coinbase(core, currency, block1, miner, receiver, spendTx),
              "txevict: failed to build spend tx for block-1 coinbase")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  const Crypto::Hash spendTxHash = CryptoNote::getObjectHash(spendTx);

  // Admit the spend tx to the mempool, exactly as a peer relay would.
  if (!expect(submitTxToPool(core, spendTx),
              "txevict: failed to admit spend tx to mempool")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  // Fork at height (totalMainBlocks - 3). Build seven alt blocks total; the
  // FIRST alt block carries the spend tx, the rest are coinbase-only. The
  // alt chain needs enough cumulative difficulty to win — with all blocks at
  // difficulty 1, an alt chain 1 block longer than main suffices.
  const size_t forkAt = totalMainBlocks - 3;   // mainChain[forkAt] is the last shared block
  const size_t totalAltBlocks = (mainChain.size() - 1 - forkAt) + 1;  // win by 1
  std::vector<CryptoNote::Block> altChain;
  CryptoNote::Block altPrev = mainChain[forkAt];

  for (size_t i = 0; i < totalAltBlocks; ++i) {
    CryptoNote::Block altBlock;
    std::list<CryptoNote::Transaction> embedded;
    if (i == 0) {
      // Embed the spend tx in the first alt block. The pool currently holds
      // a copy; handle_alternative_block will snapshot it into BlockEntry.
      embedded.push_back(spendTx);
    }
    if (!expect(buildAlternativeBlockWithTxs(core, currency, generator, miner,
                                             altPrev, embedded, altBlock),
                "txevict: failed to construct alt block")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }

    const bool shouldSwitch = (i + 1 == totalAltBlocks);
    if (!expect(submitBlock(core, altBlock, shouldSwitch, shouldSwitch,
                            "txevict: submit alt block"),
                "txevict: alt block submit checks failed")) {
      core.deinit();
      std::filesystem::remove_all(dataDir, ec);
      return false;
    }

    altChain.push_back(altBlock);
    altPrev = altBlock;

    if (i == 0) {
      // *** The crux of the regression test ***
      // The alt block carrying the spend has been accepted; the snapshot now
      // lives in BlockEntry::transactions. Evict the body from the mempool to
      // simulate TTL/restart/mined-block churn before the reorg fires. The
      // remaining alt blocks must still trigger a successful switch despite
      // the pool no longer holding the body.
      CryptoNote::Transaction discarded;
      size_t discardedSize = 0;
      uint64_t discardedFee = 0;
      if (!expect(core.getMempool().take_tx(spendTxHash, discarded,
                                                    discardedSize, discardedFee),
                  "txevict: expected spend tx to still be in pool here")) {
        core.deinit();
        std::filesystem::remove_all(dataDir, ec);
        return false;
      }
    }
  }

  // Verify the switch occurred and the new tip is the alt chain's last block.
  const Crypto::Hash newTipHash = get_block_hash(altChain.back());
  const uint32_t expectedHeight = static_cast<uint32_t>(forkAt + totalAltBlocks + 1);
  if (!expect(core.getCurrentBlockchainHeight() == expectedHeight,
              "txevict: unexpected height after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(core.getBlockIdByHeight(expectedHeight - 1) == newTipHash,
              "txevict: top hash mismatch after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  // The spend tx must be indexed as part of the new main chain. This proves
  // the replay used the snapshot (since the pool no longer held the body).
  Crypto::Hash spendContainingBlock{};
  uint32_t spendContainingHeight = 0;
  if (!expect(core.getBlockContainingTx(spendTxHash, spendContainingBlock, spendContainingHeight),
              "txevict: spend tx not indexed after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }
  if (!expect(spendContainingBlock == get_block_hash(altChain.front()),
              "txevict: spend tx resolved to wrong block after reorg")) {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return true;
}

bool runReorgWithTxAlreadyInMainChainScenario() {
  Logging::ConsoleLogger logger;
  const CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).currency();

  const std::filesystem::path dataDir =
      std::filesystem::path("lmdb_reorg_overlap_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);
  if (ec) {
    std::cerr << "[FAIL] could not create overlap data directory: "
              << ec.message() << std::endl;
    return false;
  }

  System::Dispatcher dispatcher;
  CryptoNote::Core core(currency, nullptr, logger, dispatcher, 0, false);
  CryptoNote::CoreConfig coreConfig;
  coreConfig.configFolder = dataDir.string();
  CryptoNote::MinerConfig minerConfig;

  if (!expect(core.init(coreConfig, minerConfig, false),
              "overlap: core.init failed")) {
    std::filesystem::remove_all(dataDir, ec);
    return false;
  }

  auto cleanup = [&]() {
    core.deinit();
    std::filesystem::remove_all(dataDir, ec);
  };

  test_generator generator(currency);
  CryptoNote::AccountBase miner;
  miner.generate();
  CryptoNote::AccountBase receiver;
  receiver.generate();

  std::vector<CryptoNote::Block> mainChain;
  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  CryptoNote::Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis),
              "overlap: failed to load genesis")) {
    cleanup();
    return false;
  }

  std::vector<size_t> emptySizes;
  generator.addBlock(genesis, 0, 0, emptySizes, 0);
  mainChain.push_back(genesis);

  const size_t totalMainBlocks = currency.minedMoneyUnlockWindow() + 6;
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  const uint64_t startTimestamp = now - 24 * 60 * 60;
  for (size_t i = 0; i < totalMainBlocks; ++i) {
    CryptoNote::Block block;
    const uint64_t timestamp = (i == 0)
        ? startTimestamp
        : (mainChain.back().timestamp + currency.difficultyTarget());
    if (!expect(buildMainBlock(core, currency, generator, miner, timestamp, block),
                "overlap: failed to construct main-chain block")) {
      cleanup();
      return false;
    }
    if (!expect(submitBlock(core, block, true, false, "overlap: submit main block"),
                "overlap: main block submit checks failed")) {
      cleanup();
      return false;
    }
    mainChain.push_back(block);
  }

  const CryptoNote::Block forkBase = mainChain.back();
  const uint32_t forkHeight = get_block_height(forkBase);

  CryptoNote::Transaction spendTx;
  if (!expect(buildSpendOfBlock1Coinbase(core, currency, mainChain[1], miner,
                                         receiver, spendTx),
              "overlap: failed to build spend tx")) {
    cleanup();
    return false;
  }
  const Crypto::Hash spendTxHash = CryptoNote::getObjectHash(spendTx);

  if (!expect(submitTxToPool(core, spendTx),
              "overlap: failed to admit spend tx to mempool")) {
    cleanup();
    return false;
  }

  std::list<CryptoNote::Transaction> embedded{spendTx};
  CryptoNote::Block mainSpendBlock;
  if (!expect(buildMainBlockWithTxs(core, currency, generator, miner,
                                    forkBase.timestamp + currency.difficultyTarget(),
                                    embedded, mainSpendBlock),
              "overlap: failed to build main spend block")) {
    cleanup();
    return false;
  }
  if (!expect(submitBlock(core, mainSpendBlock, true, false,
                          "overlap: submit main spend block"),
              "overlap: main spend block submit checks failed")) {
    cleanup();
    return false;
  }

  CryptoNote::Transaction poolCopy;
  if (!expect(!core.getMempool().getTransaction(spendTxHash, poolCopy),
              "overlap: spend tx unexpectedly remained in pool after main mining")) {
    cleanup();
    return false;
  }

  CryptoNote::Block altSpendBlock;
  if (!expect(buildAlternativeBlockWithTxs(core, currency, generator, miner,
                                           forkBase, embedded, altSpendBlock),
              "overlap: failed to build alt spend block")) {
    cleanup();
    return false;
  }
  if (!expect(submitBlock(core, altSpendBlock, false, false,
                          "overlap: submit alt spend block"),
              "overlap: alt spend block submit checks failed")) {
    cleanup();
    return false;
  }

  CryptoNote::Block altWinningBlock;
  std::list<CryptoNote::Transaction> noTxs;
  if (!expect(buildAlternativeBlockWithTxs(core, currency, generator, miner,
                                           altSpendBlock, noTxs, altWinningBlock),
              "overlap: failed to build winning alt block")) {
    cleanup();
    return false;
  }
  if (!expect(submitBlock(core, altWinningBlock, true, true,
                          "overlap: submit winning alt block"),
              "overlap: winning alt block submit checks failed")) {
    cleanup();
    return false;
  }

  const uint32_t expectedHeight = forkHeight + 3;
  if (!expect(core.getCurrentBlockchainHeight() == expectedHeight,
              "overlap: unexpected height after reorg")) {
    cleanup();
    return false;
  }
  if (!expect(core.getBlockIdByHeight(expectedHeight - 1) == get_block_hash(altWinningBlock),
              "overlap: top hash mismatch after reorg")) {
    cleanup();
    return false;
  }

  Crypto::Hash containingBlock{};
  uint32_t containingHeight = 0;
  if (!expect(core.getBlockContainingTx(spendTxHash, containingBlock, containingHeight),
              "overlap: spend tx not indexed after reorg")) {
    cleanup();
    return false;
  }
  if (!expect(containingBlock == get_block_hash(altSpendBlock) &&
              containingHeight == forkHeight + 1,
              "overlap: spend tx resolved to wrong block after reorg")) {
    cleanup();
    return false;
  }

  cleanup();
  return true;
}

} // namespace

int main() {
  if (!runLegacyMetaReadScenario()) {
    return 1;
  }

  if (!runReorgScenario()) {
    return 1;
  }

  if (!runReorgWithTxEvictionScenario()) {
    return 1;
  }

  if (!runReorgWithTxAlreadyInMainChainScenario()) {
    return 1;
  }

  std::cout << "[PASS] LMDB legacy metadata and reorg scenarios" << std::endl;
  return 0;
}
