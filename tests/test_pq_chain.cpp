// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// End-to-end integration test through the real Core/Blockchain:
//   * drives a synthetic chain across the v6 (PQ) activation using the V5+
//     yespower PoW harness (first real exercise of getBlockLongHash in tests);
//   * confirms a v2 TX_PQ routes through the live consensus dispatch
//     (Core::check_tx_semantic -> Blockchain::checkPqInputs) and is rejected
//     when it spends a non-existent output.
//
// NOTE: the funded happy-path lifecycle (bridge a coinbase -> spend via TX_PQ ->
// double-spend reject -> reorg-reinsert) additionally needs a ring-signed
// TX_BRIDGE builder (overlaps the wallet spend path); the PQ consensus crypto
// for it is already covered by PqValidationTests / PqNullifierDbTests.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqValidation.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"

#include "PqTxType.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <list>
#include <string>
#include <vector>

namespace {

bool expect(bool cond, const std::string& msg) {
  if (!cond) { std::cerr << "[FAIL] " << msg << std::endl; }
  return cond;
}

template <std::size_t N> std::array<uint8_t, N> pat(uint8_t a, uint8_t b) {
  std::array<uint8_t, N> r;
  for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(i * a + b);
  return r;
}
template <std::size_t N> std::vector<uint8_t> toVec(const std::array<uint8_t, N>& a) {
  return std::vector<uint8_t>(a.begin(), a.end());
}

// Mine one main-chain block at the major version expected for its height.
bool mineBlock(CryptoNote::Core& core, const CryptoNote::Currency& currency,
               test_generator& gen, const CryptoNote::AccountBase& miner,
               uint64_t timestamp) {
  uint32_t height = core.getCurrentBlockchainHeight();
  Crypto::Hash tail = core.get_tail_id();
  uint64_t generated = 0;
  if (!core.getAlreadyGeneratedCoins(tail, generated)) return false;
  std::vector<size_t> sizes;
  if (!core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow())) return false;

  // Block version must match what consensus expects at this height.
  gen.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);

  CryptoNote::Block blk;
  std::list<CryptoNote::Transaction> txs;
  if (!gen.constructBlock(blk, height, tail, miner, timestamp, generated, sizes, txs)) return false;

  CryptoNote::difficulty_type diff = core.getNextBlockDifficulty();
  if (diff > 1) {
    // Version-aware PoW search (yespower for v5+).
    fillNonce(blk, diff, &core.get_blockchain_storage());
  }
  gen.addBlock(blk, 0, 0, sizes, generated);

  CryptoNote::block_verification_context bvc{};
  core.handle_incoming_block(blk, bvc, false, false);
  return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
}

// An unfunded, well-formed, ML-DSA-signed TX_PQ that references a non-existent
// output (so it must be rejected at input resolution, not at shape).
CryptoNote::Transaction makeUnfundedPqTx() {
  using namespace CryptoNote;
  CryptoPQ::SeedMaster ms = pat<32>(2, 7);
  auto spend = CryptoPQ::deriveSpendKeys(ms);
  auto recipV = CryptoPQ::deriveViewKeys(pat<32>(3, 9));
  auto recipS = CryptoPQ::deriveSpendKeys(pat<32>(3, 9));

  PqInput in;
  in.prevTxid = Crypto::Hash{};                 // nonexistent outpoint
  for (size_t i = 0; i < 32; ++i) in.prevTxid.data[i] = static_cast<uint8_t>(i + 1);
  in.prevOutIndex = 0;
  in.authPub = toVec(spend.first);
  in.rhoReveal = toVec(pat<32>(3, 9));
  in.signature.assign(PQ_SIGNATURE_SIZE, 0);

  std::vector<CryptoPQ::InputRef> refs(1);
  std::memcpy(refs[0].prevTxid.data(), in.prevTxid.data, 32);
  refs[0].prevOutIndex = in.prevOutIndex;
  CryptoPQ::Hash256 ih = CryptoPQ::inputsHash(refs);

  CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(recipV.first, recipS.first, ih, 0, 500000);
  PqOutput po;
  po.kemCt = toVec(built.kemCt);
  po.encPayload = built.encPayload;
  std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);
  TransactionOutput out; out.amount = 500000; out.target = po;

  Transaction tx;
  tx.version = TRANSACTION_VERSION_PQ;
  tx.txType = TX_PQ;
  tx.unlockTime = 0;
  tx.inputs.push_back(in);
  tx.outputs.push_back(out);

  // Sign with the spender's ML-DSA key (digest fee = in - out; here arbitrary
  // since the tx is rejected before/at input resolution, but make it consistent).
  uint64_t fee = 0;  // sum(in)=sum(out) would be ideal but input is unresolved
  CryptoPQ::Hash256 d = pqSigningDigest(tx, fee);
  CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(spend.second, d.data(), d.size());
  boost::get<PqInput>(tx.inputs[0]).signature = toVec(sig);
  return tx;
}

bool run() {
  Logging::ConsoleLogger logger(Logging::ERROR);
  // Jump v1 -> v6 cleanly: all upgrade heights equal, so heights <= 5 are v1 and
  // heights >= 6 are v6 (the PQ activation version).
  const CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .upgradeHeightV2(5).upgradeHeightV3(5).upgradeHeightV4(5)
      .upgradeHeightV5(5).upgradeHeightV6(5)
      .currency();

  std::filesystem::path dataDir("pq_chain_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  CryptoNote::Core core(currency, nullptr, logger, dispatcher, 0, false);
  CryptoNote::CoreConfig coreConfig;
  coreConfig.configFolder = dataDir.string();
  CryptoNote::MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());  // enables v5+ yespower PoW

  CryptoNote::AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  CryptoNote::Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "load genesis")) { core.deinit(); return false; }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  // Mine across the v6 activation boundary (heights 1..10).
  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  for (int i = 0; i < 10; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "mine block " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += currency.difficultyTarget();
  }

  bool ok = true;
  uint32_t top = core.getCurrentBlockchainHeight() - 1;
  ok &= expect(core.getCurrentBlockchainHeight() == 11, "chain height == 11 (genesis + 10)");
  ok &= expect(core.getBlockMajorVersionForHeight(top) == CryptoNote::BLOCK_MAJOR_VERSION_6,
               "top block is v6 (PQ era active)");

  // v2 PQ dispatch through the live Core: an unfunded TX_PQ must be rejected.
  CryptoNote::Transaction pqTx = makeUnfundedPqTx();
  Crypto::Hash txHash = CryptoNote::getObjectHash(pqTx);
  CryptoNote::BinaryArray blob = CryptoNote::toBinaryArray(pqTx);
  CryptoNote::tx_verification_context tvc{};
  core.handleIncomingTransaction(pqTx, txHash, blob.size(), tvc, false,
                                 core.getCurrentBlockchainHeight());
  ok &= expect(!tvc.m_added_to_pool, "unfunded PQ tx not added to pool");
  ok &= expect(tvc.m_verification_failed, "unfunded PQ tx verification failed (dispatch fired)");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

}  // namespace

int main() {
  if (!run()) {
    std::cerr << "[FAIL] PQ chain integration test" << std::endl;
    return 1;
  }
  std::cout << "[PASS] PQ chain integration test" << std::endl;
  return 0;
}
