// v2 CT + v3 CT->CN unshield — chain-integration harness (real Core, real PoW path).
//
// Stands up a real `Core` on a testnet Currency with low hard-fork heights,
// mines a chain through CT activation (block-major v6) via the production
// block-accept path, then constructs REAL confidential transactions with the
// shared wallet builder (buildConfidentialTransaction) and submits them through
// handle_incoming_tx — exercising mempool admission (check_tx_semantic, incl.
// the GK-proof-count rule) and full CT validation (checkConfidentialTransaction:
// balance kernel, GK proofs, Triptych/transparent input handling).
//
// Coverage:
//   * mine v1->v4->v5->v6 with real PoW (validates the low-height testnet
//     difficulty fixes end to end);
//   * v2 CT shield: transparent coinbase KeyInput -> all-confidential outputs;
//   * v3 unshield: transparent coinbase KeyInput -> mixed outputs (one
//     ConfidentialOutput + one transparent KeyOutput). The transparent output
//     carries no GK proof, so this is exactly the shape the mempool GK-proof
//     count must accept for v3 (regression for the Core.cpp ctProofs rule).
//
// Inputs are funded from mature COINBASE outputs (transparent, ring size 1), so
// no confidential decoy/mixin assembly is needed — the focus is the CT output
// side and the consensus admission path.
//
// Blocks are mined at difficulty 1 (nonce search skipped; the core still
// computes/validates the real longhash). v2/v3 forks are skipped (v2==v3==v4
// upgrade height) to avoid merge-mining; v5+ blocks are signed (Miner.cpp).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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
#include "CryptoNoteCore/VerificationContext.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"

#include "Wallet/TransactionBuilder.h"
#include "Denominations.h"

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/transaction_balance.h"

#include "TestGenerator/TestGenerator.h"

using namespace CryptoNote;

namespace {

int tests_run = 0, tests_passed = 0;
const char* current_test = "";

#define TEST(name) do { current_test = (name); ++tests_run; } while (0)
#define REQUIRE(cond, msg) do { if (!(cond)) { std::fprintf(stderr, "FAIL [%s]: %s\n", current_test, (msg)); return false; } } while (0)
#define PASS() do { ++tests_passed; std::printf("  %-66s [PASS]\n", current_test); return true; } while (0)

// v2==v3==v4 collapses the merge-mined ranges to empty (chain goes v1->v4->v5->v6,
// all simple hashing-blob PoW). v5 sits above the unlock window + 1.
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

// v5+ "signed proof-of-work": sign cn_fast_hash(hashing blob) with the coinbase
// output[0] one-time secret (mirrors Miner.cpp). No-op below v5.
void signBlockIfNeeded(Block& blk, const AccountKeys& minerKeys) {
  if (blk.majorVersion < BLOCK_MAJOR_VERSION_5) return;
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

// Build a confidential tx funded by a mature transparent coinbase (ring size 1).
// wantV3 == false: all-confidential outputs (v2 CT shield).
// wantV3 == true : one ConfidentialOutput + one transparent KeyOutput (v3).
bool buildCtTxFromCoinbase(Core& c, const AccountBase& miner, const Block& coinbaseBlock,
                           bool wantV3, Transaction& outTx, std::string& err) {
  const AccountKeys& mk = miner.getAccountKeys();
  const Transaction& cb = coinbaseBlock.baseTransaction;
  if (cb.outputs.empty() || cb.outputs[0].target.type() != typeid(KeyOutput)) {
    err = "coinbase has no KeyOutput[0]"; return false;
  }
  const uint64_t inAmount = cb.outputs[0].amount;

  Crypto::Hash cbHash = getObjectHash(cb);
  std::vector<uint32_t> gindexs;
  if (!c.get_tx_outputs_gindexs(cbHash, gindexs) || gindexs.empty()) {
    err = "get_tx_outputs_gindexs failed"; return false;
  }

  // Derive the coinbase output[0] one-time spend key.
  Crypto::PublicKey txPub = getTransactionPublicKeyFromExtra(cb.extra);
  KeyPair eph; Crypto::KeyImage ki;
  if (!generate_key_image_helper(mk, txPub, 0, eph, ki)) { err = "key_image_helper"; return false; }
  if (eph.publicKey != boost::get<KeyOutput>(cb.outputs[0].target).key) {
    err = "ephemeral pubkey mismatch (coinbase not ours?)"; return false;
  }

  CTBuildRingMember rm;
  rm.amount = inAmount;
  rm.outputIndex = gindexs[0];
  rm.pubkey = boost::get<KeyOutput>(cb.outputs[0].target).key;
  if (!Crypto::transparent_amount_to_commitment(inAmount, rm.commitment)) { err = "commitment"; return false; }

  CTBuildInput in;
  in.ringMembers = { rm };
  in.realIndex = 0;
  in.spendPrivkey = eph.secretKey;
  std::memset(&in.realBlinding, 0, sizeof(in.realBlinding));  // transparent: zero blinding
  in.amount = inAmount;
  in.isTransparent = true;
  std::vector<CTBuildInput> inputs = { in };

  const uint64_t MIN = MIN_CT_DENOMINATION;  // == CT_MINIMUM_FEE (0.01 KRB)
  std::vector<CTBuildOutput> outputs;
  uint64_t fee = 0;

  if (!wantV3) {
    // v2: confidential outputs summing to a canonical multiple of MIN; the
    // sub-floor remainder (and the base fee) become the explicit fee.
    uint64_t confSum = ((inAmount - MIN) / MIN) * MIN;  // reserve >= 1 MIN for fee
    fee = inAmount - confSum;
    for (uint64_t d : decomposeAmount(confSum)) {
      outputs.push_back(CTBuildOutput{mk.address, d, /*isTransparent=*/false});
    }
  } else {
    // v3: one confidential change (one canonical denom) + one transparent payout.
    fee = MIN;
    uint64_t confChange = MIN;
    uint64_t transparentPayout = inAmount - confChange - fee;  // any amount > 0
    if (static_cast<int64_t>(transparentPayout) <= 0) { err = "coinbase too small for v3 split"; return false; }
    outputs.push_back(CTBuildOutput{mk.address, confChange, /*isTransparent=*/false});
    outputs.push_back(CTBuildOutput{mk.address, transparentPayout, /*isTransparent=*/true});
  }

  Crypto::SecretKey txSec;
  try {
    outTx = buildConfidentialTransaction(inputs, outputs, mk.viewSecretKey, fee, std::string(), txSec);
  } catch (const std::exception& e) {
    err = std::string("buildConfidentialTransaction threw: ") + e.what();
    return false;
  }
  return true;
}

bool submitToMempool(Core& c, const Transaction& tx, std::string& err) {
  size_t before = c.getPoolTransactionsCount();
  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  c.handle_incoming_tx(toBinaryArray(tx), tvc, /*keeped_by_block=*/false);
  if (tvc.m_verification_failed) { err = "tvc.m_verification_failed"; return false; }
  if (c.getPoolTransactionsCount() != before + 1) { err = "tx not added to pool"; return false; }
  return true;
}

bool test_ct_txs_through_consensus() {
  TEST("Chain integration: mine to v6, then v2 shield + v3 unshield through mempool");

  // Raise to Logging::INFO to see the core's per-block/tx accept/reject reasons.
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

    ok = c.init(coreConfig, minerConfig, /*load_existing=*/false);
    if (!ok) { std::fprintf(stderr, "FAIL [%s]: core init failed\n", current_test); }

    if (ok) {
      test_generator gen(currency);
      gen.setBlockchain(&c.get_blockchain_storage());
      AccountBase miner;
      miner.generate();
      const AccountKeys& minerKeys = miner.getAccountKeys();

      Block genesis;
      ok = gen.constructBlock(genesis, miner, /*timestamp=*/1000000000ULL);
      if (!ok) { std::fprintf(stderr, "FAIL [%s]: genesis failed\n", current_test); }

      if (ok && c.getBlockIdByHeight(0) != get_block_hash(genesis)) {
        c.set_genesis_block(genesis);
      }

      // Mine well past v6 so early coinbases mature (unlock window 10) and CT is active.
      const uint32_t kTargetHeight = 40;
      std::vector<Block> blocks;
      blocks.push_back(genesis);
      for (uint32_t h = 1; h <= kTargetHeight && ok; ++h) {
        const uint8_t ver = c.getBlockMajorVersionForHeight(h);
        Block blk;
        if (!gen.constructBlockManually(blk, blocks.back(), miner, test_generator::bf_major_ver, ver)) {
          std::fprintf(stderr, "FAIL [%s]: constructBlockManually failed at height %u (v%d)\n",
                       current_test, h, static_cast<int>(ver));
          ok = false; break;
        }
        signBlockIfNeeded(blk, minerKeys);
        block_verification_context bvc = boost::value_initialized<block_verification_context>();
        c.handle_incoming_block_blob(toBinaryArray(blk), bvc, false, false);
        if (!bvc.m_added_to_main_chain) {
          std::fprintf(stderr, "FAIL [%s]: block %u (v%d) rejected (verification_failed=%d)\n",
                       current_test, h, static_cast<int>(ver), bvc.m_verification_failed ? 1 : 0);
          ok = false; break;
        }
        blocks.push_back(blk);
      }

      if (ok) {
        uint32_t tip = c.getCurrentBlockchainHeight() - 1;
        REQUIRE(c.getBlockMajorVersionForHeight(tip) >= BLOCK_MAJOR_VERSION_6, "tip not v6");
        REQUIRE(currency.isConfidentialTransactionsActivated(tip), "CT not active at tip");
        std::printf("  mined to height %u (v%d), CT active\n",
                    tip, static_cast<int>(c.getBlockMajorVersionForHeight(tip)));

        // v2 CT shield from a mature coinbase (block 5, ~35 deep).
        std::string err;
        Transaction v2tx;
        REQUIRE(buildCtTxFromCoinbase(c, miner, blocks[5], /*wantV3=*/false, v2tx, err),
                ("build v2 shield: " + err).c_str());
        REQUIRE(v2tx.version == TRANSACTION_VERSION_CT, "v2 tx wrong version");
        REQUIRE(submitToMempool(c, v2tx, err), ("v2 shield to mempool: " + err).c_str());
        std::printf("  v2 CT shield accepted into mempool (%zu confidential outputs)\n", v2tx.outputs.size());

        // v3 unshield (mixed outputs) from a different mature coinbase (block 6).
        Transaction v3tx;
        REQUIRE(buildCtTxFromCoinbase(c, miner, blocks[6], /*wantV3=*/true, v3tx, err),
                ("build v3 unshield: " + err).c_str());
        REQUIRE(v3tx.version == TRANSACTION_VERSION_UNSHIELD, "v3 tx wrong version");
        // Exactly one transparent KeyOutput + one ConfidentialOutput, one GK proof.
        size_t conf = 0, plain = 0;
        for (const auto& o : v3tx.outputs) {
          if (o.target.type() == typeid(ConfidentialOutput)) ++conf; else ++plain;
        }
        REQUIRE(conf == 1 && plain == 1, "v3 tx outputs not mixed 1+1");
        REQUIRE(v3tx.ctProofs.size() == conf, "v3 ctProofs != confidential-output count");
        REQUIRE(submitToMempool(c, v3tx, err), ("v3 unshield to mempool: " + err).c_str());
        std::printf("  v3 unshield accepted into mempool (1 confidential + 1 transparent output)\n");
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
  std::printf("v2 CT + v3 Unshield Chain-Integration Tests (real Core, real PoW path)\n");
  std::printf("=====================================================================\n\n");

  test_ct_txs_through_consensus();

  std::printf("\n=====================================================================\n");
  std::printf("Results: %d/%d passed\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
