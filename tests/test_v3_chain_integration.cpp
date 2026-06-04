// v2 CT + v3 CT->CN unshield — chain-integration harness (real Core, real PoW path).
//
// Stands up a real `Core` on a testnet Currency with low hard-fork heights,
// mines a chain through CT activation (block-major v6) via the production
// block-accept path, then constructs REAL confidential transactions with the
// shared wallet builder (buildConfidentialTransaction) and submits them through
// handle_incoming_tx — exercising mempool admission (check_tx_semantic, incl.
// the GK-proof-count rule) and full CT validation (checkConfidentialTransaction:
// balance kernel, GK proofs, Triptych spend proofs, key-image double-spend).
//
// Coverage:
//   * mine v1->v4->v5->v6 with real PoW (validates the low-height testnet
//     difficulty fixes end to end);
//   * v2 CT shield: transparent coinbase KeyInput -> all-confidential outputs;
//   * v3 unshield (coinbase-funded): coinbase -> mixed (1 ConfidentialOutput +
//     1 transparent KeyOutput) — the shape the mempool GK-proof rule must accept;
//   * v2 CT->CT spend: ConfidentialInput (Triptych, ring CT_MIN_RING_SIZE) ->
//     confidential outputs — the real shielded hot path;
//   * v3 unshield from a CONFIDENTIAL input: ConfidentialInput -> transparent
//     payout + confidential change — the real production unshield;
//   * cross-version double-spend: a confidential output already spent (CT->CT)
//     cannot be spent again via v3 — rejected on the shared key-image set.
//
// Blocks are mined at difficulty 1 (the core still computes/validates the real
// longhash). v2/v3 forks are skipped (v2==v3==v4 upgrade height) to avoid
// merge-mining; v5+ blocks are signed (Miner.cpp). The initial chain is built
// with test_generator; blocks that must include mempool txs use the core's own
// get_block_template (correct coinbase + fee accounting).

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
#include "CryptoNoteCore/Difficulty.h"
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
#include "crypto/ct_ecdh.h"

#include "TestGenerator/TestGenerator.h"

using namespace CryptoNote;

namespace {

int tests_run = 0, tests_passed = 0;
const char* current_test = "";

#define TEST(name) do { current_test = (name); ++tests_run; } while (0)
#define REQUIRE(cond, msg) do { if (!(cond)) { std::fprintf(stderr, "FAIL [%s]: %s\n", current_test, (msg)); return false; } } while (0)
#define PASS() do { ++tests_passed; std::printf("  %-70s [PASS]\n", current_test); return true; } while (0)

Currency makeTestnetCurrency(Logging::ILogger& logger) {
  return CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(2).upgradeHeightV3(2).upgradeHeightV4(2)
      .upgradeHeightV5(12).upgradeHeightV6(14)
      .currency();
}

// v5+ "signed proof-of-work": sign cn_fast_hash(hashing blob) with the coinbase
// output[0] one-time secret (mirrors Miner.cpp). No-op below v5.
void signBlockIfNeeded(Block& blk, const AccountKeys& mk) {
  if (blk.majorVersion < BLOCK_MAJOR_VERSION_5) return;
  BinaryArray hashingBlob;
  get_block_hashing_blob(blk, hashingBlob);
  Crypto::Hash sigHash = Crypto::cn_fast_hash(hashingBlob.data(), hashingBlob.size());
  Crypto::PublicKey txPub = getTransactionPublicKeyFromExtra(blk.baseTransaction.extra);
  Crypto::KeyDerivation derivation;
  Crypto::generate_key_derivation(txPub, mk.viewSecretKey, derivation);
  Crypto::SecretKey ephSec;
  Crypto::derive_secret_key(derivation, 0, mk.spendSecretKey, ephSec);
  const Crypto::PublicKey& ephPub = boost::get<KeyOutput>(blk.baseTransaction.outputs[0].target).key;
  Crypto::generate_signature(sigHash, ephPub, ephSec, blk.signature);
}

// Mine the next block via the core's get_block_template (so it carries any
// mempool txs with the correct coinbase + fee), at difficulty 1.
bool mineBlockWithMempool(Core& c, const AccountKeys& mk, uint64_t timestamp, std::string& err) {
  Block blk; difficulty_type diff = 0; uint32_t height = 0;
  if (!c.get_block_template(blk, mk, diff, height, BinaryArray{})) { err = "get_block_template failed"; return false; }
  blk.timestamp = timestamp;  // target-spaced -> difficulty stays 1
  blk.nonce = 0;
  signBlockIfNeeded(blk, mk);
  Crypto::cn_context ctx; Crypto::Hash pow;
  if (!c.getBlockLongHash(ctx, blk, pow)) { err = "getBlockLongHash failed"; return false; }
  if (!check_hash(pow, diff)) { err = "nonce-0 PoW insufficient (difficulty " + std::to_string(diff) + " > 1)"; return false; }
  block_verification_context bvc = boost::value_initialized<block_verification_context>();
  c.handle_incoming_block_blob(toBinaryArray(blk), bvc, false, false);
  if (!bvc.m_added_to_main_chain) { err = "block rejected (verification_failed=" + std::to_string(bvc.m_verification_failed ? 1 : 0) + ")"; return false; }
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

// Returns true iff the tx is REJECTED by the mempool (used for double-spend).
bool rejectedByMempool(Core& c, const Transaction& tx) {
  size_t before = c.getPoolTransactionsCount();
  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  c.handle_incoming_tx(toBinaryArray(tx), tvc, false);
  return c.getPoolTransactionsCount() == before;  // not added
}

// A confidential output we own (recovered by scanning), ready to be spent or
// used as a ring decoy.
struct CtOut {
  uint32_t globalIndex;
  Crypto::PublicKey targetKey;
  Crypto::EllipticCurvePoint commitment;
  uint64_t amount;
  Crypto::EllipticCurveScalar blinding;
  Crypto::SecretKey spendKey;
};

// Build a v2 CT shield (transparent coinbase ring-1 -> all-confidential outputs).
bool buildShieldFromCoinbase(Core& c, const AccountBase& miner, const Block& coinbaseBlock,
                             Transaction& outTx, std::string& err) {
  const AccountKeys& mk = miner.getAccountKeys();
  const Transaction& cb = coinbaseBlock.baseTransaction;
  if (cb.outputs.empty() || cb.outputs[0].target.type() != typeid(KeyOutput)) { err = "coinbase out0"; return false; }
  const uint64_t inAmount = cb.outputs[0].amount;
  std::vector<uint32_t> gindexs;
  if (!c.get_tx_outputs_gindexs(getObjectHash(cb), gindexs) || gindexs.empty()) { err = "coinbase gindexs"; return false; }
  Crypto::PublicKey txPub = getTransactionPublicKeyFromExtra(cb.extra);
  KeyPair eph; Crypto::KeyImage ki;
  if (!generate_key_image_helper(mk, txPub, 0, eph, ki)) { err = "key_image_helper"; return false; }

  CTBuildRingMember rm;
  rm.amount = inAmount; rm.outputIndex = gindexs[0]; rm.pubkey = boost::get<KeyOutput>(cb.outputs[0].target).key;
  if (!Crypto::transparent_amount_to_commitment(inAmount, rm.commitment)) { err = "commitment"; return false; }
  CTBuildInput in;
  in.ringMembers = { rm }; in.realIndex = 0; in.spendPrivkey = eph.secretKey;
  std::memset(&in.realBlinding, 0, sizeof(in.realBlinding));
  in.amount = inAmount; in.isTransparent = true;
  std::vector<CTBuildInput> inputs = { in };

  const uint64_t MIN = MIN_CT_DENOMINATION;
  uint64_t confSum = ((inAmount - MIN) / MIN) * MIN;
  uint64_t fee = inAmount - confSum;
  std::vector<CTBuildOutput> outputs;
  for (uint64_t d : decomposeAmount(confSum)) outputs.push_back(CTBuildOutput{mk.address, d, false});

  Crypto::SecretKey txSec;
  try { outTx = buildConfidentialTransaction(inputs, outputs, mk.viewSecretKey, fee, std::string(), txSec); }
  catch (const std::exception& e) { err = std::string("shield build threw: ") + e.what(); return false; }
  return true;
}

// Scan a confirmed shield tx and recover the confidential outputs we own.
bool scanCtOutputs(Core& c, const AccountBase& miner, const Transaction& shieldTx,
                   std::vector<CtOut>& outs, std::string& err) {
  const AccountKeys& mk = miner.getAccountKeys();
  std::vector<uint32_t> gindexs;
  if (!c.get_tx_outputs_gindexs(getObjectHash(shieldTx), gindexs)) { err = "shield gindexs"; return false; }
  Crypto::PublicKey txPub = getTransactionPublicKeyFromExtra(shieldTx.extra);
  Crypto::KeyDerivation deriv;
  Crypto::generate_key_derivation(txPub, mk.viewSecretKey, deriv);
  for (size_t i = 0; i < shieldTx.outputs.size(); ++i) {
    if (shieldTx.outputs[i].target.type() != typeid(ConfidentialOutput)) continue;
    const ConfidentialOutput& co = boost::get<ConfidentialOutput>(shieldTx.outputs[i].target);
    Crypto::PublicKey spendPub;
    if (!Crypto::underive_public_key(deriv, i, co.targetKey, spendPub) || spendPub != mk.address.spendPublicKey) continue;
    Crypto::MaskedAmount masked; std::memcpy(masked.data, co.maskedAmount.data(), sizeof(masked.data));
    const Crypto::PublicKey& commPK = reinterpret_cast<const Crypto::PublicKey&>(co.commitment);
    uint64_t amount = 0; Crypto::EllipticCurveScalar blinding;
    if (!Crypto::decrypt_and_verify_output(mk.viewSecretKey, txPub, i, masked, commPK, amount, blinding)) { err = "decrypt_and_verify_output"; return false; }
    KeyPair eph; Crypto::KeyImage ki;
    generate_key_image_helper(mk, txPub, i, eph, ki);
    outs.push_back(CtOut{gindexs[i], co.targetKey, co.commitment, amount, blinding, eph.secretKey});
  }
  return true;
}

// Spend ring[realIdx] confidentially. unshield=false -> CT->CT (confidential
// outputs); unshield=true -> CT->CN (transparent payout + confidential change).
bool buildConfidentialSpend(const AccountBase& miner, const std::vector<CtOut>& ring, size_t realIdx,
                            bool unshield, Transaction& outTx, std::string& err) {
  const AccountKeys& mk = miner.getAccountKeys();
  CTBuildInput in;
  for (const auto& m : ring) {
    CTBuildRingMember rm;
    rm.amount = parameters::CT_CONFIDENTIAL_OUTPUT_AMOUNT; rm.outputIndex = m.globalIndex;
    rm.pubkey = m.targetKey; rm.commitment = m.commitment;
    in.ringMembers.push_back(rm);
  }
  in.realIndex = realIdx;
  in.spendPrivkey = ring[realIdx].spendKey;
  in.realBlinding = ring[realIdx].blinding;
  in.amount = ring[realIdx].amount;
  in.isTransparent = false;
  std::vector<CTBuildInput> inputs = { in };

  const uint64_t MIN = MIN_CT_DENOMINATION;
  const uint64_t R = ring[realIdx].amount;
  std::vector<CTBuildOutput> outputs;
  uint64_t fee = MIN;
  if (!unshield) {
    for (uint64_t d : decomposeAmount(R - fee)) outputs.push_back(CTBuildOutput{mk.address, d, false});
  } else {
    const uint64_t confChange = MIN;
    const uint64_t payout = R - confChange - fee;
    if (static_cast<int64_t>(payout) <= 0) { err = "CT output too small for v3 split"; return false; }
    outputs.push_back(CTBuildOutput{mk.address, confChange, false});
    outputs.push_back(CTBuildOutput{mk.address, payout, true});
  }
  Crypto::SecretKey txSec;
  try { outTx = buildConfidentialTransaction(inputs, outputs, mk.viewSecretKey, fee, std::string(), txSec); }
  catch (const std::exception& e) { err = std::string("confidential spend build threw: ") + e.what(); return false; }
  return true;
}

bool test_ct_txs_through_consensus() {
  TEST("Chain integration: v2 shield, v3 unshield, CT->CT, confidential-input unshield, double-spend");

  // Raise to Logging::INFO to see the core's per-block/tx accept/reject reasons.
  Logging::ConsoleLogger logger(Logging::ERROR);
  Currency currency = makeTestnetCurrency(logger);

  boost::filesystem::path dataDir =
      boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("karbo-v3-itest-%%%%-%%%%");
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

    if (!c.init(coreConfig, minerConfig, false)) {
      std::fprintf(stderr, "FAIL [%s]: core init failed\n", current_test);
    } else {
      test_generator gen(currency);
      gen.setBlockchain(&c.get_blockchain_storage());
      AccountBase miner; miner.generate();
      const AccountKeys& mk = miner.getAccountKeys();

      Block genesis;
      ok = gen.constructBlock(genesis, miner, 1000000000ULL);
      if (ok && c.getBlockIdByHeight(0) != get_block_hash(genesis)) c.set_genesis_block(genesis);

      const uint32_t kTargetHeight = 40;
      std::vector<Block> blocks; blocks.push_back(genesis);
      uint64_t lastTs = genesis.timestamp;
      for (uint32_t h = 1; h <= kTargetHeight && ok; ++h) {
        const uint8_t ver = c.getBlockMajorVersionForHeight(h);
        Block blk;
        if (!gen.constructBlockManually(blk, blocks.back(), miner, test_generator::bf_major_ver, ver)) {
          std::fprintf(stderr, "FAIL [%s]: constructBlockManually @%u\n", current_test, h); ok = false; break;
        }
        signBlockIfNeeded(blk, mk);
        block_verification_context bvc = boost::value_initialized<block_verification_context>();
        c.handle_incoming_block_blob(toBinaryArray(blk), bvc, false, false);
        if (!bvc.m_added_to_main_chain) {
          std::fprintf(stderr, "FAIL [%s]: block %u (v%d) rejected (vf=%d)\n",
                       current_test, h, (int)ver, bvc.m_verification_failed ? 1 : 0); ok = false; break;
        }
        blocks.push_back(blk); lastTs = blk.timestamp;
      }

      if (ok) {
        const uint64_t T = currency.difficultyTarget();
        uint32_t tip = c.getCurrentBlockchainHeight() - 1;
        REQUIRE(c.getBlockMajorVersionForHeight(tip) >= BLOCK_MAJOR_VERSION_6, "tip not v6");
        REQUIRE(currency.isConfidentialTransactionsActivated(tip), "CT not active");
        std::printf("  mined to height %u (v%d), CT active\n", tip, (int)c.getBlockMajorVersionForHeight(tip));

        std::string err;

        // (1) v2 CT shield from a mature coinbase, accepted into mempool.
        Transaction shield;
        REQUIRE(buildShieldFromCoinbase(c, miner, blocks[5], shield, err), ("build shield: " + err).c_str());
        REQUIRE(shield.version == TRANSACTION_VERSION_CT, "shield not v2");
        REQUIRE(submitToMempool(c, shield, err), ("shield mempool: " + err).c_str());
        std::printf("  (1) v2 CT shield accepted into mempool (%zu confidential outputs)\n", shield.outputs.size());

        // (2) v3 unshield (coinbase-funded, mixed outputs) — guards the P1 GK-proof rule.
        Transaction cbUnshield;
        {
          const Transaction& cb = blocks[6].baseTransaction;
          std::vector<uint32_t> gi; c.get_tx_outputs_gindexs(getObjectHash(cb), gi);
          uint64_t inAmount = cb.outputs[0].amount;
          Crypto::PublicKey txPub = getTransactionPublicKeyFromExtra(cb.extra);
          KeyPair eph; Crypto::KeyImage ki; generate_key_image_helper(mk, txPub, 0, eph, ki);
          CTBuildRingMember rm; rm.amount = inAmount; rm.outputIndex = gi[0];
          rm.pubkey = boost::get<KeyOutput>(cb.outputs[0].target).key;
          Crypto::transparent_amount_to_commitment(inAmount, rm.commitment);
          CTBuildInput in; in.ringMembers = {rm}; in.realIndex = 0; in.spendPrivkey = eph.secretKey;
          std::memset(&in.realBlinding, 0, sizeof(in.realBlinding)); in.amount = inAmount; in.isTransparent = true;
          std::vector<CTBuildInput> ins = {in};
          const uint64_t MIN = MIN_CT_DENOMINATION;
          std::vector<CTBuildOutput> outs = { {mk.address, MIN, false}, {mk.address, inAmount - 2*MIN, true} };
          Crypto::SecretKey ts;
          try { cbUnshield = buildConfidentialTransaction(ins, outs, mk.viewSecretKey, MIN, std::string(), ts); }
          catch (const std::exception& e) { REQUIRE(false, (std::string("cb unshield build: ") + e.what()).c_str()); }
        }
        REQUIRE(cbUnshield.version == TRANSACTION_VERSION_UNSHIELD, "unshield not v3");
        REQUIRE(cbUnshield.ctProofs.size() == 1, "v3 ctProofs != 1 (confidential-output count)");
        REQUIRE(submitToMempool(c, cbUnshield, err), ("cb unshield mempool: " + err).c_str());
        std::printf("  (2) v3 unshield (coinbase-funded, mixed outputs) accepted into mempool\n");

        // Confirm the pooled shield (+ the above) into a block so the shield's
        // confidential outputs become spendable ring members.
        lastTs += T;
        REQUIRE(mineBlockWithMempool(c, mk, lastTs, err), ("confirm shield: " + err).c_str());

        std::vector<CtOut> ctOuts;
        REQUIRE(scanCtOutputs(c, miner, shield, ctOuts, err), ("scan CT outputs: " + err).c_str());
        REQUIRE(ctOuts.size() >= CryptoNote::parameters::CT_MIN_RING_SIZE,
                ("not enough CT outputs for a ring: " + std::to_string(ctOuts.size())).c_str());
        std::printf("  shield confirmed; recovered %zu spendable confidential outputs\n", ctOuts.size());

        // Build a CT_MIN_RING_SIZE ring from the recovered CT outputs.
        std::vector<CtOut> ring(ctOuts.begin(), ctOuts.begin() + CryptoNote::parameters::CT_MIN_RING_SIZE);

        // (3) v2 CT->CT: spend ring[0] confidentially -> confidential outputs.
        Transaction ctToCt;
        REQUIRE(buildConfidentialSpend(miner, ring, 0, /*unshield=*/false, ctToCt, err), ("CT->CT build: " + err).c_str());
        REQUIRE(ctToCt.version == TRANSACTION_VERSION_CT, "CT->CT not v2");
        REQUIRE(submitToMempool(c, ctToCt, err), ("CT->CT mempool: " + err).c_str());
        std::printf("  (3) v2 CT->CT (Triptych, ring %zu) accepted into mempool\n", ring.size());

        // (4) v3 unshield from a CONFIDENTIAL input: spend ring[1] -> transparent payout + CT change.
        Transaction ctUnshield;
        REQUIRE(buildConfidentialSpend(miner, ring, 1, /*unshield=*/true, ctUnshield, err), ("CT unshield build: " + err).c_str());
        REQUIRE(ctUnshield.version == TRANSACTION_VERSION_UNSHIELD, "CT unshield not v3");
        REQUIRE(submitToMempool(c, ctUnshield, err), ("CT unshield mempool: " + err).c_str());
        std::printf("  (4) v3 unshield from a confidential input (Triptych) accepted into mempool\n");

        // (5) cross-version double-spend: ring[0] is already spent (3) via CT->CT;
        // spending it again via v3 must be rejected on the shared key-image set.
        Transaction doubleSpend;
        REQUIRE(buildConfidentialSpend(miner, ring, 0, /*unshield=*/true, doubleSpend, err), ("double-spend build: " + err).c_str());
        REQUIRE(rejectedByMempool(c, doubleSpend), "double-spend of an already-spent confidential output was ACCEPTED");
        std::printf("  (5) cross-version double-spend rejected on the shared key-image set\n");
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
