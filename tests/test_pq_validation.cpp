// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Consensus-validation tests for v2 TX_PQ (spec §9, ownership-fixed). Builds a
// real signed PQ transaction (outputs via PqOutputBuilder, inputs signed with
// ML-DSA over the §8.1 digest), then asserts acceptance and that each rule
// rejects when violated.

#include "gtest/gtest.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "CryptoNoteCore/PqValidation.h"

#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace CryptoNote;

namespace {

template <std::size_t N> std::array<uint8_t, N> pat(uint8_t a, uint8_t b) {
    std::array<uint8_t, N> r;
    for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(i * a + b);
    return r;
}

Crypto::Hash hashPat(uint8_t a, uint8_t b) {
    Crypto::Hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i) h.data[i] = static_cast<uint8_t>(i * a + b);
    return h;
}

template <std::size_t N> std::vector<uint8_t> toVec(const std::array<uint8_t, N>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

// A built, signed PQ transaction plus the resolved referenced outputs and the
// spender's secret (so tests can re-sign after mutating).
struct BuiltTx {
    Transaction tx;
    std::vector<PqResolvedInput> resolved;
    CryptoPQ::DsaSecretKey spendSk;
};

// One spender owns one input (amountIn) and sends amountOut to a recipient,
// leaving fee = amountIn - amountOut.
BuiltTx buildSignedTx(uint64_t amountIn, uint64_t amountOut) {
    BuiltTx b;

    CryptoPQ::SeedMaster ms = pat<32>(2, 7);   // spender
    CryptoPQ::SeedMaster mr = pat<32>(3, 9);   // recipient
    auto spenderSpend = CryptoPQ::deriveSpendKeys(ms);
    auto recipView = CryptoPQ::deriveViewKeys(mr);
    auto recipSpend = CryptoPQ::deriveSpendKeys(mr);
    b.spendSk = spenderSpend.second;

    // The input being spent: a PqOutput the spender owns, identified by
    // (prevTxid, prevOutIndex) with secret rho_in.
    Crypto::Hash prevTxid = hashPat(1, 0);
    uint32_t prevOutIndex = 2;
    CryptoPQ::Rho rhoIn = pat<32>(3, 9);

    PqInput in;
    in.prevTxid = prevTxid;
    in.prevOutIndex = prevOutIndex;
    in.authPub = toVec(spenderSpend.first);   // long-term spend pubkey
    in.rhoReveal = toVec(rhoIn);
    in.signature.assign(PQ_SIGNATURE_SIZE, 0);  // filled after digest
    b.tx.inputs.push_back(in);

    // Resolved referenced output: its spend_commit binds the spender's spend key.
    PqResolvedInput r;
    r.exists = true; r.isPqOutput = true; r.isCoinbase = false;
    r.amount = amountIn;
    {
        CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(spenderSpend.first, rhoIn);
        std::memcpy(r.spendCommit.data, sc.data(), 32);
    }
    b.resolved.push_back(r);

    // inputsHash over this tx's outpoints (binds outputs' out_context).
    std::vector<CryptoPQ::InputRef> refs(1);
    std::memcpy(refs[0].prevTxid.data(), prevTxid.data, 32);
    refs[0].prevOutIndex = prevOutIndex;
    CryptoPQ::Hash256 ih = CryptoPQ::inputsHash(refs);

    // One output to the recipient.
    CryptoPQ::PqBuiltOutput built =
        CryptoPQ::buildPqOutput(recipView.first, recipSpend.first, ih, 0, amountOut);
    PqOutput po;
    po.kemCt = toVec(built.kemCt);
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);
    TransactionOutput out;
    out.amount = amountOut;
    out.target = po;

    b.tx.version = TRANSACTION_VERSION_PQ;
    b.tx.txType = TX_PQ;
    b.tx.unlockTime = 0;
    b.tx.outputs.push_back(out);

    // Sign: digest over (tx, fee), ML-DSA with the spender's spend secret.
    uint64_t fee = amountIn - amountOut;
    CryptoPQ::Hash256 digest = pqSigningDigest(b.tx, fee);
    CryptoPQ::DsaSignature sig =
        CryptoPQ::dsa_sign(b.spendSk, digest.data(), digest.size());
    boost::get<PqInput>(b.tx.inputs[0]).signature = toVec(sig);

    return b;
}

// Re-sign after a mutation that changes the digest (amount/fee/etc.).
void resign(BuiltTx& b) {
    uint64_t sumIn = 0, sumOut = 0;
    for (auto& r : b.resolved) sumIn += r.amount;
    for (auto& o : b.tx.outputs) sumOut += o.amount;
    CryptoPQ::Hash256 d = pqSigningDigest(b.tx, sumIn - sumOut);
    CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(b.spendSk, d.data(), d.size());
    boost::get<PqInput>(b.tx.inputs[0]).signature = toVec(sig);
}

const uint64_t kMinFee = 0;  // disable fee-floor except where tested

}  // namespace

TEST(PqValidation, AcceptsValidTx) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    std::string err;
    EXPECT_TRUE(checkPqTransactionSemantic(b.tx, &err)) << err;
    std::vector<Crypto::Hash> nfs;
    EXPECT_TRUE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, &nfs, &err)) << err;
    EXPECT_EQ(nfs.size(), 1u);
}

TEST(PqValidation, RejectsTamperedSignature) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    boost::get<PqInput>(b.tx.inputs[0]).signature[10] ^= 0xFF;
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsSpendCommitMismatch) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.resolved[0].spendCommit.data[0] ^= 0xFF;  // referenced output binds a different key
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsMissingReferencedOutput) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.resolved[0].exists = false;
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsCoinbaseReference) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.resolved[0].isCoinbase = true;
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsOutputsExceedInputs) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.outputs[0].amount = 2000000;  // > input
    resign(b);
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsAmountTamperWithoutResign) {
    // Changing an output amount without re-signing breaks the digest.
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.outputs[0].amount = 800000;  // fee would change; signature now stale
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsFeeBelowFloor) {
    BuiltTx b = buildSignedTx(1000000, 999999);  // fee = 1
    std::string err;
    // With a per-byte floor, a 1-atomic fee on a multi-KB tx is far too low.
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, parameters::MIN_PQ_FEE_PER_BYTE, nullptr, &err));
}

TEST(PqValidation, RejectsDuplicateNullifier) {
    // Two inputs spending the same output (same authPub+rho) -> same nullifier.
    BuiltTx b = buildSignedTx(1000000, 900000);
    PqInput dup = boost::get<PqInput>(b.tx.inputs[0]);
    b.tx.inputs.push_back(dup);
    b.resolved.push_back(b.resolved[0]);
    resign(b);
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, SemanticRejectsWrongSubtype) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.txType = TX_BRIDGE;
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsUnlockTime) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.unlockTime = 5;
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsLegacySignatures) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.signatures.resize(1);
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsMixedFamilyInput) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    KeyInput ki; ki.amount = 1; ki.keyImage = Crypto::KeyImage{};
    b.tx.inputs.push_back(ki);
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsZeroAmountOutput) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.outputs[0].amount = 0;
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsWrongFieldSize) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    boost::get<PqInput>(b.tx.inputs[0]).authPub.pop_back();  // 1951 bytes
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
