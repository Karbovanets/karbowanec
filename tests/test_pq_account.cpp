// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for the PQ account-number registry (spec §11): the LMDB pq_acct_reg
// table with first-registration-wins + reorg rollback semantics, and the
// human-readable H-I-C account-number rendering.

#include "gtest/gtest.h"

#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "CryptoTypes.h"
#include "crypto_pq/PqAccountNumber.h"

#include <cstdint>
#include <filesystem>
#include <string>

using namespace CryptoNote;

namespace {

Crypto::Hash hashPat(uint8_t a, uint8_t b) {
    Crypto::Hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i) h.data[i] = static_cast<uint8_t>(i * a + b);
    return h;
}

struct TempDb {
    std::filesystem::path dir;
    LMDBBlockchainDB db;
    TempDb() {
        std::error_code ec;
        dir = std::filesystem::path("pq_acct_test_data");
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        EXPECT_TRUE(db.open(dir.string()));
    }
    ~TempDb() { db.close(); std::error_code ec; std::filesystem::remove_all(dir, ec); }
};

}  // namespace

TEST(PqAcctReg, PutHasGetRemove) {
    TempDb t;
    Crypto::Hash vp = hashPat(7, 1);
    EXPECT_FALSE(t.db.hasPqAcctReg(vp));

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putPqAcctReg(vp, 1234567, 42));
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqAcctReg(vp));
    uint32_t h = 0, ti = 0;
    ASSERT_TRUE(t.db.getPqAcctReg(vp, h, ti));
    EXPECT_EQ(h, 1234567u);
    EXPECT_EQ(ti, 42u);

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removePqAcctReg(vp));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasPqAcctReg(vp));
}

TEST(PqAcctReg, FirstRegistrationWins) {
    // The consensus rule (in pushTransaction) rejects a second registration of
    // an already-present viewPub. At the DB layer that's a hasPqAcctReg() check
    // returning true for the duplicate.
    TempDb t;
    Crypto::Hash vp = hashPat(5, 5);

    t.db.beginWriteTxn();
    t.db.putPqAcctReg(vp, 100, 1);   // first registration wins at (100,1)
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqAcctReg(vp));  // a later tx would be rejected
    uint32_t h, ti;
    t.db.getPqAcctReg(vp, h, ti);
    EXPECT_EQ(h, 100u);
    EXPECT_EQ(ti, 1u);
}

TEST(PqAcctReg, ReorgRollbackAllowsReregister) {
    TempDb t;
    Crypto::Hash vp = hashPat(3, 2);

    t.db.beginWriteTxn();
    t.db.putPqAcctReg(vp, 100, 1);
    t.db.commitTxn();
    EXPECT_TRUE(t.db.hasPqAcctReg(vp));

    // Block 100 orphaned by a reorg -> registration removed.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removePqAcctReg(vp));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasPqAcctReg(vp));

    // Same viewPub may now register at a new height on the competing chain.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putPqAcctReg(vp, 101, 3));
    t.db.commitTxn();
    uint32_t h, ti;
    ASSERT_TRUE(t.db.getPqAcctReg(vp, h, ti));
    EXPECT_EQ(h, 101u);
    EXPECT_EQ(ti, 3u);
}

// --- H-I-C account-number rendering ---------------------------------------

TEST(PqAccountNumber, RoundTrip) {
    std::string hic = CryptoPQ::renderAccountNumber(1234567, 42);
    uint64_t h = 0; uint32_t ti = 0;
    ASSERT_TRUE(CryptoPQ::parseAccountNumber(hic, h, ti));
    EXPECT_EQ(h, 1234567u);
    EXPECT_EQ(ti, 42u);
    // shape: "<height>-<txIndex>-<CCC>"
    EXPECT_EQ(hic.substr(0, 10), "1234567-42");
    EXPECT_EQ(hic[hic.size() - 4], '-');
}

TEST(PqAccountNumber, ChecksumRejectsTypo) {
    std::string hic = CryptoPQ::renderAccountNumber(900, 7);
    // Corrupt the last checksum char.
    hic[hic.size() - 1] = (hic[hic.size() - 1] == 'A') ? 'B' : 'A';
    uint64_t h; uint32_t ti;
    EXPECT_FALSE(CryptoPQ::parseAccountNumber(hic, h, ti));
}

TEST(PqAccountNumber, ChecksumRejectsWrongHeight) {
    std::string hic = CryptoPQ::renderAccountNumber(900, 7);
    // Same shape, different height -> checksum mismatch.
    std::string tampered = "901" + hic.substr(hic.find('-'));
    uint64_t h; uint32_t ti;
    EXPECT_FALSE(CryptoPQ::parseAccountNumber(tampered, h, ti));
}

TEST(PqAccountNumber, RejectsMalformed) {
    uint64_t h; uint32_t ti;
    EXPECT_FALSE(CryptoPQ::parseAccountNumber("not-an-account", h, ti));
    EXPECT_FALSE(CryptoPQ::parseAccountNumber("123", h, ti));
    EXPECT_FALSE(CryptoPQ::parseAccountNumber("12-34", h, ti));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
