// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Unit tests for the LMDB pq_nullifiers consensus-state table (spec §8):
// insert / lookup / remove round trips, and the reorg property that removing a
// nullifier (block pop) lets the same nullifier be re-inserted on a competing
// chain.

#include "gtest/gtest.h"

#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "CryptoTypes.h"

#include <cstdint>
#include <cstring>
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
        dir = std::filesystem::path("pq_nullifier_test_data");
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        EXPECT_TRUE(db.open(dir.string()));
    }
    ~TempDb() {
        db.close();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

}  // namespace

TEST(PqNullifierDb, PutHasGetRemove) {
    TempDb t;
    Crypto::Hash nf = hashPat(7, 1);
    Crypto::Hash txid = hashPat(3, 9);

    EXPECT_FALSE(t.db.hasPqNullifier(nf));

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putPqNullifier(nf, 12345, txid));
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqNullifier(nf));

    uint32_t h = 0; Crypto::Hash gotTxid{};
    ASSERT_TRUE(t.db.getPqNullifier(nf, h, gotTxid));
    EXPECT_EQ(h, 12345u);
    EXPECT_EQ(0, std::memcmp(gotTxid.data, txid.data, 32));

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removePqNullifier(nf));
    t.db.commitTxn();

    EXPECT_FALSE(t.db.hasPqNullifier(nf));
}

TEST(PqNullifierDb, AbsentNullifier) {
    TempDb t;
    EXPECT_FALSE(t.db.hasPqNullifier(hashPat(1, 2)));
    uint32_t h; Crypto::Hash txid;
    EXPECT_FALSE(t.db.getPqNullifier(hashPat(1, 2), h, txid));
}

TEST(PqNullifierDb, ReorgRemoveAllowsReinsert) {
    TempDb t;
    Crypto::Hash nf = hashPat(5, 5);
    Crypto::Hash txidA = hashPat(1, 0);
    Crypto::Hash txidB = hashPat(2, 0);

    // Inserted on chain A at height 100.
    t.db.beginWriteTxn();
    t.db.putPqNullifier(nf, 100, txidA);
    t.db.commitTxn();
    EXPECT_TRUE(t.db.hasPqNullifier(nf));

    // Block 100 is orphaned by a reorg -> the nullifier is removed.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removePqNullifier(nf));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasPqNullifier(nf));

    // The same (auth_pub, rho) may now re-enter on competing chain B.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putPqNullifier(nf, 101, txidB));
    t.db.commitTxn();

    uint32_t h = 0; Crypto::Hash gotTxid{};
    ASSERT_TRUE(t.db.getPqNullifier(nf, h, gotTxid));
    EXPECT_EQ(h, 101u);
    EXPECT_EQ(0, std::memcmp(gotTxid.data, txidB.data, 32));
}

TEST(PqNullifierDb, MultipleDistinct) {
    TempDb t;
    Crypto::Hash a = hashPat(1, 1), b = hashPat(2, 2), c = hashPat(3, 3);
    Crypto::Hash txid = hashPat(9, 9);

    t.db.beginWriteTxn();
    t.db.putPqNullifier(a, 1, txid);
    t.db.putPqNullifier(b, 2, txid);
    t.db.putPqNullifier(c, 3, txid);
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqNullifier(a));
    EXPECT_TRUE(t.db.hasPqNullifier(b));
    EXPECT_TRUE(t.db.hasPqNullifier(c));

    t.db.beginWriteTxn();
    t.db.removePqNullifier(b);
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqNullifier(a));
    EXPECT_FALSE(t.db.hasPqNullifier(b));
    EXPECT_TRUE(t.db.hasPqNullifier(c));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
