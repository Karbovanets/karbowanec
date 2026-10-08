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

#include "gtest/gtest.h"

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "crypto/crypto.h"
#include "Mnemonics/electrum-words.h"

namespace {

class MnemonicsTest : public ::testing::Test {
protected:
  void SetUp() override {
    Crypto::PublicKey pub;
    Crypto::generate_keys(pub, m_key);
    ASSERT_TRUE(Crypto::ElectrumWords::bytes_to_words(m_key, m_phrase, "English"));
    boost::split(m_words, m_phrase, boost::is_any_of(" "));
    ASSERT_EQ(25, m_words.size());
  }

  static std::string join(const std::vector<std::string>& words, size_t count, const std::string& sep) {
    std::string result;
    for (size_t i = 0; i < count; ++i) {
      if (i != 0) {
        result += sep;
      }
      result += words[i];
    }
    return result;
  }

  Crypto::SecretKey m_key;
  std::string m_phrase;
  std::vector<std::string> m_words;
};

TEST_F(MnemonicsTest, roundTrip25Words) {
  Crypto::SecretKey key;
  std::string language;
  ASSERT_TRUE(Crypto::ElectrumWords::words_to_bytes(m_phrase, key, language));
  ASSERT_EQ(m_key, key);
  ASSERT_EQ("English", language);
}

TEST_F(MnemonicsTest, acceptsAnyWhitespace) {
  const std::vector<std::string> phrases = {
    "  " + join(m_words, 25, "   ") + "  ",
    join(m_words, 25, "\t"),
    join(m_words, 25, "\n") + "\n",
    join(m_words, 25, "\r\n") + "\r\n",
    join(m_words, 25, " \t\r\n "),
  };

  for (const auto& phrase : phrases) {
    Crypto::SecretKey key;
    std::string language;
    ASSERT_TRUE(Crypto::ElectrumWords::words_to_bytes(phrase, key, language));
    ASSERT_EQ(m_key, key);

    std::stringstream out;
    Crypto::SecretKey validKey;
    ASSERT_TRUE(Crypto::ElectrumWords::is_valid_mnemonic(phrase, validKey, out));
    ASSERT_EQ(m_key, validKey);
  }
}

TEST_F(MnemonicsTest, accepts24WordsWithoutChecksum) {
  Crypto::SecretKey key;
  std::string language;
  ASSERT_TRUE(Crypto::ElectrumWords::words_to_bytes(join(m_words, 24, " "), key, language));
  ASSERT_EQ(m_key, key);
}

TEST_F(MnemonicsTest, accepts12Words) {
  Crypto::SecretKey key;
  std::string language;
  ASSERT_TRUE(Crypto::ElectrumWords::words_to_bytes(join(m_words, 12, " "), key, language));
  ASSERT_EQ(0, std::memcmp(key.data, m_key.data, 16));
  ASSERT_EQ(0, std::memcmp(key.data + 16, m_key.data, 16));
}

TEST_F(MnemonicsTest, rejectsOtherWordCounts) {
  Crypto::SecretKey key;
  std::string language;
  ASSERT_FALSE(Crypto::ElectrumWords::words_to_bytes("", key, language));
  ASSERT_FALSE(Crypto::ElectrumWords::words_to_bytes(join(m_words, 13, " "), key, language));
  ASSERT_FALSE(Crypto::ElectrumWords::words_to_bytes(m_phrase + " " + m_words[0], key, language));
}

TEST_F(MnemonicsTest, rejectsBadChecksum) {
  std::vector<std::string> words = m_words;
  words[24] = words[24] == words[0] ? words[1] : words[0];
  Crypto::SecretKey key;
  std::string language;
  ASSERT_FALSE(Crypto::ElectrumWords::words_to_bytes(join(words, 25, " "), key, language));
}

TEST_F(MnemonicsTest, reportsUnknownWords) {
  std::vector<std::string> words = m_words;
  words[3] = "notamnemonicword";
  std::stringstream out;
  Crypto::SecretKey key;
  ASSERT_FALSE(Crypto::ElectrumWords::is_valid_mnemonic(join(words, 25, " "), key, out));
  ASSERT_NE(std::string::npos, out.str().find("notamnemonicword is not in the english word list"));
}

}
