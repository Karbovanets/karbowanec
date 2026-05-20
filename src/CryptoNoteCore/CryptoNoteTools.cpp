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

#include "CryptoNoteTools.h"
#include "CryptoNoteFormatUtils.h"

#include <limits>

namespace CryptoNote {
template<>
bool toBinaryArray(const BinaryArray& object, BinaryArray& binaryArray) {
  try {
    Common::VectorOutputStream stream(binaryArray);
    BinaryOutputStreamSerializer serializer(stream);
    std::string oldBlob = Common::asString(object);
    serializer(oldBlob, "");
  } catch (std::exception&) {
    return false;
  }

  return true;
}

void getBinaryArrayHash(const BinaryArray& binaryArray, Crypto::Hash& hash) {
  cn_fast_hash(binaryArray.data(), binaryArray.size(), hash);
}

Crypto::Hash getBinaryArrayHash(const BinaryArray& binaryArray) {
  Crypto::Hash hash;
  getBinaryArrayHash(binaryArray, hash);
  return hash;
}

uint64_t getInputAmount(const Transaction& transaction) {
  uint64_t amount = 0;
  for (auto& input : transaction.inputs) {
    if (input.type() == typeid(KeyInput)) {
      amount += boost::get<KeyInput>(input).amount;
    }
  }

  return amount;
}

std::vector<uint64_t> getInputsAmounts(const Transaction& transaction) {
  std::vector<uint64_t> inputsAmounts;
  inputsAmounts.reserve(transaction.inputs.size());

  for (auto& input: transaction.inputs) {
    if (input.type() == typeid(KeyInput)) {
      inputsAmounts.push_back(boost::get<KeyInput>(input).amount);
    }
  }

  return inputsAmounts;
}

uint64_t getOutputAmount(const Transaction& transaction) {
  uint64_t amount = 0;
  for (auto& output : transaction.outputs) {
    amount += output.amount;
  }

  return amount;
}

namespace {
// dst = a + b, returning false if the sum would wrap uint64_t.
inline bool checkedAdd(uint64_t a, uint64_t b, uint64_t& dst) {
  if (a > std::numeric_limits<uint64_t>::max() - b) {
    return false;
  }
  dst = a + b;
  return true;
}
}

bool getInputAmountChecked(const Transaction& transaction, uint64_t& out) {
  uint64_t acc = 0;
  for (const auto& input : transaction.inputs) {
    if (input.type() == typeid(KeyInput)) {
      if (!checkedAdd(acc, boost::get<KeyInput>(input).amount, acc)) {
        return false;
      }
    }
  }
  out = acc;
  return true;
}

bool getOutputAmountChecked(const Transaction& transaction, uint64_t& out) {
  uint64_t acc = 0;
  for (const auto& output : transaction.outputs) {
    if (!checkedAdd(acc, output.amount, acc)) {
      return false;
    }
  }
  out = acc;
  return true;
}

bool computeCtPoolDelta(const Transaction& transaction, uint64_t fee,
                        uint64_t& inflow, uint64_t& outflow) {
  uint64_t plain_in = 0;
  uint64_t plain_out = 0;
  if (!getInputAmountChecked(transaction, plain_in)) return false;
  if (!getOutputAmountChecked(transaction, plain_out)) return false;
  uint64_t out_plus_fee = 0;
  if (!checkedAdd(plain_out, fee, out_plus_fee)) return false;
  if (plain_in >= out_plus_fee) {
    inflow  = plain_in - out_plus_fee;
    outflow = 0;
  } else {
    inflow  = 0;
    outflow = out_plus_fee - plain_in;
  }
  return true;
}

void decomposeAmount(uint64_t amount, uint64_t dustThreshold, std::vector<uint64_t>& decomposedAmounts) {
  decompose_amount_into_digits(amount, dustThreshold,
    [&](uint64_t amount) {
    decomposedAmounts.push_back(amount);
  },
    [&](uint64_t dust) {
    decomposedAmounts.push_back(dust);
  }
  );
}

}
