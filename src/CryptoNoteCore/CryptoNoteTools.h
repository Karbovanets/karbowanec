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

#pragma once

#include <limits>
#include "Common/MemoryInputStream.h"
#include "Common/StringTools.h"
#include "Common/VectorOutputStream.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "CryptoNoteSerialization.h"

namespace CryptoNote {

// --- InputSignatures variant helpers ---------------------------------------
// Per-input authorization is stored as a variant whose alternative is
// implicit from the matching tx.inputs[i]:
//   BaseInput          -> boost::blank
//   KeyInput           -> std::vector<Crypto::Signature>
//   ConfidentialInput  -> CTInputSignature
// These helpers keep call sites concise instead of repeating boost::get
// dispatches everywhere.

inline bool isKeyInputSig(const InputSignatures& s) {
  return s.type() == typeid(std::vector<Crypto::Signature>);
}

inline bool isCtInputSig(const InputSignatures& s) {
  return s.type() == typeid(CTInputSignature);
}

inline const std::vector<Crypto::Signature>& keyInputSig(const InputSignatures& s) {
  return boost::get<std::vector<Crypto::Signature>>(s);
}

inline std::vector<Crypto::Signature>& keyInputSig(InputSignatures& s) {
  return boost::get<std::vector<Crypto::Signature>>(s);
}

inline const CTInputSignature& ctInputSig(const InputSignatures& s) {
  return boost::get<CTInputSignature>(s);
}

inline CTInputSignature& ctInputSig(InputSignatures& s) {
  return boost::get<CTInputSignature>(s);
}

void getBinaryArrayHash(const BinaryArray& binaryArray, Crypto::Hash& hash);
Crypto::Hash getBinaryArrayHash(const BinaryArray& binaryArray);

template<class T>
bool toBinaryArray(const T& object, BinaryArray& binaryArray) {
  try {
    ::Common::VectorOutputStream stream(binaryArray);
    BinaryOutputStreamSerializer serializer(stream);
    serialize(const_cast<T&>(object), serializer);
  } catch (std::exception&) {
    return false;
  }

  return true;
}

template<>
bool toBinaryArray(const BinaryArray& object, BinaryArray& binaryArray); 

template<class T>
BinaryArray toBinaryArray(const T& object) {
  BinaryArray ba;
  toBinaryArray(object, ba);
  return ba;
}

template<class T>
bool fromBinaryArray(T& object, const BinaryArray& binaryArray) {
  bool result = false;
  try {
    Common::MemoryInputStream stream(binaryArray.data(), binaryArray.size());
    BinaryInputStreamSerializer serializer(stream);
    serialize(object, serializer);
    result = stream.endOfStream(); // check that all data was consumed
  } catch (std::exception&) {
  }

  return result;
}

template<class T>
bool getObjectBinarySize(const T& object, size_t& size) {
  BinaryArray ba;
  if (!toBinaryArray(object, ba)) {
    size = (std::numeric_limits<size_t>::max)();
    return false;
  }

  size = ba.size();
  return true;
}

template<class T>
size_t getObjectBinarySize(const T& object) {
  size_t size;
  getObjectBinarySize(object, size);
  return size;
}

template<class T>
bool getObjectHash(const T& object, Crypto::Hash& hash) {
  BinaryArray ba;
  if (!toBinaryArray(object, ba)) {
    hash = NULL_HASH;
    return false;
  }

  hash = getBinaryArrayHash(ba);
  return true;
}

template<class T>
bool getObjectHash(const T& object, Crypto::Hash& hash, size_t& size) {
  BinaryArray ba;
  if (!toBinaryArray(object, ba)) {
    hash = NULL_HASH;
    size = (std::numeric_limits<size_t>::max)();
    return false;
  }

  size = ba.size();
  hash = getBinaryArrayHash(ba);
  return true;
}

template<class T>
Crypto::Hash getObjectHash(const T& object) {
  Crypto::Hash hash;
  getObjectHash(object, hash);
  return hash;
}

uint64_t getInputAmount(const Transaction& transaction);
std::vector<uint64_t> getInputsAmounts(const Transaction& transaction);
uint64_t getOutputAmount(const Transaction& transaction);

// Overflow-checked variants of the above. Return false (and leave `out`
// undefined) if the uint64_t accumulator would wrap. Necessary on the CT
// pool accounting path: MONEY_SUPPLY (1e19) exceeds INT64_MAX, so a
// malicious transaction with large plain inputs can cause both uint64_t
// summation wraparound and signed-int64 sign flips. Callers on the
// consensus path MUST use the checked variants and reject on overflow.
bool getInputAmountChecked(const Transaction& transaction, uint64_t& out);
bool getOutputAmountChecked(const Transaction& transaction, uint64_t& out);

// Compute the visible-value delta a CT-aware transaction applies to the
// confidential pool in fully overflow-safe uint64_t arithmetic:
//   delta = plain_in - (plain_out + fee)
// where plain_in sums KeyInput.amount and plain_out sums output.amount
// (ConfidentialOutput contributes 0 because its .amount is masked to 0).
// On success exactly one of `inflow`/`outflow` is non-zero (both 0 for
// delta == 0). Returns false on any uint64_t overflow in summation —
// caller MUST reject the transaction in that case rather than silently
// truncating to a wrapped value.
bool computeCtPoolDelta(const Transaction& transaction, uint64_t fee,
                        uint64_t& inflow, uint64_t& outflow);

void decomposeAmount(uint64_t amount, uint64_t dustThreshold, std::vector<uint64_t>& decomposedAmounts);
}
