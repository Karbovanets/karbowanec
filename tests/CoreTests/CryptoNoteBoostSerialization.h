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

#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/variant.hpp>
#include <boost/blank.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/map.hpp>
#include <boost/foreach.hpp>
#include <boost/serialization/is_bitwise_serializable.hpp>
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "UnorderedContainersBoostSerialization.h"
#include "crypto/crypto.h"

//namespace CryptoNote {
namespace boost
{
  namespace serialization
  {

  //---------------------------------------------------
  template <class Archive>
  inline void serialize(Archive&, boost::blank&, const boost::serialization::version_type)
  {
  }

  template <class Archive>
  inline void serialize(Archive &a, Crypto::EllipticCurvePoint &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::EllipticCurvePoint)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, Crypto::EllipticCurveScalar &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::EllipticCurveScalar)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, Crypto::PublicKey &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::PublicKey)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, Crypto::SecretKey &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::SecretKey)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, Crypto::KeyDerivation &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::KeyDerivation)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, Crypto::KeyImage &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::KeyImage)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, Crypto::Signature &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::Signature)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, Crypto::Hash &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(Crypto::Hash)]>(x);
  }
  
  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::KeyOutput &x, const boost::serialization::version_type ver)
  {
    a & x.key;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::BaseInput &x, const boost::serialization::version_type ver)
  {
    a & x.blockIndex;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::KeyInput &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.outputIndexes;
    a & x.keyImage;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::RingMemberRef &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.outputIndex;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::ConfidentialInput &x, const boost::serialization::version_type ver)
  {
    a & x.ringMembers;
    a & x.ringPubkeys;
    a & x.ringCommitments;
    a & x.pseudoCommitment;
    a & x.keyImage;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::ConfidentialOutput &x, const boost::serialization::version_type ver)
  {
    a & x.targetKey;
    a & x.commitment;
    for (auto& byte : x.maskedAmount) {
      a & byte;
    }
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::CTInputSignature &x, const boost::serialization::version_type ver)
  {
    a & x.I_bits;
    a & x.A;
    a & x.B;
    a & x.Q_P;
    a & x.Q_M;
    a & x.Q_U;
    a & x.z;
    a & x.za;
    a & x.zb;
    a & x.f_P;
    a & x.f_M;
    a & x.f_U;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::CTOutputProof &x, const boost::serialization::version_type ver)
  {
    for (size_t i = 0; i < 6; ++i) {
      a & x.I[i];
      a & x.A[i];
      a & x.B[i];
      a & x.Q[i];
      a & x.z[i];
      a & x.za[i];
      a & x.zb[i];
    }
    a & x.f;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::TransactionKernel &x, const boost::serialization::version_type ver)
  {
    a & x.excessCommitment;
    a & x.sigE;
    a & x.sigS;
  }

  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::TransactionOutput &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.target;
  }


  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::Transaction &x, const boost::serialization::version_type ver)
  {
    a & x.version;
    a & x.unlockTime;
    a & x.inputs;
    a & x.outputs;
    a & x.extra;
    a & x.signatures;
  }


  template <class Archive>
  inline void serialize(Archive &a, CryptoNote::Block &b, const boost::serialization::version_type ver)
  {
    a & b.majorVersion;
    a & b.minorVersion;
    a & b.timestamp;
    a & b.previousBlockHash;
    a & b.nonce;
    //------------------
    a & b.baseTransaction;
    a & b.transactionHashes;
  }
}
}

//}
