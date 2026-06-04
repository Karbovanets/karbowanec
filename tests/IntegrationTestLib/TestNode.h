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

#include <system_error>
#include <INode.h>
#include "CryptoNoteCore/Account.h"
#include "IWallet.h"
#include "IWalletLegacy.h"

namespace Tests {

// Construct an AccountKeys from a legacy wallet. IWalletLegacy is the
// single-address API used throughout these integration tests; it exposes
// getAccountKeys directly.
inline CryptoNote::AccountKeys accountKeysFromWallet(CryptoNote::IWalletLegacy& wallet) {
  CryptoNote::AccountKeys keys;
  wallet.getAccountKeys(keys);
  return keys;
}

// Construct an AccountKeys from a multi-address IWallet, at a given
// subaddress index. IWallet exposes per-address spend keys plus a shared
// view key; we assemble both into a flat AccountKeys for TestNode's
// signed-PoW miner interface.
inline CryptoNote::AccountKeys accountKeysFromWallet(CryptoNote::IWallet& wallet, size_t addressIndex) {
  CryptoNote::AccountKeys keys;
  auto spend = wallet.getAddressSpendKey(addressIndex);
  auto view  = wallet.getViewKey();
  keys.spendSecretKey = spend.secretKey;
  keys.viewSecretKey  = view.secretKey;
  keys.address.spendPublicKey = spend.publicKey;
  keys.address.viewPublicKey  = view.publicKey;
  return keys;
}

// Note on API shape change:
//
// startMining() and getBlockTemplate() used to accept the miner's address as
// a Base58 string. That was correct for the Bytecoin-era Core where the
// miner only needed the public address to derive coinbase output keys.
// Karbo v5+ introduced signed Proof-of-Work — blocks are signed by the
// miner's spend key — and both the in-process miner (CryptoNote::miner)
// and the start_mining RPC now require the full AccountKeys
// (spend secret + view secret; public components derive deterministically
// from those). The interface here was lifted to match: callers must pass
// the AccountKeys they already hold (wallet->getAccountKeys / a generated
// AccountBase) instead of a string. The string→keys back-projection is
// not possible because the address loses the secret-key bits, which is
// the entire point of an address. See:
//   - src/CryptoNoteCore/Miner.h  (bool start(const AccountKeys&, size_t))
//   - src/CryptoNoteCore/Core.h   (get_block_template signature)
//   - src/Rpc/CoreRpcServerCommandsDefinitions.h
//       (COMMAND_RPC_START_MINING::request now has miner_spend_key /
//        miner_view_key fields, no more miner_address)
class TestNode {
public:
  virtual bool startMining(size_t threadsCount, const CryptoNote::AccountKeys& keys) = 0;
  virtual bool stopMining() = 0;
  virtual bool stopDaemon() = 0;
  virtual bool getBlockTemplate(const CryptoNote::AccountKeys& minerKeys, CryptoNote::Block& blockTemplate, uint64_t& difficulty) = 0;
  virtual bool submitBlock(const std::string& block) = 0;
  virtual bool getTailBlockId(Crypto::Hash& tailBlockId) = 0;
  virtual bool makeINode(std::unique_ptr<CryptoNote::INode>& node) = 0;
  virtual uint64_t getLocalHeight() = 0;

  std::unique_ptr<CryptoNote::INode> makeINode() {
    std::unique_ptr<CryptoNote::INode> node;
    if (!makeINode(node)) {
      throw std::runtime_error("Failed to create INode interface");
    }

    return node;
  }

  virtual ~TestNode() {}
};

}
