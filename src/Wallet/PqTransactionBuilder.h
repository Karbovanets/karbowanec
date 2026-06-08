// Copyright (c) 2026, The Karbo developers
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

#include <vector>

#include "CryptoNote.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqDerive.h"

// High-level builders for the PQ transaction family (spec §6/§8, ownership fix
// in docs/PQ-OWNERSHIP-FIX.md). These assemble a fully-signed CryptoNote::
// Transaction the node will accept; tests previously hand-rolled this.
//
// This header covers TX_PQ (PQ inputs -> PQ outputs), which is node-independent
// (no ring/mixin resolution). TX_BRIDGE (classical inputs -> PQ outputs) reuses
// the legacy ring-signature machinery and is added separately.

namespace CryptoNote {

// A PQ output this wallet owns and is spending. `rho` comes from the scan record
// (CryptoPQ::PqOwnedOutput.rho); the wallet authorizes the spend with its
// long-term ML-DSA spend secret, not with anything derived per-output.
struct PqSpendInput {
  Crypto::Hash  prevTxid{};
  uint32_t      prevOutIndex = 0;
  uint64_t      amount = 0;
  CryptoPQ::Rho rho{};
};

// A recipient of one new PQ output (public address material only).
struct PqSendOutput {
  CryptoPQ::KemPublicKey recipientViewPub{};
  CryptoPQ::DsaPublicKey recipientSpendPub{};
  uint64_t               amount = 0;
};

// Build and sign a TX_PQ.
//
//   spendPub / spendSk : the spender's long-term ML-DSA keypair (derivePqWalletKeys).
//   fee = sum(input amounts) - sum(output amounts), computed implicitly; the
//   caller sizes outputs to leave the intended fee. Throws std::runtime_error on
//   empty/oversized input or output sets or if outputs exceed inputs.
//
// Every input is authorized by an ML-DSA signature over the canonical signing
// digest (pqSigningDigest). `spendSk` is used only here and should be derived on
// demand and discarded by the caller after the call returns.
Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const CryptoPQ::DsaPublicKey& spendPub,
                               const CryptoPQ::DsaSecretKey& spendSk,
                               uint64_t unlockTime = 0);

}  // namespace CryptoNote
