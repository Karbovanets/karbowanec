// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin developers
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

#pragma once

#include <map>
#include <mutex>
#include <set>

#include <CryptoNoteCore/CryptoNoteBasicImpl.h>
#include <Logging/LoggerRef.h>

namespace CryptoNote
{
  class Checkpoints
  {
  public:
    Checkpoints(Logging::ILogger& log, uint32_t reject_deep_reorg_depth = 0);

    Checkpoints& operator=(Checkpoints const& other)
    {
      if (&other != this)
      {
        // lock both objects
        std::unique_lock<std::mutex> lock_this(m_mutex, std::defer_lock);
        std::unique_lock<std::mutex> lock_other(other.m_mutex, std::defer_lock);
        std::lock(lock_this, lock_other); // ensure no deadlock
        m_points = other.m_points;
        logger = other.logger;
      }

      return *this;
    }

    // `hardcoded`: whether this checkpoint comes from a trusted source — the
    // baked-in CryptoNote::CHECKPOINTS table, or an operator-supplied file
    // loaded via --load-checkpoints (both inherit the trust of the binary or
    // its operator). DNS-added checkpoints pass `hardcoded=false` since DNS
    // TXT records have no cryptographic signature and a path-on-attacker can
    // inject arbitrary height→hash mappings. The flag is consulted by
    // is_in_hardcoded_checkpoint_zone() to decide whether expensive consensus
    // validation (in particular: the CT structural-only fast path) is allowed
    // to short-circuit. The default is true to preserve the semantics of all
    // existing call sites (binary table, file load) without per-call updates.
    bool add_checkpoint(uint32_t height, const std::string& hash_str, bool hardcoded = true);
    bool load_checkpoints_from_file(const std::string& fileName);
    bool load_checkpoints_from_dns();
    bool is_in_checkpoint_zone(uint32_t height) const;
    // True iff `height` is at or below the largest *hardcoded* checkpoint
    // height. Excludes DNS-added checkpoints from the zone determination —
    // those serve only as anchor hints in check_block(), they do not grant
    // the bypass that hardcoded checkpoints do. Returns false when no
    // hardcoded checkpoints have been seeded (e.g. testnet, --disable-checkpoints).
    bool is_in_hardcoded_checkpoint_zone(uint32_t height) const;
    bool check_block(uint32_t height, const Crypto::Hash& h) const;
    bool check_block(uint32_t height, const Crypto::Hash& h, bool& is_a_checkpoint) const;
    bool is_alternative_block_allowed(uint32_t blockchain_height, uint32_t block_height) const;
    std::vector<uint32_t> getCheckpointHeights() const;
    uint32_t getRejectDeepReorgDepth() const { return m_reject_deep_reorg_depth; }

  private:
    std::map<uint32_t, Crypto::Hash> m_points;
    // Subset of m_points whose source was trusted at insertion time. Tracked
    // as a parallel index (rather than embedded in the value of m_points) so
    // existing iteration patterns over m_points stay unchanged.
    std::set<uint32_t> m_hardcoded_heights;
    Logging::LoggerRef logger;
    mutable std::mutex m_mutex;

    uint32_t m_reject_deep_reorg_depth;
  };
}
