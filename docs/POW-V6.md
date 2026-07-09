# Block-major v6 Proof-of-Work: windowed sequential full-block sampling

Status: implemented, pre-activation. `UPGRADE_HEIGHT_V6` is not yet scheduled on
mainnet, so this algorithm has never produced a mainnet block and is defined in
place — there is no dual-format / back-compat path. Authoritative code:
`Blockchain::getBlockLongHashV6` and the PoW-record helpers in
`src/CryptoNoteCore/Blockchain.cpp`; constants in `src/CryptoNoteConfig.h`.

This document explains what changed from v5, why, and — importantly — what this
does and does **not** buy us. Read the "Threat model" section before assuming
this is a botnet defense. It is not; it is a decentralization / pool-resistance
mechanism.

## 1. Background: the signed PoW family (v5)

Since block-major v5, Karbo uses an *Alternative Signed Proof-of-Work*:

- The block's hashing blob is signed with the coinbase output's ephemeral secret
  key (`Miner.cpp` step 1; verified in `Blockchain::validate_block_signature`).
  The signature covers the nonce, so **every nonce attempt requires re-signing
  with the key that controls the block reward**. You cannot hand a hashrate
  buyer a work unit without handing them the ability to steal the reward. This
  kills anonymous, custodial, rentable hashpower (NiceHash-style) and trustless
  pools. It is a *soft* property — a pool can still hand workers the per-template
  ephemeral key and rely on deposits/reputation — but it removes the frictionless
  rental market.
- v5 additionally samples 8 pseudo-random previous blocks' *hashing blobs* per
  round over 128 rounds, feeding the accumulated buffer to yespower
  (`y_slow_hash`, N=2048 r=32 → 8 MiB). This ties mining to possession of the
  header chain and resists trivial parallelization.

Two weaknesses of the v5 sampling layer motivated v6:

1. **The v6-draft "sequential" mix had a cache-resident shortcut.** The earlier
   v6 draft mixed only the first 4 bytes of each fetched blob into the chained
   state (`seq ^= load_u32_le(ba.data(), 0)`). A side table of "first 4 bytes per
   height" is `4 B × chain_len` — about 5 MB for a ~1.3M-block chain, i.e. it
   fits in L3 cache. With that table the entire per-iteration address schedule
   can be precomputed, collapsing the intended latency chain into parallel
   lookups.
2. **It was compute-bound, not possession-bound, once blobs were resident.**
   Hashing blobs are ~77 bytes; the whole set fits in RAM, so the "memory-hard"
   framing did little. The cost was dominated by keccak + yespower, and mining
   throughput scaled linearly with cores for everyone (nonce attempts are
   independent), so per-attempt sequentiality equalized per-core H/s but did not
   constrain parallel farms.

## 2. What v6 changes

v6 keeps the signed-blob layer verbatim (the anti-rental property is unchanged)
and **replaces the sampling layer** with a single sequential walk over
fixed-size *records* expanded from the **full bytes** of recent blocks, drawn
from a **bounded trailing window**.

### 2.1 Constants (`CryptoNoteConfig.h`)

| Constant | Value | Meaning |
|---|---|---|
| `POW_SAMPLE_WINDOW_V6` | 10800 | Trailing blocks eligible for sampling (~30 days at 240 s). |
| `POW_RECORD_SIZE_V6` | 16384 | Bytes per per-block record (expanded from full block bytes). |
| `POW_SLICE_SIZE_V6` | 64 | Bytes read per fetch. |
| `POW_FETCHES_V6` | 4096 | Sequential fetches per hash attempt. |

Working-set floor (resident records): `POW_SAMPLE_WINDOW_V6 × POW_RECORD_SIZE_V6`
≈ **170 MiB**, plus the unlock-window slack the cache keeps (`+ unlockWindow + 32`
records).

### 2.2 "PoW bytes" of a block

A pure function of the block:

```
powBytes(B) = serialize(B) || concat( serialize(tx) for tx in B.nonCoinbaseTxs, in header order )
```

`serialize(B)` already contains the coinbase. Because the same serialization is
used on every path, the main-chain live builder, the DB-rebuild path, and the
alternative-chain path all produce identical bytes (see §4).

### 2.3 Record expansion

Each block's PoW bytes are stretched to a fixed `POW_RECORD_SIZE_V6` record of
32-byte chunks:

```
c_0 = keccak(powBytes)
c_i = keccak(c_{i-1} || powBytes[64·(i-1) mod L .. +64))     (byte-wrapping window)
record = c_0 || c_1 || … || c_{R/32 - 1}
```

Every chunk re-absorbs a sliding 64-byte window of the raw block bytes, so a
record cannot be regenerated (even partially) without the raw block, and
regenerating a whole record costs ~`R/32` keccaks — expensive enough that keeping
the expanded window resident is the only rational miner configuration. That
resident window (~170 MiB, sustained-touched) is the memory floor the design
imposes.

### 2.4 The walk (`getBlockLongHashV6`)

```
pot   = signedHashingBlob(B)              // covers nonce + miner signature
s     = fold64(keccak(pot))               // 256-bit → 64-bit state
hi    = height(B) - 1 - unlockWindow      // exclusive top of window (reorg-safe)
lo    = max(0, hi - POW_SAMPLE_WINDOW_V6)
span  = hi - lo

repeat POW_FETCHES_V6 times:
    s      = splitmix64(s)
    height = lo + ( (s>>32) · span ) >> 32                 // which block
    s      = splitmix64(s)
    off    = ( (s>>32) · (R - 64 + 1) ) >> 32              // where in its record
    slice  = record(height)[off .. off+64)
    s     ^= fold of all 64 slice bytes                    // full-slice fold
    pot   = pot || slice

pot = pot || s
PoW = yespower( keccak(pot), pot )
```

Key points:

- **No cache-resident shortcut.** The next address depends on *all 64 bytes* of
  the previous slice, taken at a uniformly random offset within the record.
  There is no fixed-size digest of a record that answers arbitrary-offset queries
  — any precomputation that drives the walk must be as large as the record set
  itself. This is the direct fix for weakness (1).
- **Sequential and possession-bound.** Fetch *k+1*'s address is unknown until
  fetch *k*'s bytes are in hand, so the 4096 reads cannot be issued in parallel,
  and they require possession of (records derived from) the full recent window.
- **Every read feeds the output.** All fetched slices accumulate into `pot`,
  which is what yespower consumes, so there is no early-exit: you cannot skip a
  fetch you "don't like."
- **Windowed.** Only the last `POW_SAMPLE_WINDOW_V6` blocks (below the
  unlock-window reorg-exclusion zone) are eligible. This bounds the working set
  forever, makes IBD/pruned validation of PoW possible (you need only the window,
  not all history), and converts "possession of history" into "possession of the
  *current* chain" — a synced-node liveness proof. A stale snapshot stops being
  minable within ~`POW_SAMPLE_WINDOW_V6` blocks.

## 3. Record cache lifecycle

A full node keeps the window's records in RAM (`m_powRecords`, a `std::deque`
based at `m_powRecordsBase`), maintained in lockstep with the chain:

- **Build**: on startup for `[chainHeight − cap, chainHeight)` and appended per
  block in the inner `pushBlock`, where the `BlockEntry` already holds coinbase +
  all tx bodies. `cap = POW_SAMPLE_WINDOW_V6 + unlockWindow + 32`.
- **Pop/trim**: `removeLastBlock` and every batch-abort path trim records above
  the committed chain height (mirrors the `m_blobs` handling).
- **Gated**: `shouldMaintainPowRecords` returns false until heights can fall
  inside a v6 block's window, so on mainnet (v6 not scheduled) the cache costs
  nothing.
- **`--no-blobs`**: the cache is skipped entirely; records are rebuilt on demand
  from the DB.

The cache is an **optimization only**. A miss (or `--no-blobs`) falls back to
`buildPowRecordFromDb`, which reconstructs identical bytes from stored block +
tx blobs. The cache can never change a PoW value.

## 4. Consensus determinism across chains

The PoW of a block is computed once, at acceptance. It must match whether
computed by the miner, by main-chain acceptance, or by another node seeing the
block as an alternative. That holds because a sampled height resolves to the
*same block content* on every honest view:

- **Main-chain acceptance / mining**: sampled heights resolve to main-chain
  blocks via the record cache or `buildPowRecordFromDb`. The built-in miner only
  extends the main tip (empty alt-chain), so it samples exactly what the network
  will.
- **Alternative-chain acceptance**: when a block is validated on a fork, sampled
  heights above the split point must resolve to *that fork's* blocks (that is
  what its miner sampled). `getBlockLongHashV6` indexes the supplied `alt_chain`
  by height and rebuilds those records from the alt `BlockEntry`'s bytes via
  `buildPowRecordFromEntry`. For this to work, an alt block's non-coinbase tx
  bodies are resolved (from pool + main chain) into `BlockEntry.transactions`
  when the block is handled (`resolveAltBlockTransactions`). Heights below the
  split resolve to shared main-chain history.

Because `powBytes` is a pure function of block content and the same serialization
is used everywhere, all three paths produce byte-identical records → identical
PoW. The bundled test (`tests/test_pow_v6.cpp`) checks this end to end, including
a reorg deeper than the unlock window (so the alt-record path is exercised) and a
full replay of the reorged chain into a fresh node (so the DB-rebuild path is
proven to agree with the live cache).

### Notes / edge cases

- A sampled alt height whose tx bodies are momentarily unavailable makes that
  fork's descendant PoW unverifiable until the bodies arrive — the block is still
  stored, and the same unavailability would block the reorg from completing
  anyway, so this is self-consistent and self-healing, not a safety break.
- Young chains (height ≤ unlockWindow+1) clamp to `hi = 1`, `span = 1` (sample
  genesis only). Degenerate but deterministic; irrelevant on mainnet where v6
  activates far above the window.

## 5. Threat model — what this does and does not do

The security boundary.

**Solved / strengthened (decentralization & pool/ASIC/rental resistance):**

- *Outsourcing / rental*: killed by the signed-blob layer (unchanged from v5).
- *SPV/blob-light mining*: killed. v6 needs full block bytes, not just headers.
- *Parallelization within an attempt*: prevented by the data-dependent sequential
  walk; the 4-byte side-table shortcut is closed.
- *Possession of the live chain*: enforced and bounded — mining requires a synced
  node holding the recent window, and only that window.

**Explicitly NOT solved (botnets):**

- v6 does nothing to exclude botnets, and no data-access/windowing/CPU-algorithm
  trick can. Every infected machine has a CPU; anything small enough to be
  friendly to a casual CPU miner (a ~170 MiB window) is small enough for a botnet
  to replicate. Compare Monero/RandomX: a 2 GiB dataset + per-VM state, and
  XMRig remains the top cryptojacking payload. Hardware scarcity is the only
  exclusion lever (GPU-saturating PoW), and it trades the CPU-miner constituency
  for GPU farms; a capital/stake requirement (POWS-style) is the only non-hardware
  lever and trades permissionless mining. Neither is in scope here.

**v6 is a decentralization and anti-pool/anti-rental mechanism. 
Botnet resistance, if desired, is a separate layer (hardware-scarce compute 
or a stake requirement) layered on top — not a substitute, and not
something this PoW claims to provide.**

## 6. Regression gate

`tests/test_pow_v6.cpp` (CTest target `PowV6Tests` → `pow_v6_tests`):
grows a testnet-currency chain across the v5→v6 boundary at difficulty 1, forces
a reorg deeper than the unlock window, asserts the switch and post-reorg chain
state, and replays the reorged chain into a fresh node. A crash, a failed record
assembly, or a `getBlockLongHash` returning false all fail the test.
