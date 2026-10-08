# Pending consensus changes for the next hard fork

Consensus-affecting fixes that are known but can't ship in a regular release,
because changing them alters block validity. Each entry should be activated
together with the next block major version (currently `BLOCK_MAJOR_VERSION_6`;
`UPGRADE_HEIGHT_V6` is still unscheduled in `src/CryptoNoteConfig.h`), with the
old behaviour kept bit-for-bit for blocks below it.

## 1. yespower ignores its personalization seed (`pers`)

**Status:** open. Affects PoW of block major version 5 (live since height 700000).

### Symptom

`Crypto::y_slow_hash(data, len, seed, hash)` (`src/crypto/hash.h`) passes `seed`
to yespower as `pers`, but the output does not depend on it: any seed,
including all zeros, gives the same hash for the same `data`. In
`Blockchain::getBlockLongHash` the seed is `hash_1` (the last `cn_fast_hash` of
the mixed pot), so the intended extra binding of the PoW to that value is
absent.

### Root cause

`src/crypto/blake256.c`: `blake256_update` and `hmac_blake256_update` take the
data length in **bits**, but `pbkdf2_blake256` passes **byte** counts:

| Call in `pbkdf2_blake256` | Passed | Should be |
|---|---|---|
| `hmac_blake256_update(&PShctx, salt, saltlen)` | 32 | 256 |
| `hmac_blake256_update(&hctx, ivec, 4)` | 4 | 32 |
| `hmac_blake256_update(&hctx, U, 32)` (only when `c > 1`) | 32 | 256 |

With yespower's 32-byte `pers`, the inner HMAC state after the key-pad block
has absorbed only 36 bits (32 + 4). `blake256_final_h` then appends padding,
the `pb` byte and the 64-bit length via further bit-length updates, but the
total never reaches 512 bits, so **no compression runs after the key-pad
block**. The inner digest therefore equals the state after the key pad alone:
it depends on the HMAC key (`blake256(data)`) but on neither the salt (`pers`)
nor the block index. Consequences inside yespower (`src/crypto/yespower.c`,
`pbkdf2_blake256(init_hash, 32, pers, 32, 1, B, 128)`):

- `pers` has no effect on the result.
- The four 32-byte PBKDF2 output blocks are identical, so the initial 128-byte
  `B` holds 32 bytes of distinct material repeated four times.

`hmac_blake256_hash` (used for the final yespower output) multiplies by 8
correctly, so it is not affected. `pbkdf2_blake256` has no other callers.

### Impact

Low. The PoW still commits to the whole pot through `blake256(data)` and the
memory-hard `smix`, so it isn't a shortcut for miners. But the algorithm isn't
the one specified: the seed parameter is dead, and the PBKDF2 expansion is
weaker than intended. Any future PoW change that relies on `pers` for domain
separation would silently fail.

### Fix plan (hard fork)

1. Keep the current function, renamed to something like
   `pbkdf2_blake256_legacy`, used by yespower for blocks below the fork
   version. It must stay byte-for-byte identical; `Yespower.knownAnswers` in
   `tests/UnitTests/TestYespower.cpp` already pins its output.
2. Add a corrected `pbkdf2_blake256` that passes `saltlen * 8`, `4 * 8` and
   `32 * 8`, and a yespower variant (or a flag in `yespower_params_t`) that
   uses it.
3. Make `y_slow_hash` take the block major version, or add `y_slow_hash_v6`,
   and select the variant in `Blockchain::getBlockLongHash` by
   `b.majorVersion >= BLOCK_MAJOR_VERSION_6`. The miner's template hashing
   must use the same switch.
4. Add known-answer vectors for the new variant, including a check that
   different seeds give different hashes and that the four PBKDF2 blocks
   differ.
5. Optionally, take the opportunity to add explicit domain separation to the
   seed (for example, hash a version tag together with `hash_1`).

Pools and third-party miners that reimplement Karbo's yespower need the same
change at the fork height.
