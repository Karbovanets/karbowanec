# CT Checkpoint Trust Model

Karbo supports checkpointed sync to avoid repeating expensive historical
validation for blocks that the operator chooses to trust. This matters more
after CT because full validation includes Triptych proofs, GK proofs, CT
balance kernels, ring resolution, and related amount-accounting checks.

## Default Sync

By default the daemon loads built-in checkpoints and signed DNS checkpoints.
An operator can also load a checkpoint file with `--load-checkpoints`.

A checkpoint is trusted when it comes from one of these sources:

- the checkpoint table compiled into the binary
- a checkpoint file explicitly supplied by the operator
- a DNS checkpoint whose signature verifies against `DNS_CHECKPOINT_SIGNERS`

Unsigned or malformed DNS checkpoint records are rejected before they become
checkpoints.

Inside the trusted checkpoint zone, the daemon still verifies that the block
hash matches the checkpoint anchor. It also continues to run structural CT
sanity checks such as version and shape checks, subgroup checks, key-image
domain checks, canonical ordering checks, and double-spend checks.

The daemon may skip expensive historical validation that the checkpoint
authorizes, including local PoW for checkpointed blocks and full CT proof
verification. This is the intended checkpoint tradeoff: faster sync in exchange
for trusting the checkpoint source for already-checkpointed history.

## Full Local Validation

Operators who do not want to trust checkpoints should start the daemon with:

```text
--without-checkpoints
```

That mode does not seed the checkpoint table. Historical blocks are validated
locally instead of being routed through checkpoint shortcuts.

## Publishing Policy

Do not publish a built-in, file, or signed DNS checkpoint until the block has
already been fully validated by a node that was not relying on a checkpoint for
that block. For CT-era blocks, that full validation must include the Triptych,
GK, balance-kernel, ring-resolution, key-image, and supply-accounting checks.

Treat checkpoint signing keys as consensus-sensitive infrastructure. A bad
checkpoint can cause default-syncing nodes to accept the signer's assertion for
historical data until operators resync without checkpoints or upgrade to a
release that removes or supersedes the checkpoint.
