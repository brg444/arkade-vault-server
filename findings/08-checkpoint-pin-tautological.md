# Chain-Checkpoint Pins Never Verified Against the Live Chain (Tautological Check)

## Severity

Medium

## Status

Static analysis.

## Affected Code

- `/home/ubuntu/arkade-vault-server/internal/application/ark_resolver.go:69-75`
- `/home/ubuntu/arkade-vault-server/internal/deployment/config.go:19` (`MutinynetCheckpoint1`)
- `/home/ubuntu/arkade-vault-server/internal/deployment/identity.go:10` (`BitcoinGenesisHash`)
- `/home/ubuntu/arkade-vault-server/internal/application/vault_board_chain.go:118-206`

## Summary

The resolver check compares `id.CheckpointHeight/Hash` to
`deployment.Config.BitcoinCheckpoint()` — both sides come from the **same**
`IdentityFor` table, so the check is tautological. Neither
`MutinynetCheckpoint1` nor `BitcoinGenesisHash` is ever matched against a live
esplora/bitcoind response; the esplora client validates response shape and
internal consistency only.

## Impact

Chain identity rests solely on the pinned HTTPS origins. A wrong-chain esplora
served behind a pinned origin (misconfiguration, TLS/DNS compromise) would be
accepted; all downstream MTP/boarding finality math would then be computed
against the wrong chain.

## Recommendation

On startup (and periodically), fetch block 1 (mutinynet) or the genesis hash
(mainnet) from the configured esplora and compare to the pinned constant; fail
closed on mismatch.
