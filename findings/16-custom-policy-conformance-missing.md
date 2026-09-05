## Severity

Info (documented guarantee does not exist)

## Status

Static analysis. Encodings are policy-independent; policy-digest byte equality
verified empirically for default/preset/max-bound policies.

## Affected Code / Docs

- `docs/testing.md:35-36` (wallet repo) — claims cross-language conformance pins a **custom-policy** descriptor hash
- Wallet: `src/lib/vault/program/savings-vectors.test.ts:27-41` — default policy only
- Server: `internal/vault/savings/vectors_test.go:39-44` — `program.DefaultSpendingPolicy()` only

## Summary

The shared savings vectors pin only the **default** policy in both repos.
Custom-policy checks are same-language only (`descriptor.test.ts:56-70` in the
wallet; `family_test.go:95-136` in the server). The vector files have also
drifted: the server copy adds `protectionTier` per vector while the wallet
copy lacks it.

## Recommendation

Add a custom-policy vector to the shared vector set in both repos and
re-synchronize the file contents.
