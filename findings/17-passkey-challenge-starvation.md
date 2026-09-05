## Severity

Info / Low (DoS on non-spending vault operations)

## Status

Static analysis.

## Affected Code

- `internal/application/session.go:166-230` — `IssuePasskeyChallengeFor`
- Wallet edge: `api/authorizer/[...path].ts:74-84` — per-IP rate limiting only

## Summary

`IssuePasskeyChallengeFor` is unauthenticated beyond the gateway boundary and
caps pending challenges at 16 per vault. An attacker who knows a vaultId can
hold 16 challenges open continuously and block the legitimate user's passkey
sessions (transitions / recovery / map-write / envelope). Edge rate limiting
is per-IP, not per-IP-per-vault. Spending is unaffected (separate digest-bound
ceremony).

## Recommendation

Add per-IP-per-vault rate limiting, or authenticate challenge issuance.
