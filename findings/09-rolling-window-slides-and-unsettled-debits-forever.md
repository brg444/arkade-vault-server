# Rolling-24h Accounting Extends Debit Window Past Settlement; Unsettled Ops Debit Forever

## Severity

Medium (fail-closed, but permanent allowance drain possible)

## Status

Static analysis. One behavior pinned as deliberate by
`TestVtxoReservationKeepsChainProvenUnresolvedRowAsGlobalFence`.

## Affected Code

- `/home/ubuntu/arkade-vault-server/internal/application/vtxo.go:875,890` — `promoteSubmittedVtxo` rewrites `CreatedAt`
- `/home/ubuntu/arkade-vault-server/internal/policy/ledger.go:238-240` — `spentInWindow`
- `/home/ubuntu/arkade-vault-server/internal/policy/vtxo.go:512-533` — awaiting-settlement / `unresolved` fencing
- Wallet display: `src/screens/Vault/Send.tsx:286-288`

## Summary

Two deviations from the displayed "rolling 24-hour limit" model:

1. **Debit window slides at settlement.** `promoteSubmittedVtxo` rewrites
   `CreatedAt` on transition to unresolved/finalized, so the 24h debit window
   runs from the *settlement event*, not the payment.
2. **Unsettled operations debit forever.** Signed/submitted-but-never-final
   operations count toward the allowance indefinitely; an operator that never
   settles a signed operation permanently drains the allowance. The
   `unresolved` state has no exit transition (`vtxo_ledger.go:392-403`) and
   additionally fences all new operations.

The wallet surfaces only "This send did not finish. Refresh your balance
before trying again." (`spend.ts:111-121`, `humanize.ts:34-36`) and never
directs the user to the 4608-second unilateral exit that becomes their only
spend path.

## Recommendation

Anchor the debit window to the original authorization time; define a terminal
transition for `unresolved` (or age rows out of the window); when fenced,
surface the unilateral-exit path in the UI.
