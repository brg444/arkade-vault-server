# Light renewal candidate

Light renewal replaces one live Spending output with an output under the exact enrolled Light script. Principal is unchanged except for the quoted Operator fee. Only that fee consumes the rolling 24-hour allowance; a renewal cannot send principal to another receiver or change payment limits.

The wallet uses the pinned Arkade SDK for intent construction, batch participation, MuSig signing, tree validation, and forfeit construction. The runtime independently verifies the named renewal operation before its Light key capability adds a policy signature. Neither route returns a cosigner key or a reusable signature service.

## Authorization and durable state

`POST /v1/light/renew/prepare` authenticates the owner's exact wallet, operation ID, and outpoint. It resolves the live input and current Operator fee policy, then reserves the fee under the same ledger lock and policy sequence used by payments. Registration binds the exact input, receiver, amounts, finite expiry, and client tree-signing key to the persisted plan. WebAuthn presence and a direct P-256 signature authorize that plan.

The final request contains the signed replacement tree, connector tree, commitment, and owner-signed forfeit. The runtime verifies aggregate keys, signatures, the release-pinned sweep policy, the same-wallet receiver, and the exact connector-backed forfeit. A durable dispatch marker is committed before either Operator mutation. An ambiguous response retains the reservation and is not automatically resubmitted.

Status requires both the indexer's matching settlement and an independently confirmed Bitcoin commitment before reporting confirmation. A known successful submission remains submitted while Bitcoin confirmation is pending. Before any forfeit dispatch, an expired registration can be released only after the runtime observes the original live output and atomically fences the old operation. A dispatched forfeit remains reserved until its outcome is established.

## Schema migration and rollback

Schema version 2 adds `light_renewal_operation` and `light_renewal_event`. Startup strictly validates the complete version 1 schema before creating these tables in one transaction. Existing table definitions, rows, MAC preimages, and cryptographic compatibility vectors are preserved. New records use distinct domains and are authenticated before their state influences allowance or dispatch decisions.

An older binary that understands only schema version 1 cannot open the migrated database. Retain renewal rows and the schema version during rollback. A rollback must use a schema-version-2-compatible binary and retain the database, keys, and independent policy sequence together. Disabling `VAULT_LIGHT_ENABLED` prevents new Light enrollment while preserving service for existing Light wallets and pending operations. `VAULT_INVITE_ONLY` is a separate admission setting.

## Release requirements

This candidate requires an updated wallet and runtime binary. It changes no hardware firmware, stock Operator binary, or SDK package lineage. The RC target is `rc.getvaulted.xyz`.

Keep Light disabled until the live payment, renewal, restart, retry, expiry, current recovery-data, and funded independent Bitcoin exit drills pass. Unit fixtures and a generated recovery file are not substitutes for those lifecycle results. The runtime's full check, race, lint, vulnerability, and image gates must also pass for the final commit.

## Qualification result — September 5, 2026

The real Mutinynet wallet passed enrollment, 50,000-sat receipt, a 10,000-sat policy-authorized payment, renewal of its 40,000-sat protected change, and recovery preparation with the Operator blocked. Status, registration, and finalization replay returned the same confirmed result before and after a process restart, with durable renewal events unchanged. A second restart with new Light enrollment disabled preserved existing-wallet access. Concurrent preparations produced one reservation, and an expired interrupted registration released idempotently.

Renewal commitment `3976d350f7026b89f908b142b2d636f8f39234818b02222977b6fb4c76c88ac0` produced `28c5de13b7841c29cff756f928b2c2021bab1a1114e30bb67baa6e03f85a173e:0`. That output's owner-only sweep `6d81bce760c9be5d6ededa382fc1ccedb000b0eecd3e5adadfd386d5063796df` confirmed at Mutinynet block 3402489, recovering 39,702 sats after a 298-sat sweep fee. The executor used the saved file and recovery secret, rejected all non-Bitcoin requests, and completed while the Vault service was stopped.

The runtime's local check, race, lint, vulnerability, and three-image gates passed, as did CI for implementation commit `5008c35`. Qualification is complete for the RC rollout, subject to green CI on the release commit. These results cover Light's direct Arkade Spending, manual renewal, and independent Bitcoin exit; they add no hardware guarantees, Light boarding, Lightning, or delegated-access qualification.
