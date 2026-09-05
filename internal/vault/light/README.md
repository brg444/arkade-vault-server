# Light contract and integration candidate

This package constructs `vault-light-policy-v1` for the compiled `vaulted-light-v1` profile. Light enrollment and shared Spending authorization are implemented in the application layer; `VAULT_LIGHT_ENABLED` defaults to `false` while renewal and funded lifecycle qualification remain incomplete.

The cooperative leaf requires the owner, independent Vault policy cosigner, and stock Arkade Operator. The second leaf gives the same owner a delayed Bitcoin exit. Both networks use their frozen Operator and delay pins. Enrollment binds the independently derived cosigner and immutable policy; Bitcoin Script does not enforce a rolling allowance.

The owner exit runs outside cooperative payment limits. Script-engine tests cover the correct owner, early claims, timelock units, transaction version, and relative-locktime disable flag. A funded exit additionally requires current transaction paths, confirmation timing, Bitcoin fees, and owner-key restoration.

`testdata/contracts.json` remains shared byte-for-byte with the wallet. Both implementations reconstruct scripts, output keys, and descriptor hashes independently. Light identities use their own MAC-bound template and policy schema with empty hardware/Savings fields; existing Standard and Advanced records remain unchanged. Light derives its cosigner using its own named-program domain and reuses the authenticated allowance and operation ledger.

The shared admission policy remains authoritative. With `VAULT_INVITE_ONLY=false`, Light uses the normal short-lived admission session. The separate Light rollout flag controls new starts, preserves existing wallets when disabled, and does not alter invitation policy. HTTP compatibility tests record the three new enrollment routes and added status fields; the existing Contract Pack, ledger schema, and cryptographic vectors are unchanged.

Activation requires a bounded renewal authorization with durable fees, input conflicts, replay, and ambiguous-outcome handling, followed by funded Mutinynet payment and recovery drills. Funded lifecycle readiness remains unverified despite the passing contract, enrollment, signing, browser, and race tests.
