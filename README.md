# Arkade Runtime

**A compiled runtime for policy-constrained signing, recovery, and stateful
applications built with Arkade.**

> [!WARNING]
> This release candidate runs only on Mutinynet. Real-fund custody is out of
> scope. Mainnet requires reviewed Emulator and Operator pins and
> hardware-isolated VaultCosigner keys.

Arkade Runtime hosts immutable application profiles that compose named
programs, policies, stores, key capabilities, routes, and lifecycle checks.
Profiles are linked into the binary and selected when the process starts; the
runtime exposes no dynamic plugin loader, arbitrary signing API, or mutable
policy registry.

The first compiled profile is `arkade-vault-v1`, used by
[Vaulted](https://github.com/brg444/vaulted-bitcoin-wallet). It combines
Arkade's VTXO and collaborative-signing foundation with stateful Spending
limits, passkey authorization, L1 Savings verification, and delayed recovery.
This profile is one application of the Runtime—not the boundary of what the
Runtime can host.

## Runtime model

| Layer | Responsibility |
| --- | --- |
| Runtime | Compiles immutable profile metadata, mounts one selected profile, and owns readiness, lifecycle, and shutdown. |
| Profile | Defines one complete application composition and its allowed modules, routes, stores, and key scopes. |
| Module | Groups named programs and policies behind narrow semantic capabilities. |
| Program | Defines versioned transaction, signing, and recovery behavior shared with its client. |

The current binary deliberately compiles only `arkade-vault-v1`. Adding a
future profile is a source-reviewed composition and release decision; it cannot
be installed or selected through an external request.

## Current Vault profile

The Vault profile helps contain a compromised phone and coordinate recovery
after a key is lost. It owns the service key used by the Spending policy and
the authoritative allowance ledger. It cannot spend Savings by itself, build
arbitrary transactions, broadcast Savings transfers, or expose a raw signing
API.

The security model is deliberately narrow:

- **Limits contain compromise.** The profile enforces the vault's immutable
  per-payment and rolling Spending limits before adding its approval.
- **Independent keys protect Savings.** Routine Savings transfers require the
  user's device and hardware keys; the Runtime has no ordinary Savings-spend key.
- **Delayed recovery protects against loss.** The profile validates recovery and
  clawback transitions, while Bitcoin scripts enforce the waiting period and
  preserve time to cancel an unauthorized attempt.

Arkade supplies the VTXO lifecycle, collaborative signing paths, checkpoints,
forfeiture mechanics, and Operator coordination on which the current profile
is built. The profile independently verifies each permitted transaction and
its policy state before contributing a constrained signature.

The wallet and server independently validate the same versioned Vault Program.
The server may add a VaultCosigner signature only after the complete operation
matches that program and its stateful allowance. Bitcoin scripts and committed
transaction paths retain the structural spending and recovery constraints.

This release hosts one compiled program, `vault-policy-v1`, with an immutable
policy instance and protection tier for each vault. `standard` forbids a
recovery key; `advanced` requires a recovery key distinct from the other
enrolled roles. Enrollment freezes both values before the passkey ceremony.
The Spending choice is Lower exposure (25,000 sats per send and 50,000 sats
per rolling 24 hours), Everyday (50,000 and 100,000 sats respectively), or
custom values for those two limits. Every choice uses the release-managed
ceilings of 5,000 sats and 10 sat/vB. The wallet and server independently
rebuild the same descriptor and persist the selection in the authenticated
vault record. The service does not load arbitrary policy code or allow these
conditions to change after enrollment.

## What the Vault profile can—and cannot—do

| Event | Outcome |
| --- | --- |
| Phone is compromised | The attacker remains constrained by the enrolled Spending limits and cannot spend Savings with the phone alone. |
| Hardware key is lost | An enrolled delayed recovery path can move Savings after its waiting period; guardians can cancel an unexpected attempt. |
| Runtime service is unavailable | New policy-assisted Spending and service-assisted recovery pause, but the service does not gain custody and cannot take Savings. |
| VaultCosigner key is compromised | Spending policy authorization is weakened, but the attacker still needs the other required transaction signatures. Savings remains protected by its independent keys and scripts. |

## Responsibilities

The service is organized around four product workflows:

| Workflow | Server responsibility | Wallet responsibility |
| --- | --- | --- |
| Enrollment | Validate and freeze the selected protection tier and Spending preset, consume an invitation, verify the passkey ceremony, derive the tenant VaultCosigner, and persist the immutable descriptor. | Choose a protection tier and Spending preset, create the device credential and permitted keys, reconstruct and review the proposed descriptor, and retain encrypted recovery material when applicable. |
| Spending | Authenticate and reserve policy VTXOs, enforce the rolling allowance and fee cap, validate the complete Arkade transaction and checkpoints, sign, and reconcile an ambiguous response by operation ID. | Persist the operation, phone-sign the reservation, confirm the quoted fee, obtain device authorization, coordinate the Operator exchange, finalize, and post the receipt. |
| Savings | Rebuild and verify the L1 Savings program when authorizing a recovery transition. | Construct and sign Savings transfers with the device and hardware keys. The server does not publish them. |
| Recovery | Authorize `initiate` and `clawback` transitions, verify passkey sessions, and store authenticated encrypted map data. | Hold claimant and guardian keys, broadcast transitions, and claim after the committed delay. |

Spending uses `vault-policy-v1`. Its collaborative leaf requires the user,
VaultCosigner, and Arkade Operator. Savings remains an L1 vault and has no
routine path that the VaultCosigner can use to pay an arbitrary recipient.

The VaultCosigner key and ledger intentionally share one protected process.
Separating the key from the authoritative allowance would create a path that
could sign without observing the policy state.

## VTXO lifecycle

A Spending send is one durable operation, not a collection of unrelated HTTP
requests:

1. The wallet persists a client-generated operation ID, signs the canonical
   operation ID, vault, purpose, destination script, and amount with the phone
   key, then calls `reserve`. The server verifies that proof before selecting
   and locking VTXOs and debiting the rolling allowance. An exact retry returns
   the original reservation.
2. `authorize` validates the unsigned checkpoints, user-signed Arkade PSBT, and
   a canonical phone-signed pending-transaction proof for the exact reserved
   inputs. It adds the VaultCosigner signature to the Arkade transaction and
   proof, then stores both before returning them.
3. The wallet submits the operation to the Operator once. If the response is
   ambiguous, it presents the dual-signed proof through the official pending-
   transaction interface and accepts only the exact Arkade transaction and
   checkpoints recorded by the reservation.
4. `checkpoints/authorize` requires those checkpoints to match the stored
   operation and adds the VaultCosigner checkpoint signatures.
5. `finalize` verifies that the authorized Arkade transaction spent the
   reserved VTXOs. `GET /v1/vtxo/operation` lets the wallet recover ambiguous
   Vault-service responses. Operator submission recovery uses the deployed
   pending-transaction interface, which makes a second `submitTx` call
   ineligible.

The current Mutinynet slice accepts between one and 50 canonical inputs and a
`tark` destination for the same release-pinned Operator. It supports exact
no-change sends and the Operator's bounded intent fee policy. It does not
silently fall back to an onchain send or VTXO offboarding. See
[the Spending contract](docs/vault-policy-v1-spend.md).

## Boarding boundary

`vault-board-v1` is the only boarding program. Its cooperative leaf requires a
wallet-worker boarding key, a distinct VaultBoardCosigner, and the pinned
Arkade Operator. The phone key is reserved for recovery after the enrolled CSV
delay; routine boarding does not prompt for Face ID.

The official Arkade SDK owns discovery, intent construction, persistence,
retries, and settlement. The service verifies and submits four exact SDK phases
without returning its signature or replacing the SDK lifecycle. One confirmed
input may settle only into the enrolled `vault-policy-v1` Spending contract.
See [the boarding contract](docs/boarding.md).

Boarding principal does not debit the rolling allowance. The ordinary Spending
policy applies when the resulting VTXO pays another destination. Mainnet
parameters remain a separate release decision.

## HTTP surface

Mutation routes require JSON, the exact configured `Origin`, and the gateway
secret header. Unknown JSON fields are rejected. The gateway secret protects
the private service boundary; passkeys and transaction signatures provide user
authorization.

Tenant read routes are also behind the gateway, but currently use the random
vault ID as their capability; operation recovery additionally requires the
random operation ID. Request logs emit only a hashed vault tag. Mainnet must
explicitly qualify that privacy boundary or add a purpose-bound read session
without breaking fresh-device recovery and lost-response recovery.

| Route | Purpose |
| --- | --- |
| `GET /health` | Process liveness only. |
| `GET /ready` | Database and release-pinned signer/resolver readiness. |
| `GET /v1/status` | Public service status or one vault's status with `?vault=`. |
| `GET /v1/invite` | Invitation availability. |
| `POST /v1/enroll/session` | Issue a ten-minute, single-use setup session when invite-only admission is off. |
| `POST /v1/light/renew/prepare` | Reserve the fee for renewing one Light output. |
| `POST /v1/light/renew/register` | Verify owner and passkey approval, then register the exact Light renewal. |
| `POST /v1/light/renew/final` | Verify signed replacement paths and submit the owner-authorized forfeit. |
| `POST /v1/light/renew/status` | Reconcile the replacement output and confirmed Bitcoin commitment. |
| `POST /v1/light/renew/release` | Cancel an unsent renewal or fence an expired registration after checking the old output. |
| `POST /v1/light/enroll/start` | Assign a Light identity and freeze its spending policy. |
| `POST /v1/light/enroll/propose` | Return the Light descriptor for local verification and backup. |
| `POST /v1/light/enroll/finish` | Verify the passkey ceremony and atomically consume admission. |
| `POST /v1/enroll/start` | Freeze the protection tier and canonical policy digest, reserve a vault ID, and return the create-ceremony challenge. |
| `POST /v1/enroll/propose` | Return the Savings and `vault-board-v1` descriptors for wallet review. |
| `POST /v1/enroll/finish` | Verify the complete enrollment and consume the invitation. |
| `POST /v1/vtxo/board/prepare` | Reconcile and prepare one exact boarding attempt. |
| `POST /v1/vtxo/board/register` | Verify, cosign, and submit the exact registration intent. |
| `POST /v1/vtxo/board/release` | Verify, cosign, and submit release of a retained prior intent. |
| `POST /v1/vtxo/board/final` | Verify and submit the SDK-validated final commitment artifacts. |
| `POST /v1/vtxo/reserve` | Authenticate and create an immutable VTXO operation. |
| `POST /v1/vtxo/authorize` | Validate and sign the Arkade transaction and its pending-transaction recovery proof. |
| `POST /v1/vtxo/checkpoints/authorize` | Validate and sign Operator checkpoints. |
| `POST /v1/vtxo/finalize` | Verify the recorded spend and finalize the operation. |
| `GET /v1/vtxo/operation` | Read one operation for retry reconciliation. |
| `POST /v1/vtxo/abort` | Abort a pre-signature reservation and release its inputs. |
| `POST /v1/initiate` | Authorize a Savings-to-Pending recovery transition. |
| `POST /v1/clawback` | Authorize a Pending-to-Quarantine transition. |
| `POST /v1/passkey/challenge` | Issue a purpose-bound passkey challenge. |
| `POST /v1/passkey/binding` | Build the authenticated Recovery Kit binding. |
| `POST /v1/passkey/install` | Install a passkey credential envelope. |
| `POST /v1/passkey/recover` | Recover a passkey credential envelope. |
| `GET`, `POST /v1/map` | Read or write authenticated encrypted Recovery Kit map data. |

The boarding phase routes use release-pinned public Operator and Esplora adapters;
they accept no runtime origin override. Savings broadcast and ordinary
Spending submission remain wallet responsibilities.

## Persistence and failure handling

The v2 database starts at schema version 1 and accepts no other nonempty
schema. Every new economic-outflow reservation also advances an authenticated
policy sequence outside SQLite. Startup fails when the database is behind that
sequence.

The database and policy sequence require independently controlled storage,
permissions, backup jobs, and restore decisions. Two paths or two named volumes
under one restore authority leave a single failure domain. Losing sequence
persistence is a fail-closed event and never permits recreation from a database
backup.

The current Railway Mutinynet deployment does not meet that topology: both
files share one volume and restore authority. Its sequence detects
database-only rollback or sequence loss, but not restoration of the whole
volume. This is an accepted Mutinynet limitation, not mainnet evidence.

Allowance evaluation authenticates ledger rows before trusting their state or
time. The current implementation therefore has a bounded-history mainnet gate:
load tests must establish an operational ledger limit, or an authenticated
accumulator must replace the unbounded scan.

## Run the Mutinynet candidate

Create the two file-backed secrets, then configure the private service origin:

```bash
install -d -m 700 ./secrets
umask 077
openssl rand -hex 32 > ./secrets/vault-cosigner-key
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n' > ./secrets/enrollment-token
chmod 0600 ./secrets/*

cp .env.example .env
# Set VAULT_CLIENT_ORIGIN, VAULT_RP_ID, and VAULT_GATEWAY_SECRET.
docker compose up -d --build
```

Check liveness and readiness separately:

```bash
curl -fsS http://127.0.0.1:8788/health
curl -fsS http://127.0.0.1:8788/ready
```

Route wallet traffic only after readiness succeeds. Keep the
VaultCosigner scalar and enrollment token in `0600` files. Replacing the token
file provisions one additional invitation on the next restart; reusing the
same token is idempotent. Hosted
deployment may materialize them from the platform secret store at entrypoint,
then remove the raw values from the process environment before starting the
server.

## Mainnet release gates

The complete gate and operations posture are recorded in
[docs/mainnet-v2-baseline.md](docs/mainnet-v2-baseline.md) and
[deploy/ops.md](deploy/ops.md). The mainnet signer endpoint is configured privately and its advertised signer matches the
official SDK pin. The release uses `arkade.computer` and the official Arkade
SDK as deployed; it does not require a modified `arkd` or a Vault-specific
Operator API. Mainnet configuration must pin and qualify the deployed Emulator
and Operator identities, checkpoint policy, delays, and fee bounds before the
Contract Packs are regenerated. The supported policy schema and bounds must be
reviewed as release parameters; individual vaults may then choose any valid
instance during enrollment.

Ordinary VTXO send and boarding still require live qualification against
`arkade.computer`, along with the documented storage, rate-limit, and hardware
checks. Outbound Lightning uses the wallet's published swap-package adapter;
its funding transaction is an ordinary VTXO send, so this service adds no
Lightning endpoint or schema. Invoice, quote, solver, refund, and live-payment
qualification remain wallet release gates.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/authorizer` | Process configuration and shutdown. |
| `internal/authorizer` | Protected runtime assembly, secrets, ledger, and release-pinned adapters. |
| `internal/application` | Enrollment, VTXO, Savings transition, and recovery workflows. |
| `internal/policy` | Fresh ledger, authenticated records, allowance, and policy sequence. |
| `internal/vault` | L1 Vault Program scripts and transaction verification. |
| `internal/iface/http` | Constrained HTTP adapter. |
| `contract-pack.json` | Versioned names and parameters shared with the wallet. |

Run the full checks with Go 1.26.6:

```bash
go test ./... -count=1
go vet ./...
go test -race ./internal/policy ./internal/application ./internal/authorizer -count=1
```

Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## Vaulted Light candidate

The compiled `vaulted-light-v1` profile adds passkey-owned Spending with an immutable per-payment and rolling allowance policy. New Light enrollment is disabled unless `VAULT_LIGHT_ENABLED=true`; this setting is independent of `VAULT_INVITE_ONLY`. Existing Light wallets and already-started ceremonies remain usable when new enrollment is disabled.

Light is not ready for a mainnet activation: bounded renewal authorization and funded lifecycle/recovery qualification remain outstanding. See [the Light contract and integration notes](internal/vault/light/README.md). Existing Standard and Advanced programs and ledger records retain their current behavior.
