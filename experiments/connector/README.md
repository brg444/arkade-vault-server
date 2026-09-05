# Hardware connector feasibility

Status: isolated integration candidate, with the honest-independent-cosigner
trust model accepted by the owner on 2026-09-05. The connector still fails the requirement
that hardware approval remain mandatory after compromise of the phone and all
online signing authorities. Production enrollment, signing routes, Contract
Packs, and funded vaults are unchanged.

The hardware can approve the destinations and amounts of a complete Savings
transfer by signing a small ordinary Taproot input. That signature prevents
later transaction modification. Making the hardware input compulsory is a
separate authorization requirement, which the candidate enforces through the
online signing programs.

## Bitcoin accepts the bypass when every required signing key is compromised

The experiment distinguishes three constructions:

| Construction | Bitcoin signature requirement | Hardware omission |
| --- | --- | --- |
| Existing Savings admin leaf | Phone and hardware | Rejected without the hardware key |
| Existing normal-tree recovery-initiation leaf | Claimant and two program-derived cosigner keys | Possible if those three signing keys are compromised |
| Candidate normal connector leaf | Phone and two program-derived cosigner keys | Possible if those three signing keys are compromised |

Bitcoin Core regtest accepts and mines a candidate spend with an attacker-owned
connector, and another with no connector. Both fail the pinned Arkade interpreter
first. The attack harness derives the same program-bound cosigner private keys
that correspond to the committed public keys, then signs without executing the
program. No hardware key is used for either attack.

The existing full Savings tree has a related boundary. Its direct admin leaf
requires hardware, but its phone recovery-initiation leaf requires the phone and
two program-derived cosigner keys. With all three compromised, Core accepts a
direct transfer to an attacker destination without entering pending recovery.
The recovery-key initiation leaf has the equivalent result. The experiment
reconstructs the complete production tree, checks its output script against
`savings.BuildFamily`, and spends the selected leaf using its actual Merkle proof.

Consequently, the prior claim that the entire existing Savings contract survives
phone-plus-all-cosigner compromise was incorrect. Its direct admin path has that
property; the complete recovery-enabled tree relies on cosigner enforcement.
These tests assume private-key compromise and deliberate program bypass. Their
scope is signing-key authority; live Guardian authentication remains outside it.

## Compromise and availability comparison

P denotes the phone signing authority, H the hardware, G the Guardian's
VaultCosigner, E the independent program cosigner, and R the optional recovery
key. Honest services continue enforcing their programs and authentication rules.
The candidate column concerns its proposed normal path; existing recovery paths
would retain their own requirements.

| Compromise or failure | Existing Savings | Connector candidate |
| --- | --- | --- |
| P alone | Cannot use admin; recovery follows online checks and pending delay | Cannot provide H approval |
| H alone | Cannot use admin; hardware recovery follows its checks and delay | Cannot provide P approval |
| G alone | Missing claimant and E signatures | Missing P, E, and H approval |
| E alone | Missing claimant and G signatures | Missing P, G, and H approval |
| P + H | Can use the direct admin leaf | Can request program-conforming transfers, subject to honest online checks |
| P + G | Honest E still enforces recovery; admin requires H | Honest E must require H |
| P + E | Honest G still enforces recovery; admin requires H | Honest G must require H |
| H + G | Honest E enforces hardware recovery; admin requires P | Normal path still requires P and E |
| H + E | Honest G enforces hardware recovery; admin requires P | Normal path still requires P and G |
| G + E | Missing a claimant signature; admin requires P + H | Missing P signature |
| P + G + E | Phone initiation can bypass pending restrictions | Normal path can omit H |
| R + G + E | Recovery initiation can bypass pending restrictions | Same exposure if that recovery branch is retained |
| Hardware lost | Admin unavailable; remaining recovery paths apply | Connector unavailable; remaining recovery paths apply |
| Guardian or E outage | P + H admin remains available | Proposed normal path becomes unavailable |
| Connector spent separately | No effect on current contract | Selected transfer becomes invalid; Savings stays unspent |
| R alone | Authorized delayed recovery, subject to initiation checks and possible clawback | Same only if the existing recovery family is preserved |

The candidate therefore adds online availability requirements to ordinary
transfers. It does not preserve the direct admin path's independent hardware
signature requirement. Retaining that direct leaf would retain its original
hardware signing compatibility problem as well.

## Prototype transaction and checks

The first test program is named `savings-connector-experiment-v0`. That prototype
lives in `_test.go` files. The next integration stage lives in
`internal/vault/connector`; an architecture check forbids production code from
importing it. Its complete transaction and remaining gates are described in
[the integration design](integration.md).

| Component | Sats |
| --- | ---: |
| Savings input | 10,000 |
| Enrolled connector input | 1,000 |
| Registered boarding destination | 8,000 |
| Savings change | 1,500 |
| Connector returned to enrolled script | 1,000 |
| Fee | 500 |

The program fixes two inputs, three outputs, transaction version, locktime, the
boarding destination, and the connector script. It compares Savings change with
the Savings input script, avoiding a circular commitment to its own program key.
It preserves the 1,000-sat reserve and limits the fee to 1,000 sats in this fixture.
The hardware signature uses `SIGHASH_DEFAULT` and commits to all inputs and
outputs. Its importer checks the actual signature encoding as well as PSBT
metadata, since Bitcoin also accepts weaker signature modes.

The fixed script can receive another genuine hardware-controlled UTXO after an
external connector spend. This experiment reuses the script; it does not rotate
addresses, maintain a unique connector chain, or validate an xpub in the VM.
Each signed candidate still commits to its exact connector outpoint.

The interpreter receives independently supplied parent transactions whose hashes
and outputs are checked against the requested inputs. PSBT `witnessUtxo` fields
cannot override those facts. Core supplies confirmed funding and unspentness
validation in the integration tests; a previous transaction alone proves neither
confirmation nor current availability.

The first prototype invokes the pinned script engine directly. Its transaction omits
the Emulator packet and P2A output required by existing production transitions.
It tests the connector condition and the tweaked-key trust boundary, and does
not claim to implement the public Emulator signing protocol. A production
construction would need its complete packet, output shape, fee calculation,
signing order, and named API qualified separately.

## Recovery and presigned alternatives

Normal Savings has no direct claimant-only delayed branch. Recovery initiation
requires the claimant and both cosigners, whose programs force the pending
destination. Once that pending output exists, its claimant can spend after the
committed CSV delay without a connector or either online cosigner. Pending also
has cosigner-assisted clawback branches and, in the tested configuration, a
remaining-guardians-only exit into an independently authorized transaction.
Quarantine requires the remaining family keys. Hardware participation in these
custom leaves still requires separate device compatibility work.

The regtest suite funds the production pending scripts directly to isolate their
claim rules. It tests phone, hardware, and recovery claimants one block before
eligibility and at eligibility. It does not simulate an end-to-end authenticated
recovery ceremony or prove live service availability.

A fixed presigned Savings transaction does bind its connector without allowing
later omission. The presignature test also shows that changing the fee invalidates
that authorization, even when hardware approves the new candidate. A complete
construction would need the graph
`S0 + H0 -> S1 + H1 -> S2 + H2`, all amounts and output scripts, and required
recovery exits committed before removing the signing authority. Standard full
transaction signatures commit each input outpoint, so the graph cannot freely
substitute a new deposit, change amount, or connector refill.

The experiment does not establish secure key deletion, an unbounded transaction
graph, or a usable replacement and recovery mechanism for that alternative.
Keeping the unrestricted signing keys available to authorize new graph branches
retains the same compromise boundary. A bounded presigned transaction succeeds
as a signature construction, but does not qualify the proposed reusable wallet.

## Reproduce the evidence

Use Go 1.26.6 and the repository's pinned dependencies:

```sh
go test ./experiments/connector -count=1 -v
CONNECTOR_BITCOIND=/absolute/path/to/bitcoind \
  go test ./experiments/connector -count=1 -v
```

The first command skips Core explicitly when the environment variable is absent.
The second starts a disposable regtest node with its own temporary data directory,
loopback RPC, and disabled peer connections. It creates and mines test funds,
then stops the node and removes its temporary data. It never uses a running node,
an existing wallet, production credentials, or a public Bitcoin network.

Qualification used Bitcoin Core 28.1 and its default transaction relay rules.
The Core fixtures reconstruct the mainnet Savings and pending scripts with
disposable keys, then fund those scripts only on regtest. Unit tests also cover
the Mutinynet recovery-initiation construction.
The official macOS arm64 archive SHA-256 is
`abf4d2f7ebda6284e2246bce3591bcf161c114e370c0443ccc049b2728dc7e20`.
The extracted CLI binary required local ad-hoc signing on macOS before execution;
the downloaded archive was checked against the official checksum first.

The suite covers valid transfers, input substitution and omission, forged PSBT
metadata, output and fee mutations, actual weaker signature encodings, missing
signing authorities, conflicting connector spends, refills, RBF with renewed
approval, and stale transactions after confirmation. Core mines the counterexample
transactions as well as valid fixture transfers. No hardware device or transport
has been qualified.

Validation on 2026-09-05:

| Check | Result |
| --- | --- |
| `make check` with Go 1.26.6 and Core enabled | Passed: modules, build, vet, and repository tests |
| Connector suite with `-race` and Core enabled | Passed, including all ten Core scenarios |
| Pinned golangci-lint v2.13.1 | Passed |
| Documentation style and whitespace checks | Passed |

Successful counterexample tests mean the bypass was reproduced as expected.
They leave the strict hardware-enforcement gate failed.

## Feasibility decision

The candidate fails the strict hardware-enforcement gate and remains outside
production. The owner accepted proceeding with an honest-independent-cosigner
requirement and the ordinary-transfer availability cost on 2026-09-05.
The existing recovery dependence belongs in that decision; comparing only the
admin leaves would overstate the current contract's protection.

Source baseline: runtime `b6580618237d4ae946e62da6df3e21bd30fad000`, on the rewritten
privacy branch. No old pre-rewrite ancestry is introduced.

References: [Taproot signature commitments](https://bips.dev/341/),
[Core 28.1 checksums](https://bitcoincore.org/bin/bitcoin-core-28.1/SHA256SUMS),
`internal/vault/savings/family.go`, `internal/vault/savings/trees.go`, and the pinned
script engine's `tweak.go`. The runtime's durable architecture requirements remain
in the private `runtime-design.md` source; no deployment endpoints are reproduced.
