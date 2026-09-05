# Savings connector integration

The accepted candidate makes ordinary Savings transfers depend on an enrolled
hardware input, the phone, and two online cosigners. At least one cosigner must
remain honest for the hardware requirement to hold against a compromised phone.
Compromise of the phone and both cosigner signing authorities permits a bypass.
Ordinary transfers require both services to be available.

The owner accepted this tradeoff on 2026-09-05. That decision supersedes the
strict hardware-enforcement gate in the original staged proposal; the reproduced
bypass remains a required test. Existing recovery-initiation dependence is
documented in [the feasibility report](README.md).

## Accepted destination policy, 2026-09-05

The collaborative connector path permits a hardware-approved Savings withdrawal
to any user-chosen Bitcoin payment address. The enrolled program requires the
hardware connector input and return of its full reserve to the enrolled script.
It does not restrict the payment recipient to the registered Spending boarding
address. Savings-to-Spending remains one use of this path.

The user chooses the payment amount within the available Savings balance and
the transaction's dust and fee constraints. Spending per-payment and rolling
limits apply only to their existing Spending operations. Existing Spending and
recovery contracts retain their separate rules.
Savings change, when present, returns to the enrolled Savings script; the
reserve return and required protocol outputs remain constrained.

Both cosigners validate the connector and transaction rules before signing the
Savings input. The hardware reviews the complete transaction, including every
payment output, change, and total cost, then supplies the final connector
signature. The user verifies the intended recipient on the device. DEFAULT
signatures bind every input and output, preventing later substitution. This
retains the accepted honest-independent-cosigner trust requirement and the
chosen signing order.

The program accepts the recipient as a per-transfer value without an enrolled
payment-destination commitment.
Tests must accept a newly constructed, fully approved payment to an unrelated
address while rejecting changes to that address or amount after signatures
have been obtained. Connector substitution, missing hardware approval, reserve
loss, invalid change, and fee violations remain rejection cases. Complete
withdrawal omits the Savings change output and leaves no residual balance.

This decision supersedes the earlier Spending-only target. The implementation
uses new program keys and a separately versioned contract. Funded enrollment
remains disabled while service and device qualification continues.

## Implemented transaction boundary

`internal/vault/connector` contains a transaction builder, the named candidate
program, and an immutable PSBT handoff. Production imports are prohibited by
`architecture_test.go`. No profile, enrollment, signing endpoint, Contract Pack,
wallet flow, or funded Savings tree selects this candidate.

The candidate program is `savings-connector-v1`, with template
`phone-connector-recovery-savings-v1`. These identifiers remain unreleased. Both program-derived
cosigner keys commit the identical program; the normal tapscript requires the
phone and those two keys. The builder checks the exact leaf and its Merkle
proof against the independently pinned Savings script.

| Position | Input or output | Fixture value |
| --- | --- | ---: |
| Input 0 | Savings | 10,000 sats |
| Input 1 | Enrolled BIP86 connector | 1,000 sats |
| Output 0 | User-selected Bitcoin recipient | 8,000 sats |
| Output 1 | Same connector script | 1,000 sats |
| Output 2 | Existing P2A fee anchor | 240 sats |
| Output 3 | Canonical Emulator packet | 0 sats |
| Output 4, optional | Same Savings script | 760 sats |
| Miner fee | Input total minus output total | 1,000 sats |

Savings pays both the miner fee and the anchor. In this example its debit is
9,240 sats; the hardware reserve stays at 1,000 sats. A future payment review
must include the anchor in the total cost. The program caps the miner fee and
feerate separately, commits the anchor's amount, and uses the exact final
witness size when checking feerate.

The current stage has exactly two inputs and four or five outputs. Complete
withdrawal of the selected Savings input omits its change output. Partial
withdrawal returns at least 330 sats of Savings change. Multiple Savings inputs
remain additional integration work.
Both input sequences signal replacement, while version 2 and locktime 0 are
fixed. A replacement requires fresh signatures over the complete transaction.

The connector uses one fixed enrolled address. Each transfer consumes a specific
outpoint and returns its full value to the same address. Deriving a new address
for each successor would introduce an additional identity-verification contract;
that is outside this candidate. A refill must use the same enrolled script and
still requires that hardware key to authorize its later consumption.

## Signing order and verification

1. Resolve both parent transactions independently and verify the selected
   amounts and scripts. Confirmations and current unspentness remain the chain
   verifier's responsibility; parent contents establish only the prevout data.
2. Build the entire transaction, including the Emulator packet, and retain an
   immutable snapshot. The PSBT includes full parents, witness UTXOs, the
   Savings leaf/proof, and BIP32 origin metadata for the connector and return.
3. The phone and both cosigners sign the exact Savings input with DEFAULT
   sighash. Each service must validate its pinned program and authenticated
   semantic operation before using a signing key. The tests execute the packet
   through the pinned parser and engine for both cosigner public keys.
4. Verify all three Savings signatures and finalize that input before exporting
   the hardware PSBT. This supplies a verifiable external input to devices that
   require one. It does not establish support on any particular device.
5. The hardware reviews the full transaction and signs its connector input with
   DEFAULT or ALL sighash for Taproot, or ALL for native SegWit. Its approval must display the chosen payment address
   accurately enough for the user to compare with the intended recipient.
   Amount, every additional output, and total cost review remain device
   qualification gates.
6. Import only the verified hardware signature into the retained transaction.
   Reject transaction mutations, conflicting prevout claims, signatures that omit any output or allow additional inputs, script-path connector witnesses, and annexes. Retain the locally
   verified Savings witness regardless of returned foreign-input metadata.
7. Persist the exact signed transaction before broadcast, then reconcile its
   confirmation and successor outpoints through the existing wallet lifecycle.

Steps 1's live chain lookup, 3's service authentication and authorization, and 7's
persistence and broadcast are integration work remaining. The module builds and
verifies transactions without obtaining private keys or calling a signing service.
Its `Validate` function checks transaction rules; it is not a complete runtime
authorization operation.

Requiring the hardware signature before either cosigner signs would conflict
with devices that require a finalized external input for review. The chosen
order supplies Savings signatures first. Those signatures already commit the
hardware input, so they cannot be attached to a transaction with an attacker
input substituted afterward. The complete transaction cannot spend until its
hardware input has a valid signature.

## Wallet lifecycle to integrate

| Observed event | Required behavior |
| --- | --- |
| Confirmed unspent reserve discovered | Select it only when no unresolved operation already owns a connector |
| Transfer prepared | Persist exact inputs and candidate; show the amount awaiting approval |
| Any signature released | Retain the candidate and reconcile it across reload, timeout, and device disconnect |
| Hardware declines | Preserve the signed candidate's identity; no new outpoint selection based on a timeout |
| Broadcast response lost | Query and rebroadcast the same transaction; show processing while the outcome is unknown |
| Transfer confirms | Atomically advance Savings activity and the reserve to the actual successor outputs |
| Confirmed connector conflict | Mark the old candidate unusable and rediscover a same-key refill; retain the independently observed Savings balance |
| Hardware absent or lost | Keep normal transfers unavailable; expose only the enrolled recovery paths |
| Chain reorganizes | Reconcile the transaction and both reserve outpoints before showing availability |

Hardware replacement changes the committed Savings policy. The phone cannot
replace that identity in place. Existing vaults retain their current contracts;
migration requires an intentionally authorized spend into a separately enrolled
new contract. The new Standard and Advanced recovery families are reconstructed in both
repositories. Core tests fund their pending outputs directly to verify each
claim delay; full authenticated recovery initiation and clawback remain release
qualification work.

## Qualification and remaining work

The integration suite verifies the complete packet for both program-bound
cosigner roles, exact fee boundaries, pinned parents and leaf proofs, immutable
handoff, both partial and finalized hardware PSBT responses, and signature and
transaction mutations. All signing keys are disposable fixture keys. The origin
metadata includes real BIP84 derivations from a public disposable seed. Physical
device review remains untested.

Bitcoin Core 28.1 rejects the Taproot fixture's 267-byte packet output under its default
83-byte data-output policy. With only `-datacarriersize=100000` changed, the suite
accepts and mines two successive complete connector transfers, verifies the
reserve remains 1,000 sats, and rejects stale transactions. That explicit test
setting matches the larger data-output limit documented in the
[Core 30.0 release notes](https://bitcoincore.org/en/releases/30.0/); it does not
claim qualification on a Core 30 binary or on the public broadcast service.

Reproduce with the pinned Go dependencies and an isolated Core binary:

```sh
CONNECTOR_BITCOIND=/absolute/path/to/bitcoind \
  go test ./experiments/connector -run '^Test(Connector|Software)'  -count=1 -v
```

The remaining release work is:

- qualify a released software wallet through its actual import, full destination
  review, signing, and export screens; physical hardware is an additional target;
- qualify the public Emulator's multi-input request, packet, fee policy, and
  exact signature response using disposable funds;
- connect the implemented family and enrollment commitment to the versioned
  descriptor, Recovery Kit, enrollment service, and explicit migration flow;
- implement the named authenticated runtime operation and wallet coordinator,
  including durable reconciliation, multiple deposits, complete withdrawal,
  conflicting reserve spends, and replacement;
- test the public broadcast path and funded lifecycle before enabling the
  candidate in a release.

Passing the local transaction tests closes the packet and PSBT construction
stage. It does not close device review, remote-service availability, recovery,
wallet integration, or deployment qualification.

Validation on 2026-09-05: `make check` passed module verification, build, vet,
and the full repository suite with Core enabled. The complete connector suite
also passed with `-race` and Core enabled. Pinned golangci-lint v2.13.1 reported
zero issues; documentation style and whitespace checks passed.

## RC implementation status

The runtime and wallet now reconstruct identical Standard and Advanced families
on mainnet and Mutinynet. Shared vectors cover the program, normal leaf and
proof, addresses, reserve script, recovery scripts, and enrollment digest.
`arkade-vault/connector-enrollment-v1` commits the complete reconstructed
contract, immutable Spending policy, and the hardware fingerprint and complete BIP32
origin path. Network-mismatched BIP84/BIP86 origins fail validation. Native Electrum origins
are also supported, with the complete path committed by enrollment.

The wallet transaction builder verifies that digest against its caller-supplied
local enrollment pin, checks independently supplied parent contents, builds the
packet and reserve return, verifies Savings signatures, and imports only the
hardware signature into its retained transaction. Go-generated signed PSBTs
produce byte-identical final transactions in the wallet, including full
withdrawal and explicit fingerprint byte order.

These functions are ready for coordinator integration; the existing enrollment
and payment screens still select the old contract. Pending-operation storage,
service authentication, named signing routes, and release advertisement remain
the next implementation stage. No connector Contract Pack is published yet.

## Software wallet qualification

The connector supports BIP84 native SegWit and BIP86 Taproot inputs. Enrollment
commits the compressed public key, origin, and connector script through the
contract digest. Native SegWit preserves public-key parity and requires ECDSA
SIGHASH_ALL. Taproot permits DEFAULT or ALL. Signatures that omit outputs or
permit added inputs are rejected, as are modified transactions and unrelated
connector keys. PSBT and completed transaction imports use the same retained
Savings witness and independently verified parents.

Fee-rate accounting commits a lower witness-size bound. Native SegWit uses the
minimum possible DER signature length, making the ceiling conservative for
ordinary signatures. Taproot ALL adds one byte compared with DEFAULT and also
preserves that ceiling. The connector reserve remains 1,000 sats.

`TestSoftwareWalletCore` uses Bitcoin Core 28.1's descriptor wallet and
`walletprocesspsbt` to sign both connector types beside a finalized Savings
input. Partial and complete withdrawals pass mempool validation and are mined
on an isolated, peerless regtest node with the explicit data-output setting
above. These tests use actual wallet signing, in addition to fixture-key tests.

BlueWallet 8.0.1's imported-PSBT flow attempts to finalize an already-finalized
Taproot input and fails. It also signs before opening its transaction export
screen. BlueWallet-specific changes are outside the current scope; released
Electrum and Sparrow are the software wallet qualification targets. The
connector remains disabled in the existing RC enrollment and payment flows.

Unmodified Electrum 4.8.1 now passes eight wallet-signing cases covering native
Electrum seeds and BIP84 imports, both protection tiers, and partial and full
withdrawals. The export explicitly includes an empty final scriptSig alongside
the Savings witness so Electrum recognizes the input as complete. Returned PSBT
and raw transactions pass the wallet's independent signature verification.
These tests check the destination strings used by Electrum's transaction UI;
the desktop screen and manual import/export flow still need qualification.
