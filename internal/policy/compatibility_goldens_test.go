package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
)

// TestSchemaCompatibilityGolden pins the physical SQLite contract.
// The structural startup validator remains the enforcement mechanism; this
// digest catches intentional-looking SQL edits that preserve coarse column
// types while changing stored bytes, constraints, or object definitions.
func TestSchemaCompatibilityGolden(t *testing.T) {
	testSchemaGolden(t, false, "c15fdd355bcf93cc34487f43178f133f95d59c9f501ef4544589eeeb0ed9a553")
}

func TestLightRenewalSchemaGolden(t *testing.T) {
	testSchemaGolden(t, true, "a577b1311c302be332af46386f2de45c166aef422f3a2cf7186b2954100c6ee8")
}

func testSchemaGolden(t *testing.T, renewal bool, want string) {
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "vault.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	var canonical bytes.Buffer
	version := legacySchemaVersion
	if renewal {
		version = schemaVersion
	}
	fmt.Fprintf(&canonical, "schema_meta=%d\n", version)
	rows, err := ledger.db.Query(`
SELECT type, name, tbl_name, IFNULL(sql, '')
  FROM sqlite_schema
 WHERE name NOT LIKE 'sqlite_%'
 ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, name, table, sqlText string
		if err := rows.Scan(&kind, &name, &table, &sqlText); err != nil {
			t.Fatal(err)
		}
		// The original golden still freezes every legacy object verbatim.
		if !renewal && (table == "light_renewal_operation" || table == "light_renewal_event") {
			continue
		}
		fmt.Fprintf(&canonical, "%s\x00%s\x00%s\x00%s\n", kind, name, table, sqlText)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical.Bytes())
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("schema digest = %s, want %s\ncanonical schema:\n%s", got, want, canonical.String())
	}
}

// TestVtxoOperationLifecycleCompatibilityGolden freezes every legal state
// transition and the allowance consequence of every persisted state.
func TestVtxoOperationLifecycleCompatibilityGolden(t *testing.T) {
	states := []string{
		VtxoStateReserved,
		VtxoStateSigned,
		VtxoStateSubmitted,
		VtxoStateFinalized,
		VtxoStateAborted,
		VtxoStateUnresolved,
	}
	wantTransitions := map[string][]string{
		VtxoStateReserved:  {VtxoStateSigned, VtxoStateAborted},
		VtxoStateSigned:    {VtxoStateSubmitted},
		VtxoStateSubmitted: {VtxoStateFinalized, VtxoStateUnresolved},
	}
	wantAllowance := map[string]bool{
		VtxoStateReserved:   true,
		VtxoStateSigned:     true,
		VtxoStateSubmitted:  true,
		VtxoStateFinalized:  true,
		VtxoStateAborted:    false,
		VtxoStateUnresolved: true,
	}
	for _, from := range states {
		var got []string
		for _, to := range states {
			if validVtxoTransition(from, to) {
				got = append(got, to)
			}
		}
		sort.Strings(got)
		want := append([]string(nil), wantTransitions[from]...)
		sort.Strings(want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("VTXO transitions from %s = %v, want %v", from, got, want)
		}
		if got := vtxoStateCountsTowardAllowance(from); got != wantAllowance[from] {
			t.Fatalf("VTXO allowance accounting for %s = %v, want %v", from, got, wantAllowance[from])
		}
	}
	for _, unknown := range []string{"", "pending", "released", "failed"} {
		if err := requireVtxoState(unknown); err == nil {
			t.Fatalf("unknown VTXO state %q accepted", unknown)
		}
		if vtxoStateCountsTowardAllowance(unknown) {
			t.Fatalf("unknown VTXO state %q counted without validation", unknown)
		}
	}
}

func TestRecoveryOperationReplayCompatibilityGolden(t *testing.T) {
	base := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 1, DestScript: "5120ab", LastSighash: "11",
	}
	if action, err := DecideReplay(nil, base); err != nil || action != ReplaySign {
		t.Fatalf("new recovery operation = %q, %v", action, err)
	}
	pending := base
	if action, err := DecideReplay(&pending, base); err != nil || action != ReplayResign {
		t.Fatalf("exact pending recovery retry = %q, %v", action, err)
	}
	signed := base
	signed.Signature = []byte("signed-psbt")
	if action, err := DecideReplay(&signed, base); err != nil || action != ReplayReplay {
		t.Fatalf("exact signed recovery retry = %q, %v", action, err)
	}
	feeBump := base
	feeBump.LastSighash = "22"
	if action, err := DecideReplay(&signed, feeBump); err != nil || action != ReplayResign {
		t.Fatalf("signed recovery fee bump = %q, %v", action, err)
	}
	if _, err := DecideReplay(&pending, feeBump); err != ErrRecoveryBusy {
		t.Fatalf("ambiguous unsigned recovery retry = %v, want ErrRecoveryBusy", err)
	}

	// The VTXO lifecycle comparison above is pure. Exercise the public ledger
	// transition entry point once so a future adapter cannot bypass it.
	ledger := openPolicyTestLedger(t, nil)
	createPolicyTestVault(t, ledger, "vault-a", 0x71)
	op := testVtxoOperation("vault-a", "compat-op", vtxoPurposeSpend, vtxoStateReserved, 1_000, 10, ledger.NowUTC())
	input := VtxoOperationInput{OperationID: op.OperationID, Txid: bytes.Repeat([]byte{0x61}, 32), ValueSats: 1_010}
	if err := ledger.ReserveVtxoOperation(context.Background(), op, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatal(err)
	}
	next := op
	next.State = VtxoStateSigned
	if _, swapped, err := ledger.TransitionVtxoOperation(context.Background(), VtxoStateReserved, next); err != nil || !swapped {
		t.Fatalf("reserved -> signed ledger transition = %v, %v", swapped, err)
	}
}
