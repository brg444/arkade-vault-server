package policy

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func renewalFixture(t *testing.T) (*Ledger, *time.Time, LightRenewalOperation) {
	t.Helper()
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	led := openPolicyTestLedger(t, func() time.Time { return now })
	vault := strings.Repeat("ab", 32)
	createPolicyTestVault(t, led, vault, 0x51)
	return led, &now, LightRenewalOperation{OperationID: strings.Repeat("01", 16), VaultID: vault, InputTxid: strings.Repeat("02", 32), FeeSats: 123, PlanDigest: strings.Repeat("03", 32), Plan: `{"renewal":true}`, ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339)}
}
func appendRenewal(t *testing.T, l *Ledger, op LightRenewalOperation, phase string) LightRenewalEvent {
	t.Helper()
	e := LightRenewalEvent{OperationID: op.OperationID, Phase: phase, RequestDigest: op.PlanDigest}
	var credential []byte
	var count uint32
	switch phase {
	case "register_authorized":
		e.Evidence = `{"owner":"verified"}`
		credential = []byte{0x51, 0x52}
		count = 1
	case "final_authorized", "delete_authorized":
		e.Evidence = `{"verified":true}`
	case "register_result":
		e.Outcome = "registered"
		e.OperatorRef = "intent-id"
	case "final_result":
		e.Outcome = "submitted"
	case "delete_result":
		e.Outcome = "released"
	case "confirmed":
		e.Outcome = "confirmed"
		e.OperatorRef = strings.Repeat("04", 32)
		e.Evidence = `{"confirmed":true}`
	}
	out, created, err := l.AppendLightRenewalEvent(context.Background(), e, credential, count)
	if err != nil || !created {
		t.Fatalf("%s: created=%v err=%v", phase, created, err)
	}
	return out
}
func TestLightRenewalChargesOnlyFeeAndHoldsUncertainAfterExpiry(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
		t.Fatal(err)
	}
	appendRenewal(t, l, op, "register_authorized")
	appendRenewal(t, l, op, "register_dispatched")
	*now = now.Add(48 * time.Hour)
	if used, err := l.SpentInPeriod(ctx, op.VaultID, ""); err != nil || used != 123 {
		t.Fatalf("uncertain fee %d %v", used, err)
	}
	if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
		t.Fatalf("expired exact retry: %v", err)
	}
	next := op
	next.OperationID = strings.Repeat("05", 16)
	next.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	if _, err := l.ReserveLightRenewal(ctx, next, 10000); !errors.Is(err, ErrVtxoOperationActive) {
		t.Fatalf("released uncertain operation: %v", err)
	}
	if _, _, err := l.AppendLightRenewalEvent(ctx, LightRenewalEvent{OperationID: op.OperationID, Phase: "cancelled", RequestDigest: op.PlanDigest}, nil, 0); err == nil {
		t.Fatal("cancelled dispatched registration")
	}
}
func TestLightRenewalConfirmedFeeWindowAndImmutableReplay(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
		t.Fatal(err)
	}
	auth := appendRenewal(t, l, op, "register_authorized")
	if _, created, err := l.AppendLightRenewalEvent(ctx, auth, []byte{0x51, 0x52}, 1); err != nil || created {
		t.Fatalf("auth replay: %v %v", created, err)
	}
	if _, _, err := l.AppendLightRenewalEvent(ctx, auth, []byte{0x51, 0x52}, 2); err == nil {
		t.Fatal("changed replay counter accepted")
	}
	for _, phase := range []string{"register_dispatched", "register_result", "final_authorized", "final_dispatched", "final_result", "confirmed"} {
		appendRenewal(t, l, op, phase)
	}
	if used, err := l.SpentInPeriod(ctx, op.VaultID, ""); err != nil || used != 123 {
		t.Fatalf("confirmed fee: %d %v", used, err)
	}
	*now = now.Add(24*time.Hour + time.Second)
	if used, err := l.SpentInPeriod(ctx, op.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("fee window: %d %v", used, err)
	}
}
func TestLightRenewalAndPaymentReserveAtomically(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	payment := testVtxoOperation(op.VaultID, "concurrent-payment", vtxoPurposeSpend, vtxoStateReserved, 1000, 0, *now)
	payment.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x99}, 32), ValueSats: 2000, Script: []byte{0x51}}
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { defer wg.Done(); <-start; _, err := l.ReserveLightRenewal(ctx, op, 10000); results <- err }()
	go func() {
		defer wg.Done()
		<-start
		results <- l.ReserveVtxoOperation(ctx, payment, []VtxoOperationInput{input}, 10000)
	}()
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrVtxoOperationActive) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}
func TestLightRenewalTamperedCorrelationCannotHideReservations(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE light_renewal_operation SET vault_id='other'`,
		`UPDATE light_renewal_operation SET payload=replace(payload,'123','0')`,
		`UPDATE light_renewal_event SET phase='final_dispatched' WHERE phase='register_dispatched'`,
		`UPDATE light_renewal_event SET payload=replace(payload,'register_dispatched','final_dispatched')`,
	} {
		t.Run(mutation, func(t *testing.T) {
			l, _, op := renewalFixture(t)
			ctx := context.Background()
			createPolicyTestVault(t, l, "other", 0x61)
			if _, err := l.ReserveLightRenewal(ctx, op, 10000); err != nil {
				t.Fatal(err)
			}
			appendRenewal(t, l, op, "register_authorized")
			appendRenewal(t, l, op, "register_dispatched")
			if _, err := l.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := l.SpentInPeriod(ctx, op.VaultID, ""); err == nil {
				t.Fatal("tampering hidden from allowance")
			}
			if _, err := l.GetLightRenewal(ctx, op.OperationID); err == nil {
				t.Fatal("tampered snapshot accepted")
			}
		})
	}
}
func TestLightRenewalSequenceAndAtomicCredentialFailure(t *testing.T) {
	l, _, op := renewalFixture(t)
	ctx := context.Background()
	sequence, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
		t.Fatal(err)
	}
	appendRenewal(t, l, op, "register_authorized")
	if n, err := economicOutflowCount(l.db); err != nil || n != 2 {
		t.Fatalf("sequence count %d %v", n, err)
	}
	if _, err := l.db.Exec(`DELETE FROM light_renewal_event`); err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(sequence); err == nil {
		t.Fatal("database rollback accepted")
	}
	l2, _, op2 := renewalFixture(t)
	if _, err := l2.ReserveLightRenewal(ctx, op2, 123); err != nil {
		t.Fatal(err)
	}
	if _, err := l2.db.Exec(`DROP TABLE webauthn_sign_count`); err != nil {
		t.Fatal(err)
	}
	e := LightRenewalEvent{OperationID: op2.OperationID, Phase: "register_authorized", RequestDigest: op2.PlanDigest, Evidence: `{}`}
	if _, _, err := l2.AppendLightRenewalEvent(ctx, e, []byte{1}, 1); err == nil {
		t.Fatal("missing credential table accepted")
	}
	snapshot, err := l2.GetLightRenewal(ctx, op2.OperationID)
	if err != nil || len(snapshot.Events) != 0 {
		t.Fatalf("partial authorization survived: %v", err)
	}
}
func TestLightRenewalTransitionsRejectLateFinalAndContradictoryResult(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized"} {
		appendRenewal(t, l, op, phase)
	}
	*now = now.Add(6 * time.Minute)
	e := LightRenewalEvent{OperationID: op.OperationID, Phase: "final_dispatched", RequestDigest: op.PlanDigest}
	if _, _, err := l.AppendLightRenewalEvent(ctx, e, nil, 0); err == nil {
		t.Fatal("late forfeit dispatch accepted")
	}
	e.Phase = "delete_authorized"
	e.Evidence = `{}`
	if _, _, err := l.AppendLightRenewalEvent(ctx, e, nil, 0); err == nil {
		t.Fatal("deletion after forfeit authorization accepted")
	}
}

func TestLightRenewalExpiredReleaseFencesFinalAuthorization(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
		t.Fatal(err)
	}
	appendRenewal(t, l, op, "register_authorized")
	appendRenewal(t, l, op, "register_dispatched")
	release := LightRenewalEvent{OperationID: op.OperationID, Phase: "released", RequestDigest: op.PlanDigest, Evidence: `{"oldOutput":"live"}`}
	if _, _, err := l.AppendLightRenewalEvent(ctx, release, nil, 0); err == nil {
		t.Fatal("live registration released")
	}
	*now = now.Add(6 * time.Minute)
	if _, _, err := l.AppendLightRenewalEvent(ctx, release, nil, 0); err != nil {
		t.Fatal(err)
	}
	if used, err := l.SpentInPeriod(ctx, op.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("released fee held: %d %v", used, err)
	}
	late := LightRenewalEvent{OperationID: op.OperationID, Phase: "register_result", RequestDigest: op.PlanDigest, Outcome: "registered", OperatorRef: "late-intent"}
	if _, _, err := l.AppendLightRenewalEvent(ctx, late, nil, 0); err == nil {
		t.Fatal("late outcome reopened fenced registration")
	}
}

func TestLightRenewalExpiredUndispatchedFinalCanBeFenced(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		l, now, op := renewalFixture(t)
		ctx := context.Background()
		if _, err := l.ReserveLightRenewal(ctx, op, 123); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized"} {
			appendRenewal(t, l, op, phase)
		}
		if dispatched {
			appendRenewal(t, l, op, "final_dispatched")
		}
		*now = now.Add(6 * time.Minute)
		_, _, err := l.AppendLightRenewalEvent(ctx, LightRenewalEvent{OperationID: op.OperationID, Phase: "released", RequestDigest: op.PlanDigest, Evidence: `{"oldOutput":"live"}`}, nil, 0)
		if dispatched {
			if err == nil {
				t.Fatal("possibly dispatched forfeit released")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		*now = now.Add(-6 * time.Minute)
		if _, _, err := l.AppendLightRenewalEvent(ctx, LightRenewalEvent{OperationID: op.OperationID, Phase: "final_dispatched", RequestDigest: op.PlanDigest}, nil, 0); err == nil {
			t.Fatal("fenced signature dispatched after clock rollback")
		}
	}
}
