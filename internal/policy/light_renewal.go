package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// LightRenewalOperation is one immutable, fee-only renewal reservation. Plan
// contains the named program's canonical plan, not arbitrary executable data.
type LightRenewalOperation struct {
	OperationID string `json:"operationId"`
	VaultID     string `json:"vaultId"`
	InputTxid   string `json:"inputTxid"`
	InputVout   uint32 `json:"inputVout"`
	FeeSats     int64  `json:"feeSats"`
	PlanDigest  string `json:"planDigest"`
	Plan        string `json:"plan"`
	ExpiresAt   string `json:"expiresAt"`
	CreatedAt   string `json:"createdAt"`
}

// Phases are append-only. A dispatched phase with no result stays uncertain;
// neither a client retry nor elapsed time implicitly unlocks its old output.
type LightRenewalEvent struct {
	OperationID   string `json:"operationId"`
	Phase         string `json:"phase"`
	RequestDigest string `json:"requestDigest"`
	Outcome       string `json:"outcome,omitempty"`
	OperatorRef   string `json:"operatorRef,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

type LightRenewalSnapshot struct {
	Operation LightRenewalOperation
	Events    map[string]LightRenewalEvent
}

func canonicalRenewalHex(value string, n int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == n && hex.EncodeToString(raw) == value
}
func validateLightRenewalOperation(r LightRenewalOperation) error {
	if !canonicalRenewalHex(r.OperationID, 16) || !canonicalRenewalHex(r.VaultID, 32) || !canonicalRenewalHex(r.InputTxid, 32) || !canonicalRenewalHex(r.PlanDigest, 32) || r.FeeSats < 0 || r.FeeSats > 5000 || len(r.Plan) == 0 || len(r.Plan) > 8192 || !json.Valid([]byte(r.Plan)) {
		return fmt.Errorf("invalid Light renewal reservation")
	}
	expiry, e1 := time.Parse(time.RFC3339, r.ExpiresAt)
	created, e2 := time.Parse(time.RFC3339, r.CreatedAt)
	if e1 != nil || e2 != nil || !expiry.After(created) || expiry.After(created.Add(10*time.Minute)) {
		return fmt.Errorf("invalid Light renewal times")
	}
	return nil
}
func validateLightRenewalEvent(e LightRenewalEvent) error {
	if !canonicalRenewalHex(e.OperationID, 16) || !canonicalRenewalHex(e.RequestDigest, 32) || len(e.Evidence) > 900000 || len(e.OperatorRef) > 256 {
		return fmt.Errorf("invalid Light renewal phase")
	}
	if _, err := time.Parse(time.RFC3339, e.CreatedAt); err != nil {
		return err
	}
	switch e.Phase {
	case "register_authorized", "final_authorized", "delete_authorized":
		if e.Evidence == "" || !json.Valid([]byte(e.Evidence)) || e.Outcome != "" || e.OperatorRef != "" {
			return fmt.Errorf("Light renewal authorization evidence required")
		}
	case "register_dispatched", "final_dispatched", "delete_dispatched":
		if e.Evidence != "" || e.Outcome != "" || e.OperatorRef != "" {
			return fmt.Errorf("invalid Light renewal dispatch")
		}
	case "register_result":
		if e.Evidence != "" || !(e.Outcome == "registered" && e.OperatorRef != "" || e.Outcome == "rejected" && e.OperatorRef == "") {
			return fmt.Errorf("invalid Light renewal registration result")
		}
	case "final_result":
		if e.Outcome != "submitted" || e.OperatorRef != "" || e.Evidence != "" {
			return fmt.Errorf("invalid Light renewal final result")
		}
	case "delete_result":
		if e.Outcome != "released" || e.OperatorRef != "" || e.Evidence != "" {
			return fmt.Errorf("invalid Light renewal deletion result")
		}
	case "confirmed":
		if e.Outcome != "confirmed" || !canonicalRenewalHex(e.OperatorRef, 32) || e.Evidence == "" || !json.Valid([]byte(e.Evidence)) {
			return fmt.Errorf("invalid Light renewal confirmation")
		}
	case "released":
		if e.Outcome != "" || e.OperatorRef != "" || e.Evidence == "" || !json.Valid([]byte(e.Evidence)) {
			return fmt.Errorf("Light renewal release evidence required")
		}
	case "cancelled":
		if e.Outcome != "" || e.OperatorRef != "" || e.Evidence != "" {
			return fmt.Errorf("invalid Light renewal release")
		}
	default:
		return fmt.Errorf("unsupported Light renewal phase")
	}
	return nil
}
func renewalMAC(key []byte, domain, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain + ":"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// Scan and authenticate before partitioning. A tampered SQL correlation field
// must not hide a reservation or a dispatched phase from conflict handling.
func loadLightRenewals(ctx context.Context, q queryContext, key []byte) (map[string]*LightRenewalSnapshot, error) {
	rows, err := q.QueryContext(ctx, `SELECT operation_id,vault_id,payload,integrity_mac FROM light_renewal_operation`)
	if err != nil {
		return nil, err
	}
	out := map[string]*LightRenewalSnapshot{}
	for rows.Next() {
		var id, vault, payload string
		var mac []byte
		if err := rows.Scan(&id, &vault, &payload, &mac); err != nil {
			rows.Close()
			return nil, err
		}
		if len(payload) > 16384 || !hmac.Equal(mac, renewalMAC(key, "vaulted-light/renewal-operation/v1", payload)) {
			rows.Close()
			return nil, fmt.Errorf("Light renewal operation integrity")
		}
		var op LightRenewalOperation
		if err := json.Unmarshal([]byte(payload), &op); err != nil {
			rows.Close()
			return nil, err
		}
		canonical, _ := json.Marshal(op)
		if string(canonical) != payload || op.OperationID != id || op.VaultID != vault || validateLightRenewalOperation(op) != nil {
			rows.Close()
			return nil, fmt.Errorf("Light renewal operation binding")
		}
		out[id] = &LightRenewalSnapshot{Operation: op, Events: map[string]LightRenewalEvent{}}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = q.QueryContext(ctx, `SELECT operation_id,phase,payload,integrity_mac FROM light_renewal_event`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, phase, payload string
		var mac []byte
		if err := rows.Scan(&id, &phase, &payload, &mac); err != nil {
			return nil, err
		}
		if len(payload) > 1048576 || !hmac.Equal(mac, renewalMAC(key, "vaulted-light/renewal-event/v1", payload)) {
			return nil, fmt.Errorf("Light renewal event integrity")
		}
		var e LightRenewalEvent
		if err := json.Unmarshal([]byte(payload), &e); err != nil {
			return nil, err
		}
		canonical, _ := json.Marshal(e)
		if string(canonical) != payload || e.OperationID != id || e.Phase != phase || out[id] == nil || validateLightRenewalEvent(e) != nil {
			return nil, fmt.Errorf("Light renewal event binding")
		}
		out[id].Events[phase] = e
	}
	return out, rows.Err()
}
func renewalTerminal(s *LightRenewalSnapshot) bool {
	if _, ok := s.Events["confirmed"]; ok {
		return true
	}
	if _, ok := s.Events["released"]; ok {
		return true
	}
	if _, ok := s.Events["cancelled"]; ok {
		return true
	}
	return s.Events["register_result"].Outcome == "rejected"
}
func (l *Ledger) GetLightRenewal(ctx context.Context, id string) (*LightRenewalSnapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	all, err := loadLightRenewals(ctx, l.db, key)
	if err != nil {
		return nil, err
	}
	return all[id], nil
}
func (l *Ledger) withLightRenewalTx(ctx context.Context, apply func(*sql.Conn, []byte) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	tx, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer tx.Close()
	if _, err := tx.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = tx.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err := apply(tx, key); err != nil {
		return err
	}
	if err := l.observeEconomicOutflowsLocked(tx); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `COMMIT`)
	committed = err == nil
	return err
}
func (l *Ledger) ReserveLightRenewal(ctx context.Context, r LightRenewalOperation, allowance int64) (*LightRenewalSnapshot, error) {
	r.CreatedAt = l.NowUTC().Format(time.RFC3339)
	var result *LightRenewalSnapshot
	err := l.withLightRenewalTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadLightRenewals(ctx, tx, key)
		if err != nil {
			return err
		}
		if prior := all[r.OperationID]; prior != nil {
			compare := r
			compare.CreatedAt = prior.Operation.CreatedAt
			if compare != prior.Operation {
				return fmt.Errorf("Light renewal reservation changed")
			}
			result = prior
			return nil
		}
		if err := validateLightRenewalOperation(r); err != nil {
			return err
		}
		for _, prior := range all {
			if prior.Operation.VaultID == r.VaultID && !renewalTerminal(prior) {
				return ErrVtxoOperationActive
			}
		}
		if err := l.rejectConcurrentVtxoOperationLocked(ctx, tx, r.VaultID, ""); err != nil {
			return err
		}
		used, err := l.spentInWindow(ctx, tx, r.VaultID)
		if err != nil {
			return err
		}
		if allowance < 0 || used > allowance || r.FeeSats > allowance-used {
			return ErrPeriodAllowanceExceeded
		}
		payload, _ := json.Marshal(r)
		if _, err := tx.ExecContext(ctx, `INSERT INTO light_renewal_operation(operation_id,vault_id,payload,integrity_mac) VALUES(?,?,?,?)`, r.OperationID, r.VaultID, string(payload), renewalMAC(key, "vaulted-light/renewal-operation/v1", string(payload))); err != nil {
			return err
		}
		result = &LightRenewalSnapshot{Operation: r, Events: map[string]LightRenewalEvent{}}
		return nil
	})
	return result, err
}
func (l *Ledger) AppendLightRenewalEvent(ctx context.Context, e LightRenewalEvent, credentialID []byte, signCount uint32) (LightRenewalEvent, bool, error) {
	e.CreatedAt = l.NowUTC().Format(time.RFC3339)
	if err := validateLightRenewalEvent(e); err != nil {
		return LightRenewalEvent{}, false, err
	}
	var result LightRenewalEvent
	created := false
	err := l.withLightRenewalTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadLightRenewals(ctx, tx, key)
		if err != nil {
			return err
		}
		s := all[e.OperationID]
		if s == nil {
			return fmt.Errorf("Light renewal reservation not found")
		}
		if old, ok := s.Events[e.Phase]; ok {
			compare := e
			compare.CreatedAt = old.CreatedAt
			if compare != old {
				return fmt.Errorf("Light renewal phase changed")
			}
			if e.Phase == "register_authorized" {
				if err := l.verifySignCountReplayLocked(tx, s.Operation.VaultID, credentialID, signCount); err != nil {
					return err
				}
			}
			result = old
			return nil
		}
		if err := validateRenewalTransition(s, e, l.NowUTC()); err != nil {
			return err
		}
		if e.Phase == "register_authorized" {
			if len(credentialID) == 0 {
				return fmt.Errorf("Light renewal passkey required")
			}
			if err := l.advanceSignCountLocked(tx, s.Operation.VaultID, credentialID, signCount); err != nil {
				return err
			}
		} else if len(credentialID) != 0 || signCount != 0 {
			return fmt.Errorf("unexpected Light renewal credential mutation")
		}
		payload, _ := json.Marshal(e)
		if _, err := tx.ExecContext(ctx, `INSERT INTO light_renewal_event(operation_id,phase,payload,integrity_mac) VALUES(?,?,?,?)`, e.OperationID, e.Phase, string(payload), renewalMAC(key, "vaulted-light/renewal-event/v1", string(payload))); err != nil {
			return err
		}
		result = e
		created = true
		return nil
	})
	return result, created, err
}
func validateRenewalTransition(s *LightRenewalSnapshot, e LightRenewalEvent, now time.Time) error {
	if renewalTerminal(s) {
		return fmt.Errorf("Light renewal already terminal")
	}
	events := s.Events
	require := func(phase string) error {
		if _, ok := events[phase]; !ok {
			return fmt.Errorf("Light renewal requires %s", phase)
		}
		return nil
	}
	expiry, _ := time.Parse(time.RFC3339, s.Operation.ExpiresAt)
	switch e.Phase {
	case "register_authorized":
		if len(events) != 0 || !now.Before(expiry) {
			return fmt.Errorf("Light renewal registration expired or started")
		}
	case "register_dispatched":
		if err := require("register_authorized"); err != nil {
			return err
		}
		if !now.Before(expiry) || e.RequestDigest != events["register_authorized"].RequestDigest {
			return fmt.Errorf("Light renewal dispatch changed or expired")
		}
	case "register_result":
		if err := require("register_dispatched"); err != nil {
			return err
		}
		if e.RequestDigest != events["register_dispatched"].RequestDigest || events["delete_authorized"].Phase != "" || events["final_authorized"].Phase != "" {
			return fmt.Errorf("Light renewal registration result changed or superseded")
		}
	case "final_authorized":
		if events["register_result"].Outcome != "registered" || events["delete_authorized"].Phase != "" || !now.Before(expiry) {
			return fmt.Errorf("Light renewal finalization unavailable")
		}
	case "final_dispatched", "final_result":
		if e.Phase == "final_dispatched" && !now.Before(expiry) {
			return fmt.Errorf("Light renewal final dispatch expired")
		}
		prior := "final_authorized"
		if e.Phase == "final_result" {
			prior = "final_dispatched"
		}
		if err := require(prior); err != nil {
			return err
		}
		if e.RequestDigest != events[prior].RequestDigest {
			return fmt.Errorf("Light renewal final request changed")
		}
	case "confirmed":
		if err := require("final_dispatched"); err != nil {
			return err
		}
		if e.RequestDigest != events["final_dispatched"].RequestDigest {
			return fmt.Errorf("Light renewal confirmation changed")
		}
	case "delete_authorized":
		if err := require("register_dispatched"); err != nil {
			return err
		}
		if events["final_authorized"].Phase != "" {
			return fmt.Errorf("Light renewal has a forfeit authorization")
		}
	case "delete_dispatched", "delete_result":
		prior := "delete_authorized"
		if e.Phase == "delete_result" {
			prior = "delete_dispatched"
		}
		if err := require(prior); err != nil {
			return err
		}
		if e.RequestDigest != events[prior].RequestDigest {
			return fmt.Errorf("Light renewal deletion changed")
		}
	case "released":
		if events["register_dispatched"].Phase == "" || events["final_dispatched"].Phase != "" || now.Before(expiry.Add(15*time.Second)) || e.RequestDigest != events["register_dispatched"].RequestDigest {
			return fmt.Errorf("Light renewal release not final")
		}
	case "cancelled":
		if events["register_dispatched"].Phase != "" {
			return fmt.Errorf("Light renewal registration may be live")
		}
		if e.RequestDigest != s.Operation.PlanDigest {
			return fmt.Errorf("Light renewal cancellation changed")
		}
	default:
		return fmt.Errorf("unsupported Light renewal transition")
	}
	return nil
}
func (l *Ledger) lightRenewalAllowance(ctx context.Context, q queryContext, vault string, key []byte) (int64, error) {
	all, err := loadLightRenewals(ctx, q, key)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, s := range all {
		if s.Operation.VaultID != vault {
			continue
		}
		if renewalTerminal(s) {
			confirmed, ok := s.Events["confirmed"]
			if !ok {
				continue
			}
			at, _ := time.Parse(time.RFC3339, confirmed.CreatedAt)
			if l.NowUTC().After(at.Add(allowanceWindow)) {
				continue
			}
		}
		if total > (1<<63-1)-s.Operation.FeeSats {
			return 0, fmt.Errorf("Light renewal allowance overflow")
		}
		total += s.Operation.FeeSats
	}
	return total, nil
}
func (l *Ledger) rejectActiveLightRenewal(ctx context.Context, q queryContext, vault string) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	all, err := loadLightRenewals(ctx, q, key)
	if err != nil {
		return err
	}
	for _, s := range all {
		if s.Operation.VaultID == vault && !renewalTerminal(s) {
			return ErrVtxoOperationActive
		}
	}
	return nil
}
