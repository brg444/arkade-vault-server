package policy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const allowanceWindow = 24 * time.Hour

// Clock is injectable so rolling allowance windows and reservation expiry are
// deterministic in tests.
type Clock func() time.Time

// Ledger is the authenticated SQLite policy store.
type Ledger struct {
	db           *sql.DB
	network      string
	clock        Clock
	mu           sync.Mutex
	integrityKey []byte
	monotonic    *Monotonic
}

// Credential is the application-facing view of one enrolled vault and its
// passkey. Persistence keeps the vault and credential in separate tables.
type Credential struct {
	ID                  []byte
	WebAuthnP256        []byte
	PhoneDirectP256     []byte
	PhoneBIP340         []byte
	ExternalOwnerWallet []byte
	RPID                string
	Origin              string

	RecoveryKey           []byte
	VaultCosignerBase     []byte
	ArkadeCosignerBase    []byte
	ArkadeCosignerOrigin  string
	ArkadeCosignerVersion string
	TemplateVersion       string
	PolicyVersion         string
	ProtectionTier        string
	Network               string
	VaultID               string
	SavingsAddress        string
	SavingsScript         []byte
	RecipientDustSats     int64
	TxRecipientCapSats    int64
	PeriodAllowanceSats   int64
	AbsoluteFeeCapSats    int64
	FeerateCapSatPerV     int64
	IntegrityMAC          []byte
}

func (l *Ledger) Close() error {
	if l == nil {
		return nil
	}
	zeroBytes(l.integrityKey)
	l.integrityKey = nil
	if l.db == nil {
		return nil
	}
	return l.db.Close()
}

// SetIntegrityKey installs the authorizer-derived MAC key exactly once.
func (l *Ledger) SetIntegrityKey(key []byte) error {
	if len(key) != sha256.Size {
		return fmt.Errorf("policy integrity key must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.integrityKey) != 0 {
		if len(l.integrityKey) != sha256.Size || subtle.ConstantTimeCompare(l.integrityKey, key) != 1 {
			return fmt.Errorf("policy integrity key already initialized")
		}
		return nil
	}
	l.integrityKey = append([]byte(nil), key...)
	return nil
}

// RequireIntegrityKey verifies request wiring without mutating the live key.
func (l *Ledger) RequireIntegrityKey(key []byte) error {
	if len(key) != sha256.Size {
		return fmt.Errorf("policy integrity key must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.integrityKey) != sha256.Size {
		return fmt.Errorf("policy integrity key is not initialized")
	}
	if subtle.ConstantTimeCompare(l.integrityKey, key) != 1 {
		return fmt.Errorf("policy integrity key mismatch")
	}
	return nil
}

// PeriodStart is retained as a display label. Allowance enforcement uses a
// rolling 24-hour window over authenticated operation timestamps.
func (l *Ledger) PeriodStart() string {
	return l.NowUTC().Format("2006-01-02")
}

// integrityKeyCopy returns a disposable copy. Callers must hold l.mu.
func (l *Ledger) integrityKeyCopy() ([]byte, error) {
	if len(l.integrityKey) != sha256.Size {
		return nil, fmt.Errorf("policy integrity key required")
	}
	return append([]byte(nil), l.integrityKey...), nil
}

func appendCredentialField(dst, field []byte) ([]byte, error) {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return dst, fmt.Errorf("policy field too large")
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...), nil
}

func zeroBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

func addOutflow(amount, fee int64) (int64, error) {
	if amount < 0 || fee < 0 {
		return 0, fmt.Errorf("negative outflow")
	}
	if fee > 0 && amount > (1<<63-1)-fee {
		return 0, fmt.Errorf("amount+fee overflow")
	}
	return amount + fee, nil
}

type queryContext interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanVtxoOperation(row rowScanner) (VtxoOperation, error) {
	return scanVtxoOperationWith(row)
}

func scanVtxoOperationWith(row rowScanner, trailing ...any) (VtxoOperation, error) {
	var rec VtxoOperation
	var changeVout sql.NullInt64
	dest := []any{
		&rec.OperationID, &rec.VaultID, &rec.Purpose, &rec.BundleDigest, &rec.State,
		&rec.AmountSats, &rec.FeeSats, &rec.FeePolicyDigest, &rec.DestScript, &rec.ChangeScript,
		&rec.ChangeSats, &changeVout,
		&rec.UnsignedPSBT, &rec.AuthorizedPSBT, &rec.PendingProofDigest, &rec.AuthorizedPendingProof,
		&rec.CheckpointPSBTs, &rec.CheckpointRequestPSBTs,
		&rec.CheckpointTapscript, &rec.ArkTxid, &rec.ExpiresAt, &rec.CreatedAt,
		&rec.LastDestScript, &rec.IntegrityMAC,
	}
	dest = append(dest, trailing...)
	err := row.Scan(dest...)
	if err == nil && changeVout.Valid {
		if changeVout.Int64 < 0 || changeVout.Int64 > 1<<32-1 {
			return VtxoOperation{}, fmt.Errorf("vtxo operation change vout")
		}
		vout := uint32(changeVout.Int64)
		rec.ChangeVout = &vout
	}
	return rec, err
}

func nullableVtxoVout(vout *uint32) any {
	if vout == nil {
		return nil
	}
	return int64(*vout)
}

func nullableVtxoDigest(digest []byte) any {
	if len(digest) == 0 {
		return nil
	}
	return digest
}

// SpentInPeriod returns authenticated VTXO outflow in the rolling allowance
// window. Signed and submitted authorizations remain charged until an
// authoritative settlement result prevents delayed execution outside the
// original reservation window. The period argument exists only for status.
func (l *Ledger) SpentInPeriod(ctx context.Context, vaultID, _ string) (int64, error) {
	if vaultID == "" {
		return 0, fmt.Errorf("vault id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spentInWindow(ctx, l.db, vaultID)
}

func (l *Ledger) spentInWindow(ctx context.Context, q queryContext, vaultID string) (int64, error) {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return 0, err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE vault_id = ?`, vaultID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	now := l.NowUTC()
	var total int64
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return 0, err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return 0, fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if !vtxoStateCountsTowardAllowance(rec.State) {
			continue
		}
		created, err := time.Parse(time.RFC3339, rec.CreatedAt)
		if err != nil {
			return 0, fmt.Errorf("vtxo operation created_at: %w", err)
		}
		if !vtxoStateAwaitingSettlement(rec.State) && now.After(created.Add(allowanceWindow)) {
			continue
		}
		need, err := addOutflow(rec.AmountSats, rec.FeeSats)
		if err != nil {
			return 0, err
		}
		if total > (1<<63-1)-need {
			return 0, fmt.Errorf("period spent overflow")
		}
		total += need
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	renewal, err := l.lightRenewalAllowance(ctx, q, vaultID, key)
	if err != nil {
		return 0, err
	}
	return addOutflow(total, renewal)
}

// AttachMonotonic installs the external policy sequence and immediately
// compares it with all durable economic-outflow reservations.
func (l *Ledger) AttachMonotonic(m *Monotonic) error {
	if l == nil {
		return fmt.Errorf("ledger required")
	}
	if m == nil {
		return fmt.Errorf("monotonic policy sequence required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.monotonic = m
	return l.observeEconomicOutflowsLocked(l.db)
}

func economicOutflowCount(q queryContext) (uint64, error) {
	var n int64
	query := `SELECT COUNT(*) FROM vtxo_operation`
	var boardTables int
	if err := q.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('vault_board_authorization','vault_board_dispatch','vault_board_submission')`).Scan(&boardTables); err != nil {
		return 0, err
	}
	if boardTables == 3 {
		query = `SELECT (SELECT COUNT(*) FROM vtxo_operation) + (SELECT COUNT(*) FROM vault_board_authorization) + (SELECT COUNT(*) FROM vault_board_dispatch) + (SELECT COUNT(*) FROM vault_board_submission)`
	}
	var renewalTables int
	if err := q.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('light_renewal_operation','light_renewal_event')`).Scan(&renewalTables); err != nil {
		return 0, err
	}
	if renewalTables == 2 {
		query = `SELECT (` + query + `) + (SELECT COUNT(*) FROM light_renewal_operation) + (SELECT COUNT(*) FROM light_renewal_event)`
	}
	if err := q.QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("economic outflow count")
	}
	return uint64(n), nil
}

func (l *Ledger) observeEconomicOutflowsLocked(q queryContext) error {
	if l == nil || l.monotonic == nil {
		return nil
	}
	n, err := economicOutflowCount(q)
	if err != nil {
		return err
	}
	return l.monotonic.Observe(n)
}
