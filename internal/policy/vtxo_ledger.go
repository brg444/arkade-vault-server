package policy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const vtxoSelectColumns = `operation_id, vault_id, purpose, bundle_digest, state,
		        amount_sats, fee_sats, fee_policy_digest, dest_script, change_script,
		        change_sats, change_vout,
		        IFNULL(unsigned_psbt, ''), IFNULL(authorized_psbt, ''),
		        pending_proof_digest, IFNULL(authorized_pending_proof, ''),
		        IFNULL(checkpoint_psbts, ''), IFNULL(checkpoint_request_psbts, ''),
		        checkpoint_tapscript, IFNULL(ark_txid, ''), IFNULL(expires_at, ''),
		        created_at, last_dest_script, integrity_mac`

const vtxoOverlapSelectColumns = `o.operation_id, o.vault_id, o.purpose, o.bundle_digest, o.state,
		        o.amount_sats, o.fee_sats, o.fee_policy_digest, o.dest_script, o.change_script,
		        o.change_sats, o.change_vout,
		        IFNULL(o.unsigned_psbt, ''), IFNULL(o.authorized_psbt, ''),
		        o.pending_proof_digest, IFNULL(o.authorized_pending_proof, ''),
		        IFNULL(o.checkpoint_psbts, ''), IFNULL(o.checkpoint_request_psbts, ''),
		        o.checkpoint_tapscript, IFNULL(o.ark_txid, ''), IFNULL(o.expires_at, ''),
		        o.created_at, o.last_dest_script, o.integrity_mac`

const maxReservedVtxoInputs = MaxVtxoOperationInputs

// ErrPeriodAllowanceExceeded is returned when a reservation would exceed the
// vault's enrolled rolling-period allowance. The application boundary maps
// this sentinel to the stable, deliberately public wallet error contract.
var ErrPeriodAllowanceExceeded = errors.New("period allowance exceeded")

// ErrVtxoOperationActive is returned when any nonterminal Spending lifecycle
// already fences the vault against a second reservation.
var ErrVtxoOperationActive = errors.New("vtxo operation already active")

// NowUTC is the ledger clock. Reservation expiry and allowance share it.
func (l *Ledger) NowUTC() time.Time {
	if l == nil || l.clock == nil {
		return time.Now().UTC()
	}
	return l.clock().UTC()
}

// GetVtxoOperation returns one MAC-verified operation.
func (l *Ledger) GetVtxoOperation(ctx context.Context, operationID string) (VtxoOperation, error) {
	if operationID == "" {
		return VtxoOperation{}, fmt.Errorf("vtxo operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadVtxoOperation(ctx, l.db, operationID)
}

// GetVtxoOperationInputs returns MAC-verified reserved outpoints.
func (l *Ledger) GetVtxoOperationInputs(ctx context.Context, operationID string) ([]VtxoOperationInput, error) {
	if operationID == "" {
		return nil, fmt.Errorf("vtxo operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadVtxoOperationInputs(ctx, l.db, operationID)
}

// ListVtxoOperations returns MAC-verified operations for one vault.
func (l *Ledger) ListVtxoOperations(ctx context.Context, vaultID string) ([]VtxoOperation, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	rows, err := l.db.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE vault_id = ?`, vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VtxoOperation
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return nil, err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return nil, fmt.Errorf("vtxo operation integrity: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ReserveVtxoOperation inserts a reserved row and its inputs after checking
// overlapping live outpoints and the rolling allowance.
func (l *Ledger) ReserveVtxoOperation(ctx context.Context, rec VtxoOperation, inputs []VtxoOperationInput, remainingCap int64) error {
	if rec.OperationID == "" || rec.VaultID == "" {
		return fmt.Errorf("vtxo operation identity required")
	}
	if rec.State != vtxoStateReserved {
		return fmt.Errorf("reserve requires reserved state")
	}
	if remainingCap < 0 {
		return fmt.Errorf("negative allowance")
	}
	if len(inputs) == 0 || len(inputs) > maxReservedVtxoInputs {
		return fmt.Errorf("vtxo reservation input count must be 1..%d", maxReservedVtxoInputs)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	connClosed := false
	defer func() {
		if !connClosed {
			_ = conn.Close()
		}
	}()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err := l.abortExpiredVtxoLocked(ctx, conn, rec.VaultID, l.clock().UTC()); err != nil {
		return err
	}
	if err := l.rejectOverlappingVtxoInputs(ctx, conn, rec.OperationID, inputs); err != nil {
		return err
	}
	if err := l.rejectConcurrentVtxoOperationLocked(ctx, conn, rec.VaultID, rec.OperationID); err != nil {
		return err
	}
	if err := l.rejectActiveLightRenewal(ctx, conn, rec.VaultID); err != nil {
		return err
	}
	usedAmt, err := l.spentInWindow(ctx, conn, rec.VaultID)
	if err != nil {
		return err
	}
	need, err := addOutflow(rec.AmountSats, rec.FeeSats)
	if err != nil {
		return err
	}
	if usedAmt > remainingCap {
		return ErrPeriodAllowanceExceeded
	}
	if need > remainingCap-usedAmt {
		return ErrPeriodAllowanceExceeded
	}
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	if err := SealVtxoOperation(&rec, key); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `
INSERT INTO vtxo_operation (
  operation_id, vault_id, purpose, bundle_digest, state,
  amount_sats, fee_sats, fee_policy_digest, dest_script, change_script,
  change_sats, change_vout,
  unsigned_psbt, authorized_psbt, pending_proof_digest, authorized_pending_proof,
  checkpoint_psbts, checkpoint_request_psbts,
  checkpoint_tapscript, ark_txid, expires_at, created_at, last_dest_script,
  integrity_mac
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.OperationID, rec.VaultID, rec.Purpose, rec.BundleDigest, rec.State,
		rec.AmountSats, rec.FeeSats, rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript,
		rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
		rec.UnsignedPSBT, rec.AuthorizedPSBT, nullableVtxoDigest(rec.PendingProofDigest), rec.AuthorizedPendingProof,
		rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs,
		rec.CheckpointTapscript, rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt,
		rec.LastDestScript, rec.IntegrityMAC,
	); err != nil {
		return err
	}
	for i := range inputs {
		in := inputs[i]
		in.OperationID = rec.OperationID
		if err := SealVtxoOperationInput(&in, key); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `
INSERT INTO vtxo_operation_input (
  operation_id, txid, vout, value_sats, script, integrity_mac
) VALUES (?, ?, ?, ?, ?, ?)`,
			in.OperationID, in.Txid, in.Vout, in.ValueSats, in.Script, in.IntegrityMAC,
		); err != nil {
			return err
		}
	}
	// Advance rollback protection while the reservation can still be rolled
	// back. A sequence-ahead database is a deliberate fail-closed state; a
	// database-ahead sequence would permit allowance reuse after restoration.
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return fmt.Errorf("policy sequence: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return err
	}
	commit = true
	return nil
}

// rejectConcurrentVtxoOperationLocked enforces one unresolved Spending
// lifecycle per vault. This prevents a client that lost or discarded its
// local operation record from reserving successive, disjoint sets of coins.
// Every row is authenticated before its state is trusted.
func (l *Ledger) rejectConcurrentVtxoOperationLocked(
	ctx context.Context, q queryContext, vaultID, operationID string,
) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE vault_id = ?`, vaultID)
	if err != nil {
		return err
	}
	defer rows.Close()
	blocked := false
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if rec.OperationID != operationID && vtxoStateBlocksNewOperation(rec.State) {
			blocked = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if blocked {
		return ErrVtxoOperationActive
	}
	return nil
}

// TransitionVtxoOperation reseals and advances one operation only from the
// caller's verified state. A false swapped result returns the MAC-verified
// current row so the application can distinguish an exact retry from a
// conflicting concurrent mutation.
func (l *Ledger) TransitionVtxoOperation(ctx context.Context, expectedState string, rec VtxoOperation) (current VtxoOperation, swapped bool, err error) {
	if rec.OperationID == "" || rec.VaultID == "" {
		return VtxoOperation{}, false, fmt.Errorf("vtxo operation identity required")
	}
	if !validVtxoTransition(expectedState, rec.State) {
		return VtxoOperation{}, false, fmt.Errorf("invalid vtxo state transition %s -> %s", expectedState, rec.State)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return VtxoOperation{}, false, err
	}
	defer zeroBytes(key)
	if err := SealVtxoOperation(&rec, key); err != nil {
		return VtxoOperation{}, false, err
	}
	res, err := updateVtxoOperation(ctx, l.db, expectedState, rec)
	if err != nil {
		return VtxoOperation{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return VtxoOperation{}, false, err
	}
	if n == 1 {
		return rec, true, nil
	}
	current, err = l.loadVtxoOperation(ctx, l.db, rec.OperationID)
	if err != nil {
		return VtxoOperation{}, false, err
	}
	return current, false, nil
}

// CommitSignedVtxoOperation atomically advances the reserved operation and the
// authenticator counter. A crash can therefore leave either both durable or
// neither durable, preserving exact authorize retry for counterful passkeys.
func (l *Ledger) CommitSignedVtxoOperation(
	ctx context.Context, rec VtxoOperation, credentialID []byte, signCount uint32,
) (current VtxoOperation, swapped bool, err error) {
	if rec.OperationID == "" || rec.VaultID == "" || len(credentialID) == 0 || rec.State != vtxoStateSigned {
		return VtxoOperation{}, false, fmt.Errorf("signed vtxo operation identity required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return VtxoOperation{}, false, err
	}
	defer zeroBytes(key)
	if err := SealVtxoOperation(&rec, key); err != nil {
		return VtxoOperation{}, false, err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return VtxoOperation{}, false, err
	}
	defer tx.Rollback()
	res, err := updateVtxoOperation(ctx, tx, vtxoStateReserved, rec)
	if err != nil {
		return VtxoOperation{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return VtxoOperation{}, false, err
	}
	if n != 1 {
		current, err = l.loadVtxoOperation(ctx, tx, rec.OperationID)
		if err != nil {
			return VtxoOperation{}, false, err
		}
		if current.State == vtxoStateSigned {
			if err := l.verifySignCountReplayLocked(tx, rec.VaultID, credentialID, signCount); err != nil {
				return VtxoOperation{}, false, err
			}
		}
		return current, false, nil
	}
	if err := l.advanceSignCountLocked(tx, rec.VaultID, credentialID, signCount); err != nil {
		return VtxoOperation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return VtxoOperation{}, false, err
	}
	return rec, true, nil
}

// VerifySignedVtxoReplay accepts an equal authenticator counter only when it
// belongs to the same durable signed operation. General authentications remain
// strictly monotonic through AdvanceSignCount.
func (l *Ledger) VerifySignedVtxoReplay(
	ctx context.Context, operationID, vaultID string, credentialID []byte, signCount uint32,
) error {
	if operationID == "" || vaultID == "" || len(credentialID) == 0 {
		return fmt.Errorf("signed vtxo replay identity required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.integrityKey) != sha256.Size {
		return fmt.Errorf("sign count ledger required")
	}
	rec, err := l.loadVtxoOperation(ctx, l.db, operationID)
	if err != nil {
		return err
	}
	if rec.VaultID != vaultID || rec.State != vtxoStateSigned {
		return fmt.Errorf("signed vtxo replay state mismatch")
	}
	return l.verifySignCountReplayLocked(l.db, vaultID, credentialID, signCount)
}

func updateVtxoOperation(ctx context.Context, q queryContext, expectedState string, rec VtxoOperation) (sql.Result, error) {
	return q.ExecContext(ctx, `
UPDATE vtxo_operation SET
  purpose = ?, bundle_digest = ?, state = ?, amount_sats = ?, fee_sats = ?,
  fee_policy_digest = ?, dest_script = ?, change_script = ?, change_sats = ?, change_vout = ?,
  unsigned_psbt = ?, authorized_psbt = ?,
  pending_proof_digest = ?, authorized_pending_proof = ?,
  checkpoint_psbts = ?, checkpoint_request_psbts = ?, checkpoint_tapscript = ?,
  ark_txid = ?, expires_at = ?, created_at = ?, last_dest_script = ?,
  integrity_mac = ?
 WHERE operation_id = ? AND vault_id = ? AND state = ?`,
		rec.Purpose, rec.BundleDigest, rec.State, rec.AmountSats, rec.FeeSats,
		rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript, rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
		rec.UnsignedPSBT, rec.AuthorizedPSBT,
		nullableVtxoDigest(rec.PendingProofDigest), rec.AuthorizedPendingProof,
		rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs, rec.CheckpointTapscript,
		rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt, rec.LastDestScript,
		rec.IntegrityMAC, rec.OperationID, rec.VaultID, expectedState,
	)
}

func validVtxoTransition(from, to string) bool {
	switch from {
	case vtxoStateReserved:
		return to == vtxoStateSigned || to == vtxoStateAborted
	case vtxoStateSigned:
		return to == vtxoStateSubmitted
	case vtxoStateSubmitted:
		return to == vtxoStateFinalized || to == vtxoStateUnresolved
	default:
		return false
	}
}

func (l *Ledger) loadVtxoOperation(ctx context.Context, q queryContext, operationID string) (VtxoOperation, error) {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return VtxoOperation{}, err
	}
	defer zeroBytes(key)
	row := q.QueryRowContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE operation_id = ?`, operationID)
	rec, err := scanVtxoOperation(row)
	if err == sql.ErrNoRows {
		return VtxoOperation{}, err
	}
	if err != nil {
		return VtxoOperation{}, err
	}
	if err := VerifyVtxoOperation(&rec, key); err != nil {
		return VtxoOperation{}, fmt.Errorf("vtxo operation integrity: %w", err)
	}
	return rec, nil
}

func (l *Ledger) loadVtxoOperationInputs(ctx context.Context, q queryContext, operationID string) ([]VtxoOperationInput, error) {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `
SELECT operation_id, txid, vout, value_sats, script, integrity_mac
  FROM vtxo_operation_input WHERE operation_id = ? ORDER BY txid, vout`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VtxoOperationInput
	for rows.Next() {
		var in VtxoOperationInput
		if err := rows.Scan(&in.OperationID, &in.Txid, &in.Vout, &in.ValueSats, &in.Script, &in.IntegrityMAC); err != nil {
			return nil, err
		}
		if err := VerifyVtxoOperationInput(&in, key); err != nil {
			return nil, fmt.Errorf("vtxo operation input integrity: %w", err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func (l *Ledger) abortExpiredVtxoLocked(ctx context.Context, q queryContext, vaultID string, now time.Time) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation
WHERE vault_id = ? AND state = ? AND expires_at != '' AND expires_at <= ?`,
		vaultID, vtxoStateReserved, now.Format(time.RFC3339))
	if err != nil {
		return err
	}
	defer rows.Close()
	var expired []VtxoOperation
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if rec.ExpiresAt == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil {
			return fmt.Errorf("vtxo reservation expiry")
		}
		if !now.Before(exp) {
			expired = append(expired, rec)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range expired {
		expired[i].State = vtxoStateAborted
		if err := SealVtxoOperation(&expired[i], key); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, `
UPDATE vtxo_operation SET state = ?, integrity_mac = ? WHERE operation_id = ? AND state = ?`,
			expired[i].State, expired[i].IntegrityMAC, expired[i].OperationID, vtxoStateReserved,
		); err != nil {
			return err
		}
	}
	return nil
}

func (l *Ledger) rejectOverlappingVtxoInputs(ctx context.Context, q queryContext, operationID string, inputs []VtxoOperationInput) error {
	if len(inputs) == 0 || len(inputs) > maxReservedVtxoInputs {
		return fmt.Errorf("vtxo overlap input count must be 1..%d", maxReservedVtxoInputs)
	}
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)

	var predicates strings.Builder
	args := make([]any, 0, 2*len(inputs))
	for i := range inputs {
		if i > 0 {
			predicates.WriteString(" OR ")
		}
		predicates.WriteString("(i.txid = ? AND i.vout = ?)")
		args = append(args, inputs[i].Txid, inputs[i].Vout)
	}
	rows, err := q.QueryContext(ctx, `
SELECT `+vtxoOverlapSelectColumns+`,
       i.operation_id, i.txid, i.vout, i.value_sats, i.script, i.integrity_mac
  FROM vtxo_operation_input AS i
  JOIN vtxo_operation AS o ON o.operation_id = i.operation_id
 WHERE `+predicates.String()+`
 ORDER BY i.txid, i.vout, i.operation_id`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type authenticatedMatch struct {
		operationID string
		state       string
	}
	matches := make([]authenticatedMatch, 0)
	for rows.Next() {
		var in VtxoOperationInput
		rec, err := scanVtxoOperationWith(
			rows,
			&in.OperationID, &in.Txid, &in.Vout, &in.ValueSats, &in.Script, &in.IntegrityMAC,
		)
		if err != nil {
			return err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if err := VerifyVtxoOperationInput(&in, key); err != nil {
			return fmt.Errorf("vtxo operation input integrity: %w", err)
		}
		if in.OperationID != rec.OperationID {
			return fmt.Errorf("vtxo operation input parent mismatch")
		}
		matches = append(matches, authenticatedMatch{operationID: rec.OperationID, state: rec.State})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, match := range matches {
		// The current operation is excluded only after both joined records have
		// authenticated. This permits exact replay without trusting its row key.
		if match.operationID == operationID {
			continue
		}
		// State is deliberately evaluated only after the operation MAC verifies.
		if vtxoStateLocksInputs(match.state) {
			return fmt.Errorf("vtxo outpoint already reserved")
		}
	}
	return nil
}
