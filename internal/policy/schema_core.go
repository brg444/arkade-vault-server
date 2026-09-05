package policy

import (
	"database/sql"
	"sort"
)

var coreTables = []string{
	"invite",
	"pending_enrollment",
	"recovery_session",
	"schema_meta",
	"vault",
	"vault_credential",
	"vault_envelope",
	"vault_map",
	"vtxo_operation",
	"vtxo_operation_input",
	"webauthn_sign_count",
}

const createVtxoSchema = `
CREATE TABLE vtxo_operation (
  operation_id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vault(vault_id),
  purpose TEXT NOT NULL CHECK (purpose = 'spend'),
  bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
  state TEXT NOT NULL CHECK (state IN ('reserved', 'signed', 'submitted', 'finalized', 'aborted', 'unresolved')),
  amount_sats INTEGER NOT NULL CHECK (amount_sats >= 0),
  fee_sats INTEGER NOT NULL CHECK (fee_sats >= 0),
  fee_policy_digest BLOB NOT NULL CHECK (length(fee_policy_digest) = 32),
  dest_script BLOB,
  change_script BLOB,
  change_sats INTEGER NOT NULL CHECK (change_sats >= 0),
  change_vout INTEGER CHECK (change_vout >= 0),
  unsigned_psbt TEXT,
  authorized_psbt TEXT,
  pending_proof_digest BLOB CHECK (pending_proof_digest IS NULL OR length(pending_proof_digest) = 32),
  authorized_pending_proof TEXT,
  checkpoint_psbts TEXT,
  checkpoint_request_psbts TEXT,
  checkpoint_tapscript BLOB,
  ark_txid TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  last_dest_script BLOB,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  CHECK (
    (change_sats = 0 AND change_vout IS NULL AND (change_script IS NULL OR length(change_script) = 0))
    OR (change_sats >= 330 AND change_vout = 1 AND change_script IS NOT NULL AND length(change_script) > 0)
  ),
  CHECK (
    (pending_proof_digest IS NULL AND (authorized_pending_proof IS NULL OR length(authorized_pending_proof) = 0))
    OR (length(pending_proof_digest) = 32 AND authorized_pending_proof IS NOT NULL AND length(authorized_pending_proof) > 0)
  )
);
CREATE TABLE vtxo_operation_input (
  operation_id TEXT NOT NULL REFERENCES vtxo_operation(operation_id),
  txid BLOB NOT NULL CHECK (length(txid) = 32),
  vout INTEGER NOT NULL CHECK (vout >= 0),
  value_sats INTEGER NOT NULL CHECK (value_sats >= 0),
  script BLOB,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (operation_id, txid, vout)
);
CREATE INDEX vtxo_operation_vault_state_created ON vtxo_operation(vault_id, state, created_at);
CREATE INDEX vtxo_operation_vault_state_expiry ON vtxo_operation(vault_id, state, expires_at);
CREATE INDEX vtxo_operation_input_outpoint ON vtxo_operation_input(txid, vout, operation_id);
`

func hasTable(db *sql.DB, table string) bool {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	return err == nil && name == table
}

func knownSchemaTable(table string) bool {
	if table == "light_renewal_operation" || table == "light_renewal_event" {
		return true
	}
	for _, known := range coreTables {
		if table == known {
			return true
		}
	}
	for _, known := range boardingTables {
		if table == known {
			return true
		}
	}
	return false
}

func applicationTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func sameStrings(left, right []string) bool {
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
