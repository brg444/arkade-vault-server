package policy

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/program"
)

const schemaVersion = 2
const legacySchemaVersion = 1

var boardingTables = []string{
	"vault_board_authorization",
	"vault_board_dispatch",
	"vault_board_enrollment",
	"vault_board_operation",
	"vault_board_submission",
}

var expectedBoardingTables = map[string]struct {
	cols    []colSpec
	fks     []fkSpec
	indexes []idxSpec
}{
	"vault_board_enrollment": {
		cols: []colSpec{
			spec("vault_id", "TEXT", false, 1), spec("program", "TEXT", true, 0),
			spec("boarding_pub", "BLOB", true, 0), spec("cosigner_pub", "BLOB", true, 0),
			spec("operator_pub", "BLOB", true, 0), spec("exit_delay", "INTEGER", true, 0),
			spec("exit_delay_unit", "TEXT", true, 0), spec("pk_script", "BLOB", true, 0),
			spec("address", "TEXT", true, 0), spec("integrity_mac", "BLOB", true, 0),
		},
		fks:     []fkSpec{{Table: "vault", From: "vault_id", To: "vault_id"}},
		indexes: []idxSpec{{Name: "", Unique: true, Cols: []string{"vault_id"}}},
	},
	"vault_board_operation": {
		cols: []colSpec{
			spec("operation_id", "TEXT", false, 1), spec("vault_id", "TEXT", true, 0),
			spec("txid", "BLOB", true, 0), spec("vout", "INTEGER", true, 0),
			spec("value_sats", "INTEGER", true, 0), spec("boarding_script", "BLOB", true, 0),
			spec("receiver_script", "BLOB", true, 0), spec("sequence_anchor_mtp", "INTEGER", true, 0),
			spec("created_at", "TEXT", true, 0), spec("integrity_mac", "BLOB", true, 0),
		},
		fks: []fkSpec{{Table: "vault_board_enrollment", From: "vault_id", To: "vault_id"}},
		indexes: []idxSpec{
			{Name: "", Unique: true, Cols: []string{"operation_id"}},
			{Name: "", Unique: true, Cols: []string{"vault_id", "txid", "vout"}},
			{Name: "vault_board_operation_vault", Unique: false, Cols: []string{"vault_id", "created_at"}},
		},
	},
	"vault_board_authorization": {
		cols: []colSpec{
			spec("operation_id", "TEXT", true, 1), spec("attempt", "INTEGER", true, 2),
			spec("phase", "TEXT", true, 3), spec("request_digest", "BLOB", true, 0),
			spec("tree_session_pub", "BLOB", false, 0), spec("receiver_sats", "INTEGER", true, 0),
			spec("fee_sats", "INTEGER", true, 0), spec("expire_at", "INTEGER", true, 0),
			spec("commitment_txid", "TEXT", true, 0), spec("receiver_txid", "TEXT", true, 0),
			spec("receiver_vout", "INTEGER", true, 0),
			spec("created_at", "TEXT", true, 0), spec("integrity_mac", "BLOB", true, 0),
		},
		fks: []fkSpec{{Table: "vault_board_operation", From: "operation_id", To: "operation_id"}},
		indexes: []idxSpec{
			{Name: "", Unique: true, Cols: []string{"operation_id", "attempt", "phase"}},
			{Name: "vault_board_authorization_phase", Unique: false, Cols: []string{"phase", "created_at"}},
		},
	},
	"vault_board_submission": {
		cols: []colSpec{
			spec("operation_id", "TEXT", true, 1), spec("attempt", "INTEGER", true, 2),
			spec("phase", "TEXT", true, 3), spec("request_digest", "BLOB", true, 0),
			spec("outcome", "TEXT", true, 0), spec("operator_ref", "TEXT", true, 0),
			spec("commitment_txid", "TEXT", true, 0),
			spec("receiver_txid", "TEXT", true, 0), spec("receiver_vout", "INTEGER", true, 0),
			spec("created_at", "TEXT", true, 0), spec("integrity_mac", "BLOB", true, 0),
		},
		fks: []fkSpec{
			{Table: "vault_board_dispatch", From: "operation_id", To: "operation_id"},
			{Table: "vault_board_dispatch", From: "attempt", To: "attempt"},
			{Table: "vault_board_dispatch", From: "phase", To: "phase"},
			{Table: "vault_board_authorization", From: "operation_id", To: "operation_id"},
			{Table: "vault_board_authorization", From: "attempt", To: "attempt"},
			{Table: "vault_board_authorization", From: "phase", To: "phase"},
		},
		indexes: []idxSpec{{Name: "", Unique: true, Cols: []string{"operation_id", "attempt", "phase"}}},
	},
	"vault_board_dispatch": {
		cols: []colSpec{
			spec("operation_id", "TEXT", true, 1), spec("attempt", "INTEGER", true, 2),
			spec("phase", "TEXT", true, 3), spec("request_digest", "BLOB", true, 0),
			spec("created_at", "TEXT", true, 0), spec("integrity_mac", "BLOB", true, 0),
		},
		fks: []fkSpec{
			{Table: "vault_board_authorization", From: "operation_id", To: "operation_id"},
			{Table: "vault_board_authorization", From: "attempt", To: "attempt"},
			{Table: "vault_board_authorization", From: "phase", To: "phase"},
		},
		indexes: []idxSpec{{Name: "", Unique: true, Cols: []string{"operation_id", "attempt", "phase"}}},
	},
}

const createVaultBoardSchema = `
CREATE TABLE vault_board_enrollment (
  vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
  program TEXT NOT NULL CHECK (program = 'vault-board-v1'),
  boarding_pub BLOB NOT NULL CHECK (length(boarding_pub) = 33),
  cosigner_pub BLOB NOT NULL CHECK (length(cosigner_pub) = 33),
  operator_pub BLOB NOT NULL CHECK (length(operator_pub) = 33),
  exit_delay INTEGER NOT NULL CHECK (exit_delay = 604672),
  exit_delay_unit TEXT NOT NULL CHECK (exit_delay_unit = 'seconds'),
  pk_script BLOB NOT NULL CHECK (length(pk_script) = 34),
  address TEXT NOT NULL CHECK (length(address) > 0 AND length(address) <= 128),
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE vault_board_operation (
  operation_id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vault_board_enrollment(vault_id),
  txid BLOB NOT NULL CHECK (length(txid) = 32),
  vout INTEGER NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
  value_sats INTEGER NOT NULL CHECK (value_sats > 0),
  boarding_script BLOB NOT NULL CHECK (length(boarding_script) = 34),
  receiver_script BLOB NOT NULL CHECK (length(receiver_script) > 0 AND length(receiver_script) <= 10000),
  sequence_anchor_mtp INTEGER NOT NULL CHECK (sequence_anchor_mtp > 0),
  created_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  UNIQUE (vault_id, txid, vout)
);
CREATE TABLE vault_board_authorization (
  operation_id TEXT NOT NULL REFERENCES vault_board_operation(operation_id),
  attempt INTEGER NOT NULL CHECK (attempt >= 0 AND attempt <= 4294967295),
  phase TEXT NOT NULL CHECK (phase IN ('register', 'delete', 'finalize')),
  request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
  tree_session_pub BLOB CHECK (tree_session_pub IS NULL OR length(tree_session_pub) = 33),
  receiver_sats INTEGER NOT NULL CHECK (receiver_sats >= 0),
  fee_sats INTEGER NOT NULL CHECK (fee_sats >= 0),
  expire_at INTEGER NOT NULL CHECK (expire_at >= 0),
  commitment_txid TEXT NOT NULL CHECK (length(commitment_txid) IN (0, 64)),
  receiver_txid TEXT NOT NULL CHECK (length(receiver_txid) IN (0, 64)),
  receiver_vout INTEGER NOT NULL CHECK (receiver_vout >= 0 AND receiver_vout <= 4294967295),
  created_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (operation_id, attempt, phase),
  CHECK (
    (phase = 'register' AND expire_at > 0 AND tree_session_pub IS NOT NULL AND length(tree_session_pub) = 33 AND receiver_sats > 0 AND length(commitment_txid) = 0 AND length(receiver_txid) = 0 AND receiver_vout = 0)
    OR (phase = 'delete' AND expire_at > 0 AND tree_session_pub IS NULL AND receiver_sats = 0 AND fee_sats = 0 AND length(commitment_txid) = 0 AND length(receiver_txid) = 0 AND receiver_vout = 0)
    OR (phase = 'finalize' AND expire_at = 0 AND tree_session_pub IS NULL AND receiver_sats = 0 AND fee_sats = 0 AND length(commitment_txid) = 64 AND length(receiver_txid) = 64)
  )
);
CREATE TABLE vault_board_submission (
  operation_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  phase TEXT NOT NULL,
  request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
  outcome TEXT NOT NULL CHECK (outcome IN ('submitted', 'released', 'rejected')),
  operator_ref TEXT NOT NULL CHECK (length(operator_ref) <= 256),
  commitment_txid TEXT NOT NULL CHECK (length(commitment_txid) IN (0, 64)),
	receiver_txid TEXT NOT NULL CHECK (length(receiver_txid) IN (0, 64)),
	receiver_vout INTEGER NOT NULL CHECK (receiver_vout >= 0 AND receiver_vout <= 4294967295),
  created_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (operation_id, attempt, phase),
  FOREIGN KEY (operation_id, attempt, phase) REFERENCES vault_board_authorization(operation_id, attempt, phase),
	FOREIGN KEY (operation_id, attempt, phase) REFERENCES vault_board_dispatch(operation_id, attempt, phase),
  CHECK (
		(phase = 'register' AND ((outcome = 'submitted' AND length(operator_ref) > 0) OR (outcome = 'rejected' AND length(operator_ref) = 0)) AND length(commitment_txid) = 0 AND length(receiver_txid) = 0 AND receiver_vout = 0)
		OR (phase = 'delete' AND outcome = 'released' AND length(operator_ref) = 0 AND length(commitment_txid) = 0 AND length(receiver_txid) = 0 AND receiver_vout = 0)
		OR (phase = 'finalize' AND outcome = 'submitted' AND length(operator_ref) = 0 AND length(commitment_txid) = 64 AND length(receiver_txid) = 64)
  )
);
CREATE TABLE vault_board_dispatch (
	operation_id TEXT NOT NULL,
	attempt INTEGER NOT NULL,
	phase TEXT NOT NULL,
	request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
	created_at TEXT NOT NULL,
	integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
	PRIMARY KEY (operation_id, attempt, phase),
	FOREIGN KEY (operation_id, attempt, phase) REFERENCES vault_board_authorization(operation_id, attempt, phase)
);
CREATE INDEX vault_board_authorization_phase ON vault_board_authorization(phase, created_at);
CREATE INDEX vault_board_operation_vault ON vault_board_operation(vault_id, created_at);
`

// OpenLedger opens the sole fresh Arkade Vault schema. It never upgrades or
// reinterprets an older database.
func OpenLedger(path string, clock Clock) (*Ledger, error) {
	return OpenLedgerForNetwork(path, clock, program.NetworkMutinynet)
}

// OpenLedgerForNetwork creates or validates the exact boarding schema for the
// selected deployment. It never rewrites an existing schema or accepts the
// other network's boarding delay.
func OpenLedgerForNetwork(path string, clock Clock, network string) (*Ledger, error) {
	boardSchema, err := vaultBoardSchemaForNetwork(network)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("database path required")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{`PRAGMA busy_timeout = 5000`, `PRAGMA synchronous = FULL`, `PRAGMA foreign_keys = ON`} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := initializeOrValidateSchema(db, boardSchema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Ledger{db: db, clock: clock, network: network}, nil
}

func initializeOrValidateLegacySchema(db *sql.DB, boardSchema string) error {
	tables, err := applicationTables(db)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(createMultiTenantSchema + createVtxoSchema + boardSchema); err != nil {
			return fmt.Errorf("create vault schema: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_meta (version) VALUES (?)`, legacySchemaVersion); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		tables = append(append([]string(nil), coreTables...), boardingTables...)
	}
	want := append(append([]string(nil), coreTables...), boardingTables...)
	sort.Strings(want)
	if !sameStrings(tables, want) {
		return fmt.Errorf("database is not the current vault baseline: tables %v", tables)
	}
	if err := validateVaultSchemaObjects(db, false); err != nil {
		return err
	}
	ver, rows, err := schemaMetaState(db)
	if err != nil {
		return err
	}
	if rows != 1 || ver != legacySchemaVersion {
		return fmt.Errorf("database is not the current vault baseline: schema version %d", ver)
	}
	if err := validateMultiTenantSchemaOn(db); err != nil {
		return err
	}
	if err := validateBoardingTables(db, boardSchema); err != nil {
		return err
	}
	if err := requireForeignKeysEnabled(db); err != nil {
		return err
	}
	return requireForeignKeyCheckClean(db)
}

func validateBoardingTables(db *sql.DB, boardSchema string) error {
	for _, table := range boardingTables {
		wantStruct := expectedBoardingTables[table]
		cols, err := readTableXInfo(db, table)
		if err != nil {
			return err
		}
		if err := matchColumns(table, cols, wantStruct.cols); err != nil {
			return err
		}
		fks, err := readForeignKeys(db, table)
		if err != nil {
			return err
		}
		if err := matchForeignKeys(table, fks, wantStruct.fks); err != nil {
			return err
		}
		indexes, err := readIndexes(db, table)
		if err != nil {
			return err
		}
		if err := matchVaultBoardIndexes(table, indexes, wantStruct.indexes); err != nil {
			return err
		}
		var createSQL string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&createSQL); err != nil {
			return fmt.Errorf("vault-board-v1 table %s: %w", table, err)
		}
		want := extractChecksByTable(boardSchema)[table]
		if err := sameCheckSet(table, extractNormalizedChecks(createSQL), want); err != nil {
			return err
		}
	}
	return nil
}

func matchVaultBoardIndexes(table string, got, want []idxSpec) error {
	if len(got) != len(want) {
		return fmt.Errorf("incompatible vault database: %s index count %d, want %d", table, len(got), len(want))
	}
	used := make([]bool, len(got))
	for _, expected := range want {
		matched := false
		for i, actual := range got {
			if used[i] || (expected.Name != "" && actual.Name != expected.Name) || actual.Unique != expected.Unique || !sameStringSlice(actual.Cols, expected.Cols) {
				continue
			}
			used[i] = true
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf("incompatible vault database: %s missing exact index unique=%v cols=%v", table, expected.Unique, expected.Cols)
		}
	}
	return nil
}

func validateVaultSchemaObjects(db *sql.DB, renewal bool) error {
	want := append([]string(nil), coreTables...)
	for i, table := range want {
		want[i] = "table:" + table
	}
	want = append(want,
		"table:vault_board_authorization", "table:vault_board_enrollment",
		"table:vault_board_dispatch", "table:vault_board_operation", "table:vault_board_submission",
		"index:vault_credential_vault", "index:vtxo_operation_input_outpoint",
		"index:vtxo_operation_vault_state_created", "index:vtxo_operation_vault_state_expiry",
		"index:vault_board_authorization_phase", "index:vault_board_operation_vault",
	)
	if renewal {
		want = append(want, "table:light_renewal_operation", "table:light_renewal_event")
	}
	rows, err := db.Query(`SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view') AND (type != 'index' OR sql IS NOT NULL) ORDER BY type, name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return err
		}
		got = append(got, kind+":"+name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !sameStrings(got, want) {
		return fmt.Errorf("database is not the current vault baseline: objects %v", got)
	}
	return nil
}

func vaultBoardSchemaForNetwork(network string) (string, error) {
	switch network {
	case program.NetworkMutinynet:
		return createVaultBoardSchema, nil
	case program.NetworkMainnet:
		return strings.Replace(createVaultBoardSchema, "exit_delay = 604672", fmt.Sprintf("exit_delay = %d", program.MainnetVaultBoardV1ExitDelay), 1), nil
	default:
		return "", fmt.Errorf("unsupported ledger network %q", network)
	}
}
