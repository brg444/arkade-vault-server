package policy

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func legacyRenewalDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if err := initializeOrValidateLegacySchema(db, createVaultBoardSchema); err != nil {
		t.Fatal(err)
	}
	return db, path
}
func TestLightRenewalMigrationPreservesLegacyRecordsAndSequence(t *testing.T) {
	db, path := legacyRenewalDatabase(t)
	old := &Ledger{db: db, clock: defaultRenewalTestClock, network: "mutinynet"}
	if err := old.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, old, "legacy-wallet", 0x56)
	var before []byte
	if err := db.QueryRow(`SELECT integrity_mac FROM vault WHERE vault_id='legacy-wallet'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenLedger(path, defaultRenewalTestClock)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var after []byte
	if err := migrated.db.QueryRow(`SELECT integrity_mac FROM vault WHERE vault_id='legacy-wallet'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("migration changed authenticated identity")
	}
	if version, err := migrated.SchemaVersion(); err != nil || version != 2 {
		t.Fatalf("migration version %d %v", version, err)
	}
	if n, err := economicOutflowCount(migrated.db); err != nil || n != 0 {
		t.Fatalf("empty renewal changed sequence %d %v", n, err)
	}
}
func TestLightRenewalMigrationRejectsTamperedLegacyBeforeWriting(t *testing.T) {
	for _, mutation := range []string{
		`CREATE TABLE light_renewal_operation (junk TEXT)`,
		`ALTER TABLE vault ADD COLUMN junk TEXT`,
		`DROP INDEX vtxo_operation_input_outpoint`,
		`CREATE TRIGGER tamper AFTER INSERT ON schema_meta BEGIN DELETE FROM vault; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			db, path := legacyRenewalDatabase(t)
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if l, err := OpenLedger(path, nil); err == nil {
				l.Close()
				t.Fatal("tampered legacy migrated")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			if err := db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || version != 1 {
				t.Fatalf("changed refused schema: %d %v", version, err)
			}
			if hasTable(db, "light_renewal_event") {
				t.Fatal("partial migration survived")
			}
		})
	}
}
func TestLightRenewalSchemaRejectsDriftOnRestart(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE light_renewal_event ADD COLUMN junk TEXT`,
		`DROP TABLE light_renewal_event`,
		`CREATE INDEX hidden_phase ON light_renewal_event(phase)`,
		`CREATE TRIGGER erase_renewals AFTER INSERT ON light_renewal_event BEGIN DELETE FROM light_renewal_operation; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "current.sqlite")
			l, err := OpenLedger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			l.Close()
			if accepted, err := OpenLedger(path, nil); err == nil {
				accepted.Close()
				t.Fatal("renewal schema drift accepted")
			}
		})
	}
}

func defaultRenewalTestClock() time.Time { return time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC) }
