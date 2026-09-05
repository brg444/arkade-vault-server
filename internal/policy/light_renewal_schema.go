package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

const createLightRenewalSchema = `
CREATE TABLE light_renewal_operation (
 operation_id TEXT PRIMARY KEY,
 vault_id TEXT NOT NULL REFERENCES vault(vault_id),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 16384),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE light_renewal_event (
 operation_id TEXT NOT NULL REFERENCES light_renewal_operation(operation_id),
 phase TEXT NOT NULL CHECK (phase IN ('register_authorized','register_dispatched','register_result','final_authorized','final_dispatched','final_result','confirmed','delete_authorized','delete_dispatched','delete_result','released','cancelled')),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 1048576),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
 PRIMARY KEY (operation_id, phase)
);
`

// Migration adds only Light's named lifecycle store. Existing rows, canonical
// MAC preimages, and the independent economic sequence remain byte-identical.
func initializeOrValidateSchema(db *sql.DB, boardSchema string) error {
	tables, err := applicationTables(db)
	if err != nil {
		return err
	}
	version := 0
	if len(tables) > 0 {
		var count int
		version, count, err = schemaMetaState(db)
		if err != nil || count != 1 {
			return fmt.Errorf("database is not the current vault baseline: invalid schema metadata")
		}
	}
	if version == 0 || version == legacySchemaVersion {
		if err := initializeOrValidateLegacySchema(db, boardSchema); err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.Exec(createLightRenewalSchema); err != nil {
			return fmt.Errorf("create Light renewal store: %w", err)
		}
		if _, err = tx.Exec(`UPDATE schema_meta SET version=? WHERE version=?`, schemaVersion, legacySchemaVersion); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	} else if version != schemaVersion {
		return fmt.Errorf("unsupported vault schema version %d", version)
	}
	if err := validateVaultSchemaObjects(db, true); err != nil {
		return err
	}
	if err := validateMultiTenantSchemaOn(db); err != nil {
		return err
	}
	if err := validateBoardingTables(db, boardSchema); err != nil {
		return err
	}
	for _, statement := range strings.Split(strings.TrimSpace(createLightRenewalSchema), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		fields := strings.Fields(statement)
		name := fields[2]
		var actual string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&actual); err != nil {
			return err
		}
		if normalizeCheck(actual) != normalizeCheck(statement) {
			return fmt.Errorf("Light renewal table %s changed", name)
		}
	}
	if err := requireForeignKeysEnabled(db); err != nil {
		return err
	}
	return requireForeignKeyCheckClean(db)
}
