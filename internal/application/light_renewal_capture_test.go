package application

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
)

// Opt-in diagnostic uses only owner-signed request data and a read-only copy
// of the test plan. It never loads cosigner keys or submits a transaction.
func TestLightRenewalCapturedRegistration(t *testing.T) {
	directory := os.Getenv("VAULT_LIGHT_RENEWAL_CAPTURE")
	if directory == "" {
		t.Skip("captured Mutinynet renewal not requested")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "register-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request lightRenewalRegisterRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(directory, "browser-owner-backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var backup struct {
		Saved struct {
			Descriptor light.Descriptor `json:"descriptor"`
		} `json:"saved"`
	}
	if err := json.Unmarshal(raw, &backup); err != nil {
		t.Fatal(err)
	}
	if backup.Saved.Descriptor.Network != "mutinynet" {
		t.Fatal("Mutinynet only")
	}
	path := filepath.Join(filepath.Dir(directory), "runtime", "light-browser.sqlite")
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var payload string
	if err := db.QueryRowContext(context.Background(), `SELECT payload FROM light_renewal_operation WHERE operation_id=?`, request.OperationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var operation policy.LightRenewalOperation
	if err := json.Unmarshal([]byte(payload), &operation); err != nil {
		t.Fatal(err)
	}
	var plan lightRenewalPlan
	if err := json.Unmarshal([]byte(operation.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	tree, err := buildLightPolicyTree(backup.Saved.Descriptor, mustDecodeRenewalHex(deployment.MutinynetOperatorSignerPubHex), "tark")
	if err != nil {
		t.Fatal(err)
	}
	registration, err := verifyLightRenewalRegistration(request.PSBT, request.Message, plan, backup.Saved.Descriptor, tree)
	if err != nil {
		t.Fatal(err)
	}
	stateRaw, err := os.ReadFile(filepath.Join(directory, "browser-state.json"))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		State struct {
			Origins []struct {
				LocalStorage []struct{ Name, Value string } `json:"localStorage"`
			} `json:"origins"`
		} `json:"state"`
	}
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		t.Fatal(err)
	}
	for _, origin := range state.State.Origins {
		for _, row := range origin.LocalStorage {
			if row.Name != "vaulted-light-renewal:"+plan.VaultID {
				continue
			}
			var journal struct {
				Final *lightRenewalFinalEvidence `json:"final"`
			}
			if err := json.Unmarshal([]byte(row.Value), &journal); err != nil {
				t.Fatal(err)
			}
			if journal.Final != nil {
				if _, err := verifyLightRenewalFinal(*journal.Final, plan, backup.Saved.Descriptor, tree, registration); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
