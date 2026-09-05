package arkadevaultv1

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
	arkaderuntime "github.com/brg444/arkade-runtime/internal/runtime"
)

func TestArkadeVaultV1IsOneComposedProfile(t *testing.T) {
	definition := Definition()
	if definition.ID != ProfileID || len(definition.Modules) != 1 || definition.Modules[0].ID != ModuleID {
		t.Fatalf("profile composition = %+v", definition)
	}
	module := definition.Modules[0]
	if want := []string{SavingsRecoveryProgram, program.VaultBoardV1, program.VaultPolicyV1}; !reflect.DeepEqual(module.Programs, want) {
		t.Fatalf("programs = %v, want %v", module.Programs, want)
	}
	if !reflect.DeepEqual(module.Policies, []string{SpendingPolicy}) {
		t.Fatalf("policies = %v", module.Policies)
	}
	if want := []string{"identity-store", "allowance-store", "vtxo-operation-store", "recovery-operation-store", "map-store", "vault-board-store"}; !reflect.DeepEqual(module.Stores, want) {
		t.Fatalf("stores = %v, want %v", module.Stores, want)
	}
	if want := []string{
		"enrollment-derivation",
		"savings-recovery-authorization",
		"vtxo-transaction-authorization",
		"vtxo-checkpoint-authorization",
		"vault-board-authorization",
		"public-emulator-operation",
	}; !reflect.DeepEqual(module.KeyScopes, want) {
		t.Fatalf("key scopes = %v, want %v", module.KeyScopes, want)
	}
	registry, err := arkaderuntime.Compile(definition)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.ProfileIDs(); !reflect.DeepEqual(got, []string{ProfileID}) {
		t.Fatalf("compiled profiles = %v", got)
	}
}

func TestArkadeVaultV1RoutesMatchCompatibilityGolden(t *testing.T) {
	raw, err := os.ReadFile("../../application/testdata/http-v1-compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Routes map[string][]string `json:"routes"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]struct{})
	for path, methods := range golden.Routes {
		// Process liveness and lifecycle readiness are common runtime routes,
		// not profile-owned routes. The mounted handler still serves their
		// exact compatibility-frozen behavior.
		if path == "/health" || path == "/ready" || strings.HasPrefix(path, "/v1/light/") {
			continue
		}
		for _, method := range methods {
			want[method+" "+path] = struct{}{}
		}
	}
	got := make(map[string]struct{})
	for _, route := range Definition().Routes {
		got[route.Method+" "+route.Path] = struct{}{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled profile routes = %v, want %v", got, want)
	}
}
