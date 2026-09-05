package arkadevaultv1_test

import (
	"reflect"
	"testing"

	arkadevaultv1 "github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
)

func TestStorePortsExposeOnlyNamedVaultOperations(t *testing.T) {
	tests := []struct {
		name string
		typ  reflect.Type
		want []string
	}{
		{
			name: "identity", typ: reflect.TypeOf((*arkadevaultv1.IdentityStore)(nil)).Elem(),
			want: []string{
				"AdvanceSignCount", "CreateVault", "GetInvite", "GetPendingByHandle",
				"GetVaultEnvelope", "IssueEnrollmentSession", "ListVaultIDs", "LoadVerifiedVault", "ReplaceVaultEnvelope",
				"RequireIntegrityKey", "ReservePendingEnrollment", "SchemaVersion",
				"StoreVaultEnvelopeIfAbsent",
			},
		},
		{
			name: "allowance", typ: reflect.TypeOf((*arkadevaultv1.AllowanceStore)(nil)).Elem(),
			want: []string{"PeriodStart", "ReserveVtxoOperation", "SpentInPeriod"},
		},
		{
			name: "VTXO operation", typ: reflect.TypeOf((*arkadevaultv1.VtxoOperationStore)(nil)).Elem(),
			want: []string{"CommitSignedVtxoOperation", "GetVtxoOperation", "GetVtxoOperationInputs", "NowUTC", "TransitionVtxoOperation", "VerifySignedVtxoReplay"},
		},
		{
			name: "recovery operation", typ: reflect.TypeOf((*arkadevaultv1.RecoveryOperationStore)(nil)).Elem(),
			want: []string{"ApplyRecoveryReplay"},
		},
		{
			name: "map", typ: reflect.TypeOf((*arkadevaultv1.MapStore)(nil)).Elem(),
			want: []string{"GetVaultMap", "PutVaultMap"},
		},
		{
			name: "Light renewal", typ: reflect.TypeOf((*arkadevaultv1.LightRenewalStore)(nil)).Elem(),
			want: []string{"AppendLightRenewalEvent", "GetLightRenewal", "ReserveLightRenewal"},
		},
		{
			name: "Vault Board", typ: reflect.TypeOf((*arkadevaultv1.VaultBoardStore)(nil)).Elem(),
			want: []string{
				"AppendVaultBoardAuthorizationAndDispatch", "AppendVaultBoardDispatch",
				"AppendVaultBoardSubmission", "BeginVaultBoardAttempt", "CreateVaultWithBoard",
				"GetCurrentVaultBoardAttempt", "GetVaultBoardEnrollment",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := make([]string, test.typ.NumMethod())
			for i := range got {
				got[i] = test.typ.Method(i).Name
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("%s store methods = %v, want %v", test.name, got, test.want)
			}
		})
	}
}

func TestStoresBundleContainsExactlySevenNarrowPorts(t *testing.T) {
	typ := reflect.TypeOf(arkadevaultv1.Stores{})
	want := []string{"Identity", "Allowance", "VtxoOperations", "RecoveryOperations", "Maps", "VaultBoard", "LightRenewal"}
	got := make([]string, typ.NumField())
	for i := range got {
		got[i] = typ.Field(i).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("store bundle fields = %v, want %v", got, want)
	}
}
