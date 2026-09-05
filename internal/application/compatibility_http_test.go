package application

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

type httpV1CompatibilityGolden struct {
	Routes map[string][]string `json:"routes"`
	Shapes map[string][]string `json:"shapes"`
}

// TestHTTPV1CompatibilityGolden freezes the complete route allowlist and the
// accepted/emitted JSON field names, order, primitive kinds, and omission
// behavior. It deliberately describes the existing Vault API, not a generic
// runtime or module-discovery protocol.
func TestHTTPV1CompatibilityGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/http-v1-compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var want httpV1CompatibilityGolden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	got := httpV1CompatibilityGolden{
		Routes: make(map[string][]string, len(authorizerRouteMethods)),
		Shapes: map[string][]string{},
	}
	for path, methods := range authorizerRouteMethods {
		got.Routes[path] = sortedMethods(methods)
	}

	types := map[string]reflect.Type{
		"LightRenewalPlan":             reflect.TypeOf(lightRenewalPlan{}),
		"LightRenewalPrepareRequest":   reflect.TypeOf(lightRenewalPrepareRequest{}),
		"LightRenewalPrepared":         reflect.TypeOf(lightRenewalPrepared{}),
		"LightRenewalRegisterRequest":  reflect.TypeOf(lightRenewalRegisterRequest{}),
		"LightRenewalFinalRequest":     reflect.TypeOf(lightRenewalFinalRequest{}),
		"LightRenewalFinalEvidence":    reflect.TypeOf(lightRenewalFinalEvidence{}),
		"LightRenewalOperationRequest": reflect.TypeOf(lightRenewalOperationRequest{}),
		"LightRenewalResponse":         reflect.TypeOf(lightRenewalResponse{}),
		"LightEnrollStartRequest":      reflect.TypeOf(LightEnrollStartRequest{}),
		"LightEnrollFinishRequest":     reflect.TypeOf(LightEnrollFinishRequest{}),
		"ProposedLightEnrollment":      reflect.TypeOf(ProposedLightEnrollment{}),
		"ReadyStatus":                  reflect.TypeOf(ReadyStatus{}),
		"PublicStatus":                 reflect.TypeOf(PublicStatus{}),
		"Status":                       reflect.TypeOf(Status{}),
		"InviteView":                   reflect.TypeOf(InviteView{}),
		"EnrollmentSession":            reflect.TypeOf(EnrollmentSession{}),
		"EnrollStartRequest":           reflect.TypeOf(EnrollStartRequest{}),
		"EnrollStartResponse":          reflect.TypeOf(EnrollStartResponse{}),
		"EnrollFinishRequest":          reflect.TypeOf(EnrollFinishRequest{}),
		"ProposedEnrollment":           reflect.TypeOf(ProposedEnrollment{}),
		"TransitionRequest":            reflect.TypeOf(TransitionRequest{}),
		"TransitionResponse":           reflect.TypeOf(TransitionResponse{}),
		"PasskeyChallengeRequest":      reflect.TypeOf(PasskeyChallengeRequest{}),
		"PasskeyChallengeResponse":     reflect.TypeOf(PasskeyChallengeResponse{}),
		"RecoveryBindingRouteRequest": reflect.TypeOf(struct {
			VaultID string `json:"vaultId"`
			RecoveryBindingRequest
		}{}),
		"RecoveryBindingResponse":           reflect.TypeOf(RecoveryBindingResponse{}),
		"InstallCredentialEnvelopeRequest":  reflect.TypeOf(InstallCredentialEnvelopeRequest{}),
		"RecoverCredentialEnvelopeRequest":  reflect.TypeOf(RecoverCredentialEnvelopeRequest{}),
		"RecoverCredentialEnvelopeResponse": reflect.TypeOf(RecoverCredentialEnvelopeResponse{}),
		"MapWriteRequest":                   reflect.TypeOf(MapWriteRequest{}),
		"VtxoReserveRequest":                reflect.TypeOf(VtxoReserveRequest{}),
		"VtxoInputView":                     reflect.TypeOf(VtxoInputView{}),
		"VtxoReserveResponse":               reflect.TypeOf(VtxoReserveResponse{}),
		"VtxoAuthorizeRequest":              reflect.TypeOf(VtxoAuthorizeRequest{}),
		"VtxoAuthorizeResponse":             reflect.TypeOf(VtxoAuthorizeResponse{}),
		"VtxoCheckpointAuthorizeRequest":    reflect.TypeOf(VtxoCheckpointAuthorizeRequest{}),
		"VtxoCheckpointAuthorizeResponse":   reflect.TypeOf(VtxoCheckpointAuthorizeResponse{}),
		"VtxoFinalizeRequest":               reflect.TypeOf(VtxoFinalizeRequest{}),
		"VtxoFinalizeResponse":              reflect.TypeOf(VtxoFinalizeResponse{}),
		"VtxoOperationView":                 reflect.TypeOf(VtxoOperationView{}),
		"VtxoAbortRequest":                  reflect.TypeOf(VtxoAbortRequest{}),
		"VtxoAbortResponse":                 reflect.TypeOf(VtxoAbortResponse{}),
		"SavingsPublicDescriptor":           reflect.TypeOf(savings.PublicDescriptor{}),
		"SavingsPublicKeys":                 reflect.TypeOf(savings.PublicKeys{}),
		"SavingsPublicPair":                 reflect.TypeOf(savings.PublicPair{}),
		"SavingsPublicTweaks":               reflect.TypeOf(savings.PublicTweaks{}),
		"SavingsPublicArkade":               reflect.TypeOf(savings.PublicArkade{}),
		"SavingsPublicCSV":                  reflect.TypeOf(savings.PublicCSV{}),
		"SavingsPublicPolicy":               reflect.TypeOf(savings.PublicPolicy{}),
		"SavingsPublicP2A":                  reflect.TypeOf(savings.PublicP2A{}),
		"SavingsTreeRef":                    reflect.TypeOf(savings.TreeRef{}),
		"SavingsPendingRef":                 reflect.TypeOf(savings.PendingRef{}),
		"SavingsQuarantineRef":              reflect.TypeOf(savings.QuarantineRef{}),
		"MutationSuccess": reflect.TypeOf(struct {
			OK bool `json:"ok"`
		}{}),
		"ErrorResponse": reflect.TypeOf(struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}{}),
	}
	for name, typ := range types {
		got.Shapes[name] = jsonWireShape(typ)
	}

	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("/v1 compatibility drifted; current surface:\n%s", gotJSON)
	}
}

func jsonWireShape(typ reflect.Type) []string {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if field.Anonymous && tag == "" {
			out = append(out, jsonWireShape(field.Type)...)
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		entry := name + ":" + jsonWireType(field.Type)
		for _, option := range parts[1:] {
			if option == "omitempty" {
				entry += ",omitempty"
			}
		}
		out = append(out, entry)
	}
	return out
}

func jsonWireType(typ reflect.Type) string {
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return "json"
	}
	if typ.Kind() == reflect.Pointer {
		return jsonWireType(typ.Elem()) + "|null"
	}
	switch typ.Kind() {
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.String:
		return "string"
	case reflect.Slice, reflect.Array:
		return "array<" + jsonWireType(typ.Elem()) + ">"
	case reflect.Map, reflect.Struct:
		return "object"
	case reflect.Interface:
		return "any"
	default:
		return typ.Kind().String()
	}
}
