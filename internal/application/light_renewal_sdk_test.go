package application

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/vault/light"
)

// Generated using the pinned TypeScript SDK's Intent.create and SingleKey.sign,
// with public fixture owner secret 1. No funded output or private identity.
func TestLightRenewalPinnedSDKRegistration(t *testing.T) {
	raw, err := os.ReadFile("testdata/light-renewal-sdk-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Descriptor light.Descriptor `json:"descriptor"`
		Plan       lightRenewalPlan `json:"plan"`
		PSBT       string           `json:"psbt"`
		Message    string           `json:"message"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	tree, err := buildLightPolicyTree(f.Descriptor, mustDecodeRenewalHex(deployment.MutinynetOperatorSignerPubHex), "tark")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyLightRenewalRegistration(f.PSBT, f.Message, f.Plan, f.Descriptor, tree); err != nil {
		t.Fatal(err)
	}
}
