// Package vaultedlightv1 declares the passkey-owned Spending profile. Common
// admission, status and transaction coordination remain on the existing API;
// persisted identity selects the program before a signing capability is created.
package vaultedlightv1

import (
	"net/http"

	arkaderuntime "github.com/brg444/arkade-runtime/internal/runtime"
	"github.com/brg444/arkade-runtime/internal/vault/light"
)

const ProfileID = light.Profile

func Definition() arkaderuntime.ProfileDefinition {
	var routes []arkaderuntime.Route
	for _, path := range []string{"/v1/light/enroll/start", "/v1/light/enroll/propose", "/v1/light/enroll/finish", "/v1/light/renew/prepare", "/v1/light/renew/register", "/v1/light/renew/final", "/v1/light/renew/status", "/v1/light/renew/release"} {
		routes = append(routes, arkaderuntime.Route{Method: http.MethodPost, Path: path}, arkaderuntime.Route{Method: http.MethodOptions, Path: path})
	}
	return arkaderuntime.ProfileDefinition{ID: ProfileID, Modules: []arkaderuntime.ModuleDefinition{{
		ID: ProfileID, Programs: []string{light.Program}, Policies: []string{light.PolicySchema},
		Stores:    []string{"light-identity-store", "light-allowance-store", "light-vtxo-operation-store", "light-renewal-store"},
		KeyScopes: []string{"light-vtxo-transaction-authorization", "light-vtxo-checkpoint-authorization", "light-renewal-authorization"},
	}}, Routes: routes}
}
