package application

import "net/http"

func attachLightRenewalRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/light/renew/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalPrepareRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.prepareLightRenewal(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/light/renew/register", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalRegisterRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.registerLightRenewal(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/light/renew/final", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalFinalRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.finalizeLightRenewal(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/light/renew/status", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalOperationRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.reconcileLightRenewal(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/light/renew/release", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalOperationRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.releaseLightRenewal(r.Context(), request)
		writeJSON(w, response, err)
	})
}
