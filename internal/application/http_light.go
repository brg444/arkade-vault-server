package application

import (
	"encoding/json"
	"errors"
	"net/http"
)

func attachLightEnrollmentRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/light/enroll/start", func(w http.ResponseWriter, r *http.Request) {
		var req LightEnrollStartRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.StartLightEnrollment(r.Header.Get(EnrollmentTokenHeader), req)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/light/enroll/propose", func(w http.ResponseWriter, r *http.Request) {
		var req LightEnrollFinishRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.ProposeLightEnrollment(r.Header.Get(EnrollmentTokenHeader), req)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/light/enroll/finish", func(w http.ResponseWriter, r *http.Request) {
		var req LightEnrollFinishRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.FinishLightEnrollment(r.Context(), r.Header.Get(EnrollmentTokenHeader), req)
		if errors.Is(err, errLightEnrollmentExpired) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "light_enrollment_expired"})
			return
		}
		writeJSON(w, response, err)
	})
}
