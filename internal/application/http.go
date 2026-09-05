package application

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/apperr"
)

const GatewaySecretHeader = "X-Vault-Gateway-Secret"

const maxJSONBody = 1 << 20
const maxRequestIDLength = 64
const EnrollmentTokenHeader = "X-Vault-Enrollment-Token"

const (
	serverWriteTimeout = 75 * time.Second
)

// NewServer applies bounded production HTTP timeouts.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       60 * time.Second,
	}
}

// ContentSecurityPolicy is the page policy for the decrypt-and-sign UI.
// Remote script and connect sources are forbidden so a CDN cannot see the
// PRF-unlocked PhoneBIP340 software key.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'"

// AuthorizerHandler is the protected software-box surface. It deliberately
// has no static file handler, demo controller, or raw signing route.
func AuthorizerHandler(svc *Service) http.Handler {
	return requireGatewaySecret(authorizerSurface(svc))
}

func authorizerSurface(svc *Service) http.Handler {
	origin := serviceOrigin(svc)
	mux := http.NewServeMux()
	attachCoreRoutes(mux, svc, origin)
	inner := withRequestLog(withCORS(mux, origin))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods, known := authorizerRouteMethods[r.URL.Path]
		if !known {
			http.NotFound(w, r)
			return
		}
		if _, allowed := methods[r.Method]; !allowed {
			w.Header().Set("Allow", strings.Join(sortedMethods(methods), ", "))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func safeVaultLogID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 80 {
		return ""
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return ""
		}
	}
	digest := sha256.Sum256([]byte(id))
	return hex.EncodeToString(digest[:8])
}

func withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := validRequestID(r.Header.Get("X-Request-Id"))
		if id == "" {
			id = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		w.Header().Set("X-Request-Id", id)
		rec := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		vault := safeVaultLogID(r.URL.Query().Get("vault"))
		if vault == "" {
			vault = "-"
		}
		code := strings.TrimSpace(rec.Header().Get("X-Vault-Error-Code"))
		if code == "" {
			code = "ok"
		}
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("request id=%s op=%s path=%s vault=%s status=%d code=%s", id, r.Method, r.URL.Path, vault, status, code)
	})
}

func validRequestID(raw string) string {
	id := strings.TrimSpace(raw)
	if id == "" || len(id) > maxRequestIDLength {
		return ""
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return ""
		}
	}
	return id
}

func requireGatewaySecret(next http.Handler) http.Handler {
	return requireGatewaySecretValue(strings.TrimSpace(os.Getenv("VAULT_GATEWAY_SECRET")), next)
}

func requireGatewaySecretValue(want string, next http.Handler) http.Handler {
	want = strings.TrimSpace(want)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}
		if want == "" {
			http.Error(w, "gateway authentication is not configured", http.StatusServiceUnavailable)
			return
		}
		got := r.Header.Get(GatewaySecretHeader)
		wantHash := sha256.Sum256([]byte(want))
		gotHash := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(wantHash[:], gotHash[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var authorizerRouteMethods = map[string]map[string]struct{}{
	"/v1/light/renew/prepare":        {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/renew/register":       {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/renew/final":          {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/renew/status":         {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/renew/release":        {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/enroll/start":         {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/enroll/propose":       {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/light/enroll/finish":        {http.MethodPost: {}, http.MethodOptions: {}},
	"/health":                        {http.MethodGet: {}},
	"/ready":                         {http.MethodGet: {}},
	"/v1/status":                     {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/enroll/session":             {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/invite":                     {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/enroll/start":               {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/enroll/propose":             {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/enroll/finish":              {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/initiate":                   {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/clawback":                   {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/challenge":          {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/binding":            {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/install":            {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/recover":            {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/map":                        {http.MethodGet: {}, http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/reserve":               {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/authorize":             {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/checkpoints/authorize": {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/finalize":              {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/operation":             {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/vtxo/abort":                 {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/board/prepare":         {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/board/register":        {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/board/release":         {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/vtxo/board/final":           {http.MethodPost: {}, http.MethodOptions: {}},
}

func sortedMethods(methods map[string]struct{}) []string {
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

func serviceOrigin(svc *Service) string {
	if svc == nil {
		return ""
	}
	return svc.runtimeConfig().ClientOrigin
}

func attachCoreRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		st := svc.Ready(r.Context())
		if !st.Ok {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		writeJSON(w, st, nil)
	})
	attachEnrollmentRoutes(mux, svc, origin)
	attachLightEnrollmentRoutes(mux, svc, origin)
	attachLightRenewalRoutes(mux, svc, origin)
	attachRecoveryRoutes(mux, svc, origin)
	attachVtxoRoutes(mux, svc, origin)
	attachVaultBoardRoutes(mux, svc, origin)
}

type mutationError struct {
	status int
	msg    string
}

func (e *mutationError) Error() string { return e.msg }

func decodeMutation(r *http.Request, dst any, expectedOrigin string) error {
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		return &mutationError{http.StatusUnsupportedMediaType, "content-type"}
	}
	if expectedOrigin == "" || r.Header.Get("Origin") != expectedOrigin {
		return &mutationError{http.StatusForbidden, "origin"}
	}
	if r.ContentLength > maxJSONBody {
		return &mutationError{http.StatusRequestEntityTooLarge, "request too large"}
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("multiple json values")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple json values")
	}
	return nil
}

func writeMutationError(w http.ResponseWriter, err error) {
	w.Header().Set("X-Vault-Error-Code", string(apperr.CodeRejected))
	var me *mutationError
	if errors.As(err, &me) {
		http.Error(w, me.msg, me.status)
		return
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		status := http.StatusBadRequest
		code := apperr.CodeRejected
		switch {
		case errors.Is(err, apperr.ErrEnrollmentClosed), errors.Is(err, apperr.ErrNotFound):
			status = http.StatusNotFound
			code = apperr.CodeNotFound
		case errors.Is(err, ErrVerificationBusy), errors.Is(err, apperr.ErrBusy):
			status = http.StatusTooManyRequests
			code = apperr.CodeBusy
			w.Header().Set("Retry-After", "1")
		case errors.Is(err, apperr.ErrVaultIDRequired):
			code = apperr.CodeVaultIDRequired
		case errors.Is(err, apperr.ErrNotEnrolled):
			code = apperr.CodeNotEnrolled
		default:
			if e := apperr.Of(err); e != nil && e.Code != apperr.CodeRejected {
				code = e.Code
			}
		}
		w.Header().Set("X-Vault-Error-Code", string(code))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": publicErrorMessage(code, err), "code": string(code)})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func publicErrorMessage(code apperr.Code, err error) string {
	if err == nil {
		return "request rejected"
	}
	// Only errors deliberately classified at the application boundary may
	// expose their message. Unknown dependency, parser, database, and transport
	// errors are never made public, regardless of their current wording.
	var classified *apperr.Error
	if errors.As(err, &classified) && classified.Code == code && classified.Msg != "" {
		return classified.Msg
	}
	switch code {
	case apperr.CodeNotFound:
		return "not found"
	case apperr.CodeBusy:
		return "busy"
	case apperr.CodeVaultIDRequired:
		return "vault id required"
	case apperr.CodeNotEnrolled:
		return "not enrolled"
	default:
		return "request rejected"
	}
}

func withCORS(next http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, "+EnrollmentTokenHeader)
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Never serve a generic emulator signing path.
		if strings.HasPrefix(r.URL.Path, "/v1/onchain-tx") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
