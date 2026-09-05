package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/brg444/arkade-runtime/internal/authorizer"
	"github.com/brg444/arkade-runtime/internal/deployment"
	httpapi "github.com/brg444/arkade-runtime/internal/iface/http"
)

func main() {
	inviteOnlyDefault, err := parseInviteOnly(os.Getenv("VAULT_INVITE_ONLY"))
	if err != nil {
		log.Fatal(err)
	}
	lightEnabledDefault, err := parseLightEnabled(os.Getenv("VAULT_LIGHT_ENABLED"))
	if err != nil {
		log.Fatal(err)
	}
	var (
		lightEnabled        = flag.Bool("light-enabled", lightEnabledDefault, "allow new Light wallet enrollment after lifecycle qualification")
		inviteOnly          = flag.Bool("invite-only", inviteOnlyDefault, "require operator-issued invitations for new enrollment")
		addr                = flag.String("addr", envOr("VAULT_AUTHORIZER_ADDR", "127.0.0.1:8788"), "internal authorizer listen address")
		dbPath              = flag.String("db", os.Getenv("VAULT_DB_PATH"), "absolute authoritative SQLite path")
		sequence            = flag.String("policy-sequence", os.Getenv("VAULT_POLICY_SEQUENCE_PATH"), "absolute external policy-sequence path")
		keyFile             = flag.String("vault-cosigner-key-file", os.Getenv("VAULT_VAULT_COSIGNER_KEY_FILE"), "file containing the VaultCosigner private scalar")
		tokenFile           = flag.String("enrollment-token-file", os.Getenv("VAULT_ENROLLMENT_TOKEN_FILE"), "offline-provisioned one-time enrollment token file")
		origin              = flag.String("client-origin", os.Getenv("VAULT_CLIENT_ORIGIN"), "exact HTTPS signing-client origin")
		rpID                = flag.String("rp-id", os.Getenv("VAULT_RP_ID"), "exact WebAuthn relying-party ID")
		network             = flag.String("network", os.Getenv("VAULT_NETWORK"), "mutinynet or mainnet")
		storageIsolation    = flag.String("storage-isolation", os.Getenv("VAULT_STORAGE_ISOLATION"), "mainnet storage control attestation")
		edgeRateLimit       = flag.String("edge-rate-limit", os.Getenv("VAULT_EDGE_RATE_LIMIT"), "mainnet edge rate-limit attestation")
		mainnetAcknowledged = flag.String("mainnet-ack", os.Getenv("VAULT_MAINNET_ACK"), "mainnet fresh-state acknowledgement")
		cosignerKeyUnlink   = flag.String("cosigner-key-unlink", os.Getenv("VAULT_COSIGNER_KEY_UNLINK"), "after-load deletes the plaintext VaultCosigner key file once it is in process memory")
	)
	flag.Parse()

	cfg := authorizer.Config{
		Deployment:           deployment.Config{ClientOrigin: *origin, RPID: *rpID, Network: *network},
		DatabasePath:         *dbPath,
		PolicySequencePath:   *sequence,
		VaultCosignerKeyFile: *keyFile,
		EnrollmentTokenFile:  *tokenFile,
		OpenEnrollment:       !*inviteOnly,
		LightEnabled:         *lightEnabled,
		StorageIsolation:     *storageIsolation,
		EdgeRateLimit:        *edgeRateLimit,
		MainnetAcknowledged:  *mainnetAcknowledged,
		CosignerKeyUnlink:    *cosignerKeyUnlink,
		ArkadeCosignerOrigin: os.Getenv("VAULT_ARKADE_COSIGNER_ORIGIN"),
	}
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 40*time.Second)
	runtime, err := authorizer.Open(startupCtx, cfg)
	startupCancel()
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close()
	if err := clearGatewaySecretEnv(); err != nil {
		_ = runtime.Close()
		log.Fatalf("clear gateway secret environment: %v", err)
	}

	server := httpapi.NewServer(*addr, runtime.Handler())
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()
	log.Printf("%s software authorizer listening internally on %s; key and ledger share this process", *network, *addr)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	case <-signalCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("authorizer shutdown: %v", err)
		}
	}
}

func clearGatewaySecretEnv() error {
	return os.Unsetenv("VAULT_GATEWAY_SECRET")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// An absent setting retains invite-only admission; invalid values fail startup.
func parseInviteOnly(value string) (bool, error) {
	if value == "" {
		return true, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return true, fmt.Errorf("VAULT_INVITE_ONLY must be true or false")
	}
	return enabled, nil
}

func parseLightEnabled(value string) (bool, error) {
	switch value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("VAULT_LIGHT_ENABLED must be true or false")
	}
}
