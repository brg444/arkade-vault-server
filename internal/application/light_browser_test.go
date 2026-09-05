package application

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Opt-in local browser harness. It uses an ephemeral ledger and keys and binds
// loopback only; it is absent from production binaries and normal test runs.
func TestLightBrowserHarness(t *testing.T) {
	addr := os.Getenv("VAULT_LIGHT_BROWSER_ADDR")
	if addr == "" {
		t.Skip("local browser harness not requested")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("browser harness requires loopback")
	}
	origin := os.Getenv("VAULT_LIGHT_BROWSER_ORIGIN")
	if !strings.HasPrefix(origin, "https://localhost:") {
		t.Fatal("browser harness requires HTTPS localhost origin")
	}
	directory := t.TempDir()
	if supplied := os.Getenv("VAULT_LIGHT_BROWSER_DIRECTORY"); supplied != "" {
		if !filepath.IsAbs(supplied) || os.Getenv("VAULT_LIGHT_BROWSER_LIVE") != "mutinynet" {
			t.Fatal("persistent harness requires absolute private Mutinynet directory")
		}
		directory = supplied
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := policy.OpenLedger(filepath.Join(directory, "light-browser.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	svc := enrollService(t, ledger)
	if os.Getenv("VAULT_LIGHT_BROWSER_DIRECTORY") != "" {
		path := filepath.Join(directory, "runtime-master.key")
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			raw = key.Serialize()
			key.Key.Zero()
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(raw); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Sync(); err != nil {
				file.Close()
				t.Fatal(err)
			}
			file.Close()
		} else if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 32 {
			t.Fatal("invalid saved test master")
		}
		master, _ := btcec.PrivKeyFromBytes(raw)
		zeroServiceBytes(raw)
		emulator, _ := btcec.NewPrivateKey()
		svc.keys.Wipe()
		svc.keys = testKeys(t, master, LocalSigner{Priv: emulator})
		svc.VaultCosignerPub = master.PubKey()
		sequence, err := policy.OpenMonotonic(filepath.Join(directory, "policy-sequence"), testCredentialIntegrityKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := ledger.AttachMonotonic(sequence); err != nil {
			t.Fatal(err)
		}
	}
	svc.LightEnabled = os.Getenv("VAULT_LIGHT_BROWSER_DISABLE_ENROLLMENT") != "1"
	svc.OpenEnrollment = true
	svc.Deployment.ClientOrigin = origin
	svc.Deployment.RPID = "localhost"
	svc.ArkResolver = stubArkResolver{signer: mustDecode(t, "02301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a")}
	if mode := os.Getenv("VAULT_LIGHT_BROWSER_LIVE"); mode != "" {
		if mode != "mutinynet" {
			t.Fatal("funded browser harness supports only Mutinynet")
		}
		svc.ArkResolver, err = DialArkResolver(context.Background(), "mutinynet")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	handler := http.NewServeMux()
	handler.Handle("/", testAuthorizer(svc))

	server := NewServer(addr, handler)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	t.Log("Light browser harness ready")
	select {
	case err := <-stopped:
		if err != nil && err != http.ErrServerClosed {
			t.Fatal(err)
		}
	case <-time.After(45 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
}
