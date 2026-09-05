package authorizer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/application"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type stubEmulatorSigner struct{}

func (stubEmulatorSigner) Sign(context.Context, *psbt.Packet) (*psbt.Packet, error) {
	return nil, errors.New("stub public signer must not be called")
}

type nilEmulatorSigner struct{}

func (*nilEmulatorSigner) Sign(context.Context, *psbt.Packet) (*psbt.Packet, error) {
	return nil, errors.New("nil public signer must not be called")
}

type testArkResolver struct {
	checkpoint []byte
	operator   []byte
}

func (r testArkResolver) SpendableVtxos(context.Context, []byte) ([]ports.ResolvedVtxo, error) {
	return nil, nil
}

func (r testArkResolver) IntentFeePolicy(context.Context) (ports.IntentFeePolicy, error) {
	return ports.IntentFeePolicy{}, nil
}

func (r testArkResolver) SubmittedVtxoState(context.Context, []byte, []ports.ResolvedVtxo, string, *uint32, uint64) (ports.SubmittedVtxoState, error) {
	return ports.SubmittedVtxoFinalized, nil
}

func (r testArkResolver) CheckpointTapscript() []byte { return append([]byte(nil), r.checkpoint...) }
func (r testArkResolver) OperatorSignerPub() []byte   { return append([]byte(nil), r.operator...) }
func (testArkResolver) Network() string               { return deployment.NetworkMutinynet }

func openWithTestArkadeDialer(t *testing.T, ctx context.Context, cfg Config, dialArkade arkadeSignerDialer) (*Runtime, error) {
	t.Helper()
	checkpoint, err := hex.DecodeString(deployment.MutinynetCheckpointTapscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := hex.DecodeString(deployment.MutinynetOperatorSignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	return openWithArkadeDialers(ctx, cfg, dialArkade, func(context.Context, string) (ports.ArkResolver, error) {
		return testArkResolver{checkpoint: checkpoint, operator: operator}, nil
	})
}

func TestLoadVaultCosignerKeyRejectsNormalizedAndOutOfRangeScalars(t *testing.T) {
	order := btcec.S256().N
	orderMinusOne := new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1))
	orderPlusOne := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1))
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "zero", raw: make([]byte, 32)},
		{name: "curve order", raw: order.FillBytes(make([]byte, 32))},
		{name: "curve order plus one", raw: orderPlusOne.FillBytes(make([]byte, 32))},
		{name: "known generator fixture", raw: append(make([]byte, 31), 1)},
		{name: "negated generator fixture", raw: orderMinusOne.FillBytes(make([]byte, 32))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault-cosigner-key")
			if err := os.WriteFile(path, []byte(hex.EncodeToString(test.raw)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadVaultCosignerKey(path); err == nil {
				t.Fatal("unsafe VaultCosigner scalar accepted")
			}
		})
	}

	valid, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault-cosigner-key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(valid.Serialize())), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadVaultCosignerKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PubKey().IsEqual(valid.PubKey()) {
		t.Fatal("loaded VaultCosigner key changed")
	}
	overlong := filepath.Join(t.TempDir(), "vault-cosigner-key")
	if err := os.WriteFile(overlong, []byte(hex.EncodeToString(valid.Serialize())+"  ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVaultCosignerKey(overlong); err == nil {
		t.Fatal("overlong file with a valid key prefix was accepted")
	}
}

func TestUnlinkCosignerKeyAfterLoadRemovesPlaintext(t *testing.T) {
	valid, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault-cosigner-key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(valid.Serialize())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unlinkCosignerKeyAfterLoad(path, "after-load"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("plaintext key remained: %v", err)
	}
}

func TestUnlinkCosignerKeyRejectsUnknownMode(t *testing.T) {
	if err := unlinkCosignerKeyAfterLoad("unused", "tmpfs"); err == nil || !strings.Contains(err.Error(), "after-load") {
		t.Fatalf("got %v", err)
	}
}

func TestCredentialIntegrityKeyUsesDomainSeparatedHKDF(t *testing.T) {
	first, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := deriveCredentialIntegrityKey(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(a)
	b, err := deriveCredentialIntegrityKey(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(b)
	c, err := deriveCredentialIntegrityKey(second)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(c)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatal("credential integrity derivation is not deterministic")
	}
	if bytes.Equal(a, first.Serialize()) {
		t.Fatal("provider scalar was used directly as the MAC key")
	}
	if bytes.Equal(a, c) {
		t.Fatal("distinct provider scalars derived the same MAC key")
	}
}

func TestProtectedRuntimeRevalidatesEmulatorDialResult(t *testing.T) {
	expectedRaw, err := hex.DecodeString(deployment.MutinynetArkadeCosignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := btcec.ParsePubKey(expectedRaw)
	if err != nil {
		t.Fatal(err)
	}
	valid := application.PublicEmulatorIdentity{
		Origin: deployment.MutinynetArkadeCosignerOrigin, Version: deployment.MutinynetArkadeCosignerVersion, BasePub: expected,
	}
	pins, err := deployment.IdentityFor(deployment.NetworkMutinynet)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateArkadeDialResult(stubEmulatorSigner{}, valid, expected, pins); err != nil {
		t.Fatal(err)
	}
	var typedNil *nilEmulatorSigner
	other, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		signer   application.Signer
		identity application.PublicEmulatorIdentity
	}{
		"missing signer": {identity: valid},
		"typed nil signer": {
			signer: typedNil, identity: valid,
		},
		"wrong origin": {
			signer: stubEmulatorSigner{}, identity: application.PublicEmulatorIdentity{
				Origin: "https://attacker.example", Version: valid.Version, BasePub: valid.BasePub,
			},
		},
		"wrong version": {
			signer: stubEmulatorSigner{}, identity: application.PublicEmulatorIdentity{
				Origin: valid.Origin, Version: "v0.0.0", BasePub: valid.BasePub,
			},
		},
		"wrong key": {
			signer: stubEmulatorSigner{}, identity: application.PublicEmulatorIdentity{
				Origin: valid.Origin, Version: valid.Version, BasePub: other.PubKey(),
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateArkadeDialResult(test.signer, test.identity, expected, pins); err == nil {
				t.Fatal("untrusted dial result accepted")
			}
		})
	}
}

func TestWipePrivateKeyZerosScalar(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wipePrivateKey(key)
	if !bytes.Equal(key.Serialize(), make([]byte, 32)) {
		t.Fatal("private scalar was not zeroed")
	}
	// Cleanup must be nil-safe for partial startup failures.
	wipePrivateKey(nil)
}

func TestDeploymentKeyRejectsFixtureEncodings(t *testing.T) {
	fixtureRaw, err := hex.DecodeString(fixture.RecoveryKeyPubHex)
	if err != nil {
		t.Fatal(err)
	}
	fixturePub, err := btcec.ParsePubKey(fixtureRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{
		fixture.RecoveryKeyPubHex,
		strings.ToUpper(fixture.RecoveryKeyPubHex),
		hex.EncodeToString(negatePub(t, fixturePub).SerializeCompressed()),
		hex.EncodeToString(fixturePub.SerializeUncompressed()),
	} {
		if _, err := parseDeploymentPub("RecoveryKey", encoded); err == nil {
			t.Fatalf("unsafe RecoveryKey accepted: %s", encoded)
		}
	}
}

func negatePub(t *testing.T, pub *btcec.PublicKey) *btcec.PublicKey {
	t.Helper()
	raw := append([]byte(nil), pub.SerializeCompressed()...)
	raw[0] ^= 1
	negated, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return negated
}

func TestRuntimeOwnsKeyAndLedgerAndPersistsInitialInvite(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	dir := t.TempDir()
	vaultCosignerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultCosignerPath := filepath.Join(dir, "vault-cosigner-key")
	if err := os.WriteFile(vaultCosignerPath, []byte(hex.EncodeToString(vaultCosignerKey.Serialize())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6d}, 32))
	tokenPath := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Deployment: deployment.Config{
			ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
			Network: deployment.NetworkMutinynet,
		},
		DatabasePath:         filepath.Join(dir, "vault.sqlite"),
		PolicySequencePath:   filepath.Join(dir, "policy-sequence"),
		VaultCosignerKeyFile: vaultCosignerPath,
	}
	emulatorDials := 0
	emulatorDial := func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, allowDeprecated bool) (application.Signer, application.PublicEmulatorIdentity, error) {
		emulatorDials++
		if origin != deployment.MutinynetArkadeCosignerOrigin ||
			expected == nil || hex.EncodeToString(expected.SerializeCompressed()) != deployment.MutinynetArkadeCosignerPubHex ||
			len(versions) != 1 || versions[0] != deployment.MutinynetArkadeCosignerVersion {
			t.Fatalf("public emulator pin = %q %x %v", origin, expected.SerializeCompressed(), versions)
		}
		if allowDeprecated {
			t.Fatalf("public emulator accepted a deprecated key on dial %d", emulatorDials)
		}
		return stubEmulatorSigner{}, application.PublicEmulatorIdentity{
			Origin: origin, Version: versions[0], BasePub: expected,
		}, nil
	}

	if _, err := openWithTestArkadeDialer(t, context.Background(), cfg, emulatorDial); err == nil || !strings.Contains(err.Error(), "enrollment token file") {
		t.Fatalf("fresh ledger without enrollment secret: %v", err)
	}
	if emulatorDials != 0 {
		t.Fatal("external service contacted before fresh-ledger bootstrap validation")
	}

	cfg.EnrollmentTokenFile = tokenPath
	runtime, err := openWithTestArkadeDialer(t, context.Background(), cfg, emulatorDial)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.IntegrityKeyCopy()) != 32 {
		t.Fatal("fresh runtime did not derive a credential integrity key")
	}
	if runtime.host == nil {
		t.Fatal("compiled runtime host missing")
	}
	if got := runtime.host.Profile().ID(); got != arkadevaultv1.ProfileID {
		t.Fatalf("compiled runtime profile = %q", got)
	}
	tokenHash, err := application.HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := runtime.ledger.GetInvite(tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if invite == nil || !invite.Usable(time.Now()) {
		t.Fatal("fresh runtime did not persist a usable enrollment invite")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.IntegrityKeyCopy()) != 0 {
		t.Fatal("runtime close did not release credential integrity key")
	}

	// An empty deployment still requires the token file on every restart. The
	// persisted row is authoritative, but startup never recovers the plaintext.
	cfg.EnrollmentTokenFile = filepath.Join(dir, "already-removed-token")
	if _, err := openWithTestArkadeDialer(t, context.Background(), cfg, emulatorDial); err == nil ||
		!strings.Contains(err.Error(), "enrollment token") {
		t.Fatalf("empty restart without token: %v", err)
	}
}

func TestProductionRegistryCompilesVaultAndLight(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := registry.ProfileIDs(), []string{arkadevaultv1.ProfileID, "vaulted-light-v1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled production profiles = %v, want %v", got, want)
	}
}

func TestProvisionEnrollmentInviteSupportsOfflineTokenRotation(t *testing.T) {
	dir := t.TempDir()
	ledger, err := policy.OpenLedger(filepath.Join(dir, "vault.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	now := time.Date(2026, time.August, 22, 10, 0, 0, 0, time.UTC)
	firstToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6a}, 32))
	firstPath := filepath.Join(dir, "invite-one")
	if err := os.WriteFile(firstPath, []byte(firstToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{EnrollmentTokenFile: firstPath, EnrollmentWindow: 15 * time.Minute}
	if err := provisionEnrollmentInvite(ledger, cfg, false, now); err != nil {
		t.Fatal(err)
	}
	firstHash, err := application.HashEnrollmentToken(firstToken)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ledger.GetInvite(firstHash)
	if err != nil || first == nil {
		t.Fatalf("first invite: %+v %v", first, err)
	}

	// Re-presenting the same operator file must preserve the original expiry,
	// even if startup happens much later.
	if err := provisionEnrollmentInvite(ledger, cfg, true, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	replayed, err := ledger.GetInvite(firstHash)
	if err != nil {
		t.Fatal(err)
	}
	if replayed == nil || replayed.ExpiresAt != first.ExpiresAt || replayed.CreatedAt != first.CreatedAt {
		t.Fatalf("same-token replay changed invitation: first=%+v replay=%+v", first, replayed)
	}

	secondToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))
	secondPath := filepath.Join(dir, "invite-two")
	if err := os.WriteFile(secondPath, []byte(secondToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.EnrollmentTokenFile = secondPath
	if err := provisionEnrollmentInvite(ledger, cfg, true, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	secondHash, err := application.HashEnrollmentToken(secondToken)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ledger.GetInvite(secondHash)
	if err != nil || second == nil || !second.Usable(now.Add(time.Hour)) {
		t.Fatalf("rotated invite: %+v %v", second, err)
	}

	if err := provisionEnrollmentInvite(ledger, Config{}, true, now); err != nil {
		t.Fatalf("existing deployment without a provisioning file: %v", err)
	}
	if err := provisionEnrollmentInvite(ledger, Config{}, false, now); err == nil ||
		!strings.Contains(err.Error(), "fresh authorizer") {
		t.Fatalf("fresh deployment without a provisioning file: %v", err)
	}
}

func TestRuntimeRequiresGatewaySecret(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "")
	dir := t.TempDir()
	vaultCosignerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultCosignerPath := filepath.Join(dir, "vault-cosigner-key")
	if err := os.WriteFile(vaultCosignerPath, []byte(hex.EncodeToString(vaultCosignerKey.Serialize())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Deployment: deployment.Config{
			ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
			Network: deployment.NetworkMutinynet,
		},
		DatabasePath:         filepath.Join(dir, "vault.sqlite"),
		PolicySequencePath:   filepath.Join(dir, "policy-sequence"),
		VaultCosignerKeyFile: vaultCosignerPath,
		EnrollmentTokenFile:  filepath.Join(dir, "enrollment-token"),
	}
	_, err = openWithTestArkadeDialer(t, context.Background(), cfg,
		func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, _ bool) (application.Signer, application.PublicEmulatorIdentity, error) {
			return stubEmulatorSigner{}, application.PublicEmulatorIdentity{Origin: origin, Version: versions[0], BasePub: expected}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "VAULT_GATEWAY_SECRET") {
		t.Fatalf("missing gateway secret: %v", err)
	}
}
