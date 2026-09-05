package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	arkadevaultv1 "github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// Service is the trusted VaultCosigner authorization boundary.
type Service struct {
	Stores         arkadevaultv1.Stores
	Deployment     deployment.Config
	LightEnabled   bool // admits new Light wallets only; existing wallets remain usable
	OpenEnrollment bool // admission only; existing sessions retain their expiry
	// CredentialIntegrityKey authenticates the immutable descriptor stored in
	// the authoritative ledger. Production derives it from the VaultCosigner
	// scalar with a domain-separated KDF.
	CredentialIntegrityKey []byte
	EnrollmentNow          func() time.Time
	VaultCosignerPub       *btcec.PublicKey
	ArkadeCosignerPub      *btcec.PublicKey
	ArkadeCosignerOrigin   string
	ArkadeCosignerVersion  string
	keys                   KeyCapabilities
	SignTimeout            time.Duration
	// MaxConcurrentVerifications bounds the CPU-heavy WebAuthn, P-256 and
	// Schnorr verification stage. Zero uses the conservative default.
	MaxConcurrentVerifications int
	// MaxConcurrentFeeSelections bounds authenticated but potentially
	// adversarial Operator CEL evaluation. Zero uses the conservative default.
	MaxConcurrentFeeSelections int
	ArkResolver                ports.ArkResolver
	contractPackJSON           []byte
	vaultPolicyHasExit         *bool
	mu                         sync.Mutex
	published                  atomic.Pointer[publishedIndex]
	verificationOnce           sync.Once
	verificationSlots          chan struct{}
	feeSelectionOnce           sync.Once
	feeSelectionSlots          chan struct{}
	transitionRateMu           sync.Mutex
	transitionRateHits         map[string][]time.Time
	sessionMu                  sync.Mutex
	sessionChallenges          map[string]passkeyChallenge
	SessionNow                 func() time.Time
	afterLoadPending           func()
	vaultBoardRuntime          *vaultBoardRuntime
	lightRenewalOperatorDial   func(context.Context) (lightRenewalOperator, error)
	resolverReadyMu            sync.Mutex
	resolverReadyAt            time.Time
	resolverReadyErr           error
}

// Deps is the constructor input. Private keys stay behind scoped capabilities.
type Deps struct {
	Stores                arkadevaultv1.Stores
	Deployment            deployment.Config
	OpenEnrollment        bool
	LightEnabled          bool
	IntegrityKey          []byte
	Keys                  KeyCapabilities
	VaultCosignerPub      *btcec.PublicKey
	ArkadeCosignerPub     *btcec.PublicKey
	ArkadeCosignerOrigin  string
	ArkadeCosignerVersion string
	ArkResolver           ports.ArkResolver
}

// New builds the application service without receiving raw key material or a
// generic signer.
func New(d Deps) *Service {
	s := &Service{
		Stores:                 d.Stores,
		Deployment:             d.Deployment,
		OpenEnrollment:         d.OpenEnrollment,
		LightEnabled:           d.LightEnabled,
		CredentialIntegrityKey: d.IntegrityKey,
		VaultCosignerPub:       d.VaultCosignerPub,
		ArkadeCosignerPub:      d.ArkadeCosignerPub,
		ArkadeCosignerOrigin:   d.ArkadeCosignerOrigin,
		ArkadeCosignerVersion:  d.ArkadeCosignerVersion,
		keys:                   d.Keys,
		ArkResolver:            d.ArkResolver,
	}
	if raw, err := liveContractPackJSONFor(d.Deployment.Network); err == nil {
		s.contractPackJSON = raw
	}
	return s
}

// ClientOrigin is the pinned signing origin.
func (s *Service) ClientOrigin() string {
	if s == nil {
		return ""
	}
	return s.runtimeConfig().ClientOrigin
}

// IntegrityKeyCopy returns a copy of the MAC key for shutdown tests.
func (s *Service) IntegrityKeyCopy() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.CredentialIntegrityKey...)
}

// WipeSecrets zeros the IKM and integrity key. Called on process shutdown.
func (s *Service) WipeSecrets() {
	if s == nil {
		return
	}
	zeroServiceBytes(s.CredentialIntegrityKey)
	s.CredentialIntegrityKey = nil
	s.keys.Wipe()
}

const defaultConcurrentVerifications = 4
const defaultConcurrentFeeSelections = 2

var ErrVerificationBusy = errors.New("crypto verification capacity exhausted")

// enrolledSnapshot is one immutable published enrollment for a single vault.
type enrolledSnapshot struct {
	Light               *light.Descriptor
	VaultID             string
	CredentialID        []byte
	PhoneBIP340         *btcec.PublicKey
	ExternalOwnerWallet *btcec.PublicKey
	RecoveryKey         *btcec.PublicKey
	VaultCosignerBase   *btcec.PublicKey
	ArkadeCosignerBase  *btcec.PublicKey
	Savings             *savingsSnapshot
	Board               *vaultBoardSnapshot
}

type vaultBoardSnapshot struct {
	BoardingPub *btcec.PublicKey
	CosignerPub *btcec.PublicKey
	OperatorPub *btcec.PublicKey
	PkScript    []byte
	Address     string
}

type savingsSnapshot struct {
	Address             string
	PkScript            []byte
	ExternalOwnerWallet *btcec.PublicKey
	RecoveryKey         *btcec.PublicKey
	VaultCosignerBase   *btcec.PublicKey
	ArkadeCosignerBase  *btcec.PublicKey
}

// publishedIndex is a swapped immutable map of vaults and credential IDs.
type publishedIndex struct {
	byVault map[string]*enrolledSnapshot
	byCred  map[string]string
}

// RegisterRequest is the enrollment payload. All byte fields are hex.
// A second call is accepted only when it matches the already-enrolled
// credential ID, WebAuthn P-256, PhoneDirectP256, and PhoneBIP340,
// and this process's pinned deployment keys/policy still rebuild the stored
// descriptor.
type RegisterRequest struct {
	CredentialID           string `json:"credentialId"`
	WebAuthnP256           string `json:"webauthnP256"`
	PhoneDirectP256        string `json:"phoneDirectP256"`
	PhoneBIP340Pub         string `json:"phoneBip340Pub"`
	VtxoBoardingProgram    string `json:"vtxoBoardingProgram"`
	VaultBoardingBIP340Pub string `json:"vaultBoardingBip340Pub"`
	// These BIP340 x-only keys are chosen exactly once for a fresh portable
	// deployment. A configured deployment may precommit the same identities.
	ExternalOwnerWalletXOnly string `json:"externalOwnerWalletXOnly,omitempty"`
	RecoveryXOnly            string `json:"recoveryXOnly,omitempty"`
	RecoveryKeyXOnly         string `json:"recoveryKeyXOnly,omitempty"`
	// Optional tenant identity. Extra fields must not 400 under
	// DisallowUnknownFields; new enrollments should send them.
	VaultID              string                 `json:"vaultId,omitempty"`
	DescriptorHash       string                 `json:"descriptorHash,omitempty"`
	ProtectionTier       string                 `json:"protectionTier"`
	SpendingPolicy       program.SpendingPolicy `json:"spendingPolicy"`
	SpendingPolicyDigest string                 `json:"spendingPolicyDigest"`
}

type parsedRegisterRequest struct {
	id, webauthnP256, phoneDirectP256 []byte
	phone                             *btcec.PublicKey
	externalOwner                     *btcec.PublicKey
	recovery                          *btcec.PublicKey
	boardPub                          *btcec.PublicKey
	boardingProgram                   string
	vaultID                           string
	protectionTier                    string
	spendingPolicy                    program.SpendingPolicy
}

func (s *Service) requireLedgerIntegrity() error {
	if s == nil || s.Stores.Identity == nil {
		return fmt.Errorf("ledger required")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return s.Stores.Identity.RequireIntegrityKey(key)
}

// CreateTenantVault atomically persists a new HKDF-derived vault and consumes
// the invite. HTTP enrollment remains gated; this is the PR1 service primitive.
func (s *Service) CreateTenantVault(vaultID string, tokenHash []byte, req RegisterRequest) error {
	return s.createTenantVault(vaultID, tokenHash, req, nil)
}

func (s *Service) createTenantVault(vaultID string, tokenHash []byte, req RegisterRequest, pending *policy.PendingEnrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}
	if vaultID == "" {
		return fmt.Errorf("tenant vault id required")
	}
	if req.ExternalOwnerWalletXOnly == "" {
		return fmt.Errorf("tenant owner pub required")
	}
	childPub, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return err
	}
	parsed, err = s.applyVaultBoardEnrollmentRequest(parsed, req)
	if err != nil {
		return err
	}
	proposed, err := s.previewVaultBoardEnrollmentDescriptor(vaultID, req)
	if err != nil {
		return err
	}
	if req.DescriptorHash == "" || req.DescriptorHash != proposed.DescriptorHash {
		return fmt.Errorf("enrollment descriptor hash does not match the proposed vault")
	}
	descriptor, sv, err := s.mintSavingsCredential(vaultID, parsed, childPub)
	if err != nil {
		return err
	}
	rec := policy.VaultRecord{}
	rec = vaultRecordFromDescriptor(descriptor)
	if err := sealVaultRecordForService(&rec, s); err != nil {
		return err
	}
	vcred := policy.VaultCredential{
		CredentialID: append([]byte(nil), descriptor.ID...),
		VaultID:      vaultID,
		WebAuthnP256: append([]byte(nil), descriptor.WebAuthnP256...),
		UserHandle:   []byte(vaultID),
		Resident:     true,
	}
	if err := sealVaultCredentialForService(&vcred, s); err != nil {
		return err
	}
	boardRec, boardSnap, err := s.mintVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return err
	}
	if boardRec == nil || boardSnap == nil || s.Stores.VaultBoard == nil {
		return fmt.Errorf("vault-board-v1 release store is not active")
	}
	create := policy.CreateVaultInput{Record: rec, Credential: vcred, TokenHash: tokenHash, Pending: pending}
	if err := s.Stores.VaultBoard.CreateVaultWithBoard(create, *boardRec); err != nil {
		return err
	}
	stored, err := s.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	if err != nil || stored == nil || !bytes.Equal(stored.IntegrityMAC, boardRec.IntegrityMAC) {
		return fmt.Errorf("vault-board-v1 enrollment readback failed")
	}
	s.publishEnrollmentAt(vaultID, descriptor.ID, parsed.phone, sv, boardSnap)
	return nil
}

func vaultRecordFromDescriptor(c policy.Credential) policy.VaultRecord {
	return policy.VaultRecordFromCredential(c)
}

func sealVaultRecordForService(rec *policy.VaultRecord, s *Service) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return policy.SealVaultRecord(rec, key)
}

func sealVaultCredentialForService(cred *policy.VaultCredential, s *Service) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return policy.SealVaultCredential(cred, key)
}

func (s *Service) currentEnrollmentTime() time.Time {
	if s.EnrollmentNow != nil {
		return s.EnrollmentNow()
	}
	return time.Now()
}

// HashEnrollmentToken validates the one supported token encoding and returns
// the SHA-256 digest held by the authorizer process.
func HashEnrollmentToken(token string) ([]byte, error) {
	raw, err := decodeEnrollmentToken(token)
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(raw)
	digest := sha256.Sum256(raw)
	return append([]byte(nil), digest[:]...), nil
}

func decodeEnrollmentToken(token string) ([]byte, error) {
	if len(token) != 43 || strings.TrimSpace(token) != token {
		return nil, fmt.Errorf("enrollment token must be 32-byte base64url without padding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		zeroServiceBytes(raw)
		return nil, fmt.Errorf("enrollment token must be 32-byte base64url without padding")
	}
	return raw, nil
}

func (s *Service) parseRegisterRequestIndependent(req RegisterRequest) (parsedRegisterRequest, error) {
	var parsed parsedRegisterRequest
	var err error
	parsed.id, err = decodeHex(req.CredentialID)
	if err != nil {
		return parsed, fmt.Errorf("credentialId: %w", err)
	}
	if len(parsed.id) > 1024 {
		return parsed, fmt.Errorf("credentialId too large")
	}
	parsed.webauthnP256, err = decodeHex(req.WebAuthnP256)
	if err != nil {
		return parsed, fmt.Errorf("webauthnP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(parsed.webauthnP256); err != nil {
		return parsed, fmt.Errorf("webauthnP256: %w", err)
	}
	parsed.phoneDirectP256, err = decodeHex(req.PhoneDirectP256)
	if err != nil {
		return parsed, fmt.Errorf("phoneDirectP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(parsed.phoneDirectP256); err != nil {
		return parsed, fmt.Errorf("phoneDirectP256: %w", err)
	}
	if bytes.Equal(parsed.webauthnP256, parsed.phoneDirectP256) {
		return parsed, fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	parsed.phone, err = parsePhoneBIP340Pub(req.PhoneBIP340Pub)
	if err != nil {
		return parsed, err
	}
	parsed.externalOwner, err = s.parseOnboardingKey("externalOwnerWalletXOnly", req.ExternalOwnerWalletXOnly)
	if err != nil {
		return parsed, err
	}
	if rec := recoveryField(req); rec != "" {
		parsed.recovery, err = s.parseOnboardingKey("recoveryXOnly", rec)
		if err != nil {
			return parsed, err
		}
	}
	if err := program.ValidateProtectionTierRecovery(req.ProtectionTier, parsed.recovery != nil); err != nil {
		return parsed, err
	}
	parsed.protectionTier = req.ProtectionTier
	parsed.vaultID = req.VaultID
	parsed.boardingProgram = program.VaultBoardV1
	if _, err := requireSpendingPolicyDigest(s.runtimeConfig().Network, req.SpendingPolicy, req.SpendingPolicyDigest); err != nil {
		return parsed, err
	}
	parsed.spendingPolicy = req.SpendingPolicy
	return parsed, nil
}

// LoadVaults rebuilds trees from the persisted enrollment descriptor.
// Runtime config must be compatible; trees are never derived from a
// rotated GetInfo key or a changed CSV/network/template.
func (s *Service) LoadVaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireLedgerIntegrity(); err != nil {
		return err
	}
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}
	ids, err := s.Stores.Identity.ListVaultIDs()
	if err != nil {
		return err
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	for _, id := range ids {
		rec, vcred, err := s.Stores.Identity.LoadVerifiedVault(id, key)
		if err != nil {
			return err
		}
		if rec == nil || vcred == nil {
			return fmt.Errorf("vault %s missing credential", id)
		}
		cred := rec.ToCredential(*vcred)
		if err := s.publishStoredEnrollment(&cred); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) publishStoredEnrollment(cred *policy.Credential) error {
	if cred.TemplateVersion == light.Profile {
		return s.publishStoredLightEnrollment(cred)
	}
	phone, _, _, _, _, sv, err := s.rebuildFromCredential(cred)
	if err != nil {
		return err
	}
	if s.Stores.VaultBoard == nil {
		return fmt.Errorf("vault-board-v1 store required")
	}
	rec, loadErr := s.Stores.VaultBoard.GetVaultBoardEnrollment(cred.VaultID)
	if loadErr != nil || rec == nil {
		return fmt.Errorf("vault-board-v1 enrollment required")
	}
	board, loadErr := boardSnapshotFromRecord(rec)
	if loadErr != nil || board == nil {
		return fmt.Errorf("vault-board-v1 enrollment invalid")
	}
	rebuilt, rebuildErr := s.buildVtxoBoardTree(cred.VaultID, enrolledSnapshot{PhoneBIP340: phone}, board.BoardingPub)
	if rebuildErr != nil {
		return rebuildErr
	}
	if rebuilt.OnchainAddress != board.Address || !bytes.Equal(rebuilt.PkScript, board.PkScript) ||
		!rebuilt.CosignerPub.IsEqual(board.CosignerPub) || !rebuilt.OperatorPub.IsEqual(board.OperatorPub) {
		return fmt.Errorf("rebuilt vault-board-v1 does not match stored enrollment")
	}
	s.publishEnrollmentAt(cred.VaultID, cred.ID, phone, sv, board)
	return nil
}

func (s *Service) rebuildFromCredential(cred *policy.Credential) (
	phone, externalOwner, recovery, vaultBase, arkadeBase *btcec.PublicKey,
	sv *savingsSnapshot, err error,
) {
	if err = s.requireCompatible(cred); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	if cred.TemplateVersion != savings.Template {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("unsupported vault template %q", cred.TemplateVersion)
	}
	return s.rebuildSavings(cred)
}

func (s *Service) requireCompatible(cred *policy.Credential) error {
	cfg := s.runtimeConfig()
	if !knownTemplate(cred.TemplateVersion) {
		return fmt.Errorf("stored template %q incompatible with runtime", cred.TemplateVersion)
	}
	if cred.PolicyVersion != program.PolicyVersion {
		return fmt.Errorf("stored policy %q incompatible with runtime %q", cred.PolicyVersion, program.PolicyVersion)
	}
	if err := program.ValidateProtectionTierRecovery(cred.ProtectionTier, len(cred.RecoveryKey) > 0); err != nil {
		return fmt.Errorf("stored protection tier: %w", err)
	}
	if cred.Network != cfg.Network {
		return fmt.Errorf("stored network %q incompatible with runtime %q", cred.Network, cfg.Network)
	}
	if cred.VaultID == "" {
		return fmt.Errorf("stored vault id required")
	}
	if cred.Origin != cfg.ClientOrigin {
		return fmt.Errorf("stored origin %q incompatible with runtime %q", cred.Origin, cfg.ClientOrigin)
	}
	if cred.RPID != cfg.RPID {
		return fmt.Errorf("stored rp id %q incompatible with runtime %q", cred.RPID, cfg.RPID)
	}
	if cred.RecipientDustSats != program.DustSats {
		return fmt.Errorf("stored economic policy incompatible with runtime")
	}
	if err := program.ValidateSpendingPolicyFor(cfg.Network, spendingPolicyFromCredential(cred)); err != nil {
		return fmt.Errorf("stored economic policy: %w", err)
	}
	wantOrigin, wantVersion := s.arkadeIdentity()
	if cred.ArkadeCosignerOrigin != wantOrigin {
		return fmt.Errorf("stored signing identity requires enrollment migration")
	}
	if cred.ArkadeCosignerVersion != wantVersion {
		return fmt.Errorf("stored ArkadeCosigner version %q incompatible with runtime %q", cred.ArkadeCosignerVersion, wantVersion)
	}
	if cred.ArkadeCosignerVersion == "" || s.ArkadeCosignerVersion == "" {
		return fmt.Errorf("stored and runtime ArkadeCosigner versions are required")
	}
	if err := requireSignerCompatible("ArkadeCosigner", s.ArkadeCosignerPub, cred.ArkadeCosignerBase); err != nil {
		return err
	}
	return nil
}

func requireSignerCompatible(name string, current *btcec.PublicKey, stored []byte) error {
	if current != nil && sameCompressed(current, stored) {
		return nil
	}
	return fmt.Errorf("enrolled %s key does not match the configured runtime signer", name)
}

func sameCompressed(pub *btcec.PublicKey, raw []byte) bool {
	return pub != nil && bytes.Equal(pub.SerializeCompressed(), raw)
}

func parsePhoneBIP340Pub(hexPub string) (*btcec.PublicKey, error) {
	if hexPub == "" {
		return nil, fmt.Errorf("phoneBip340Pub required")
	}
	raw, err := decodeHex(hexPub)
	if err != nil {
		return nil, fmt.Errorf("phoneBip340Pub: %w", err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("phoneBip340Pub: %w", err)
	}
	return pub, nil
}

func (s *Service) parseOnboardingKey(name, encoded string) (*btcec.PublicKey, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%s required", name)
	}
	if len(encoded) != 64 || encoded != strings.ToLower(encoded) {
		return nil, fmt.Errorf("%s must be canonical 32-byte BIP340 x-only lowercase hex", name)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s must be canonical 32-byte BIP340 x-only lowercase hex", name)
	}
	pub, err := schnorr.ParsePubKey(raw)
	if err != nil || !bytes.Equal(schnorr.SerializePubKey(pub), raw) {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	if knownFixtureXOnly(raw) {
		return nil, fmt.Errorf("public test fixture is forbidden for %s", name)
	}
	return pub, nil
}

func knownFixtureXOnly(xonly []byte) bool {
	for _, encoded := range []string{program.UnsafeGenerator2G, program.UnsafeGeneratorG} {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			continue
		}
		pub, err := btcec.ParsePubKey(raw)
		if err == nil && bytes.Equal(schnorr.SerializePubKey(pub), xonly) {
			return true
		}
	}
	return false
}

func (s *Service) publishEnrollmentAt(vaultID string, credID []byte, phone *btcec.PublicKey, sv *savingsSnapshot, board ...*vaultBoardSnapshot) {
	snap := &enrolledSnapshot{
		VaultID:      vaultID,
		CredentialID: append([]byte(nil), credID...),
		PhoneBIP340:  phone, Savings: sv,
	}
	if len(board) == 1 {
		snap.Board = board[0]
	}
	if sv != nil {
		snap.ExternalOwnerWallet = sv.ExternalOwnerWallet
		snap.RecoveryKey = sv.RecoveryKey
		snap.VaultCosignerBase = sv.VaultCosignerBase
		snap.ArkadeCosignerBase = sv.ArkadeCosignerBase
	}
	s.publishSnapshot(snap)
}

func (s *Service) publishSnapshot(snap *enrolledSnapshot) {
	vaultID, credID := snap.VaultID, snap.CredentialID
	prev := s.published.Load()
	next := &publishedIndex{
		byVault: make(map[string]*enrolledSnapshot, 4),
		byCred:  make(map[string]string, 4),
	}
	if prev != nil {
		for k, v := range prev.byVault {
			next.byVault[k] = v
		}
		for k, v := range prev.byCred {
			next.byCred[k] = v
		}
	}
	next.byVault[vaultID] = snap
	if len(credID) > 0 {
		next.byCred[hex.EncodeToString(credID)] = vaultID
	}
	s.published.Store(next)
}

func (s *Service) snapshot(vaultID string) enrolledSnapshot {
	idx := s.published.Load()
	if idx == nil {
		return enrolledSnapshot{}
	}
	if snap := idx.byVault[vaultID]; snap != nil {
		return *snap
	}
	return enrolledSnapshot{}
}

func periodAllowanceSats(rec *policy.VaultRecord, cred *policy.Credential) int64 {
	if rec != nil && rec.PeriodAllowanceSats > 0 {
		return rec.PeriodAllowanceSats
	}
	if cred != nil && cred.PeriodAllowanceSats > 0 {
		return cred.PeriodAllowanceSats
	}
	return program.PeriodAllowanceSats
}

func spendingPolicyFromCredential(cred *policy.Credential) program.SpendingPolicy {
	if cred == nil {
		return program.SpendingPolicy{}
	}
	return program.SpendingPolicyFromValues(
		cred.TxRecipientCapSats, cred.PeriodAllowanceSats, cred.AbsoluteFeeCapSats, cred.FeerateCapSatPerV,
	)
}

func spendingPolicyFromRecord(rec *policy.VaultRecord) program.SpendingPolicy {
	if rec == nil {
		return program.SpendingPolicy{}
	}
	return program.SpendingPolicyFromValues(
		rec.TxRecipientCapSats, rec.PeriodAllowanceSats, rec.AbsoluteFeeCapSats, rec.FeerateCapSatPerV,
	)
}

func (s *Service) routeVaultID(vaultID string) (string, error) {
	id := strings.TrimSpace(vaultID)
	if id == "" {
		return "", apperr.ErrVaultIDRequired
	}
	return id, nil
}

func (s *Service) resolveSpendVaultRecord(vaultID string) (string, enrolledSnapshot, *policy.VaultRecord, error) {
	id, err := s.routeVaultID(vaultID)
	if err != nil {
		return "", enrolledSnapshot{}, nil, err
	}
	snap := s.snapshot(id)
	if snap.Savings == nil && snap.Light == nil {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("not enrolled")
	}
	if s.Stores.Identity == nil {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("ledger unavailable")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return "", enrolledSnapshot{}, nil, err
	}
	defer zeroServiceBytes(key)
	rec, _, err := s.Stores.Identity.LoadVerifiedVault(id, key)
	if err != nil {
		return "", enrolledSnapshot{}, nil, err
	}
	if rec == nil {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("not enrolled")
	}
	if err := validateRecordSpendingPolicy(s.runtimeConfig().Network, rec); err != nil {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("stored economic policy: %w", err)
	}
	if err := program.ValidateProtectionTierRecovery(rec.ProtectionTier, len(rec.RecoveryKey) > 0); err != nil {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("stored protection tier: %w", err)
	}
	return id, snap, rec, nil
}

func (s *Service) rejectCrossVaultCredential(vaultID string, credID []byte) error {
	idx := s.published.Load()
	if idx == nil || len(credID) == 0 {
		return nil
	}
	mapped, ok := idx.byCred[hex.EncodeToString(credID)]
	if ok && mapped != vaultID {
		return fmt.Errorf("credential does not belong to this vault")
	}
	return nil
}

func mapLedgerBusy(err error) error {
	if errors.Is(err, policy.ErrRecoveryBusy) {
		return apperr.ErrBusy
	}
	if errors.Is(err, policy.ErrPeriodAllowanceExceeded) {
		return apperr.New(apperr.CodeRejected, "period allowance exceeded")
	}
	if errors.Is(err, policy.ErrVtxoOperationActive) {
		return apperr.New(apperr.CodeRejected, policy.ErrVtxoOperationActive.Error())
	}
	return err
}

func (s *Service) acquireVerification(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.verificationOnce.Do(func() {
		limit := s.MaxConcurrentVerifications
		if limit <= 0 {
			limit = defaultConcurrentVerifications
		}
		s.verificationSlots = make(chan struct{}, limit)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.verificationSlots <- struct{}{}:
		return func() { <-s.verificationSlots }, nil
	default:
		return nil, ErrVerificationBusy
	}
}

func (s *Service) acquireFeeSelection(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.feeSelectionOnce.Do(func() {
		limit := s.MaxConcurrentFeeSelections
		if limit <= 0 {
			limit = defaultConcurrentFeeSelections
		}
		s.feeSelectionSlots = make(chan struct{}, limit)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.feeSelectionSlots <- struct{}{}:
		return func() { <-s.feeSelectionSlots }, nil
	default:
		return nil, apperr.New(apperr.CodeBusy, "fee selection capacity exhausted")
	}
}

func (s *Service) runtimeConfig() deployment.Config {
	if s == nil {
		return deployment.Config{}
	}
	return s.Deployment
}

func (s *Service) programPins() program.NetworkPins {
	pins, err := program.PinsFor(s.runtimeConfig().Network)
	if err != nil {
		return program.NetworkPins{}
	}
	return pins
}

func (s *Service) boardExitDelay() uint32 {
	return s.programPins().BoardExitDelay
}

func (s *Service) policyExitDelay() uint32 {
	return s.programPins().PolicyExitDelay
}

func (s *Service) credentialIntegrityKey() ([]byte, error) {
	if len(s.CredentialIntegrityKey) == sha256.Size {
		return append([]byte(nil), s.CredentialIntegrityKey...), nil
	}
	if len(s.CredentialIntegrityKey) != 0 {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	return nil, fmt.Errorf("credential integrity key is required")
}

func (s *Service) loadVerifiedEnvelopeFor(vaultID string, credentialID []byte) (*policy.CredentialEnvelope, error) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(key)
	vaultID, err = s.routeVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	envelope, err := s.Stores.Identity.GetVaultEnvelope(vaultID)
	if err != nil || envelope == nil {
		return envelope, err
	}
	if err := policy.VerifyVaultEnvelope(envelope, vaultID, credentialID, key); err != nil {
		return nil, fmt.Errorf("authoritative credential envelope integrity verification failed: %w; restore a verified backup or use a reviewed migration", err)
	}
	return envelope, nil
}

func (s *Service) loadVerifiedCredentialFor(vaultID string) (*policy.Credential, error) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(key)
	vaultID, err = s.routeVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	rec, vcred, err := s.Stores.Identity.LoadVerifiedVault(vaultID, key)
	if err != nil || rec == nil || vcred == nil {
		return nil, err
	}
	out := rec.ToCredential(*vcred)
	return &out, nil
}

func zeroServiceBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

// RuntimeConfig returns the validated public identity used by HTTP and the
// browser. Callers receive a value copy and cannot mutate Service state.
func (s *Service) RuntimeConfig() (deployment.Config, error) {
	cfg := s.runtimeConfig()
	return cfg, cfg.Validate()
}

func decodeAssertion(req WebAuthnAssertionRequest) (webauthn.Assertion, error) {
	id, err := decodeHex(req.CredentialID)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	cd, err := decodeHex(req.ClientDataJSON)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	ad, err := decodeHex(req.AuthenticatorData)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	sig, err := decodeHex(req.Signature)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	return webauthn.Assertion{
		CredentialID:      id,
		ClientDataJSON:    cd,
		AuthenticatorData: ad,
		DERSignature:      sig,
	}, nil
}

func parseAndVerifyPrevout(raw string) (*psbt.Packet, *wire.MsgTx, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		return nil, nil, fmt.Errorf("psbt: %w", err)
	}
	prev, err := vault.RequireVerifiedPrevout(ptx)
	if err != nil {
		return nil, nil, err
	}
	return ptx, prev, nil
}

func verifyDirectAuth(directPub, digest, compact []byte) error {
	pub, err := webauthn.ParseCompressedP256(directPub)
	if err != nil {
		return fmt.Errorf("direct p256: %w", err)
	}
	if err := webauthn.VerifyDigestLowS(pub, digest, compact); err != nil {
		return fmt.Errorf("direct auth: %w", err)
	}
	return nil
}

func (s *Service) advanceSignCount(vaultID string, credID []byte, count uint32) error {
	if s == nil || s.Stores.Identity == nil {
		return nil
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return err
	}
	return s.Stores.Identity.AdvanceSignCount(vaultID, credID, count)
}

func rejectPRF(clientDataJSON []byte) error {
	if webauthn.ContainsPRFField(clientDataJSON) {
		return fmt.Errorf("prf material rejected")
	}
	return nil
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return b, nil
}

func init() {
	log.SetFlags(log.LstdFlags)
}
