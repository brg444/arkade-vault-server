package application

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/webauthn"
)

const pendingEnrollmentTTL = 5 * time.Minute

// InviteView is the public invite lookup. It never includes consumed_vault_id.
type InviteView struct {
	CanEnroll bool    `json:"canEnroll"`
	VaultID   *string `json:"vaultId"`
}

// EnrollStartRequest freezes the user's selected policy before creating the
// passkey. The invite is carried separately in the header.
type EnrollStartRequest struct {
	ProtectionTier       string                 `json:"protectionTier"`
	SpendingPolicy       program.SpendingPolicy `json:"spendingPolicy"`
	SpendingPolicyDigest string                 `json:"spendingPolicyDigest"`
}

// EnrollStartResponse is the server-assigned vault identity plus create options.
type EnrollStartResponse struct {
	Handle               string                 `json:"handle"`
	VaultID              string                 `json:"vaultId"`
	Challenge            string                 `json:"challenge"`
	RPID                 string                 `json:"rpId"`
	RPName               string                 `json:"rpName"`
	UserID               string                 `json:"userId"`
	UserName             string                 `json:"userName"`
	TimeoutMS            int                    `json:"timeoutMs"`
	ProtectionTier       string                 `json:"protectionTier"`
	SpendingPolicy       program.SpendingPolicy `json:"spendingPolicy"`
	SpendingPolicyDigest string                 `json:"spendingPolicyDigest"`
}

// EnrollFinishRequest binds the pending handle to the created credential.
type EnrollFinishRequest struct {
	Handle            string `json:"handle"`
	UserHandle        string `json:"userHandle"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	AttestationObject string `json:"attestationObject,omitempty"`
	RegisterRequest
}

// InviteStatus reports whether the token can still enroll. Failures are generic.
func (s *Service) InviteStatus(token string) (InviteView, error) {
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	inv, err := s.Stores.Identity.GetInvite(hash)
	if err != nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	if inv == nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	if inv.ConsumedVaultID != "" {
		id := inv.ConsumedVaultID
		return InviteView{CanEnroll: false, VaultID: &id}, nil
	}
	if !inv.Usable(s.currentEnrollmentTime()) {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	return InviteView{CanEnroll: true, VaultID: nil}, nil
}

// StartEnrollment assigns a vault id for an unused invite and does not consume it.
func (s *Service) StartEnrollment(token string, request EnrollStartRequest) (*EnrollStartResponse, error) {
	if err := s.runtimeConfig().Validate(); err != nil {
		return nil, fmt.Errorf("deployment: %w", err)
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	if err := program.ValidateProtectionTier(request.ProtectionTier); err != nil {
		return nil, err
	}
	policyDigest, err := requireSpendingPolicyDigest(s.runtimeConfig().Network, request.SpendingPolicy, request.SpendingPolicyDigest)
	if err != nil {
		return nil, err
	}
	now := s.currentEnrollmentTime().UTC()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		return nil, err
	}
	handle, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	challenge, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	pending, err := s.Stores.Identity.ReservePendingEnrollment(policy.PendingEnrollment{
		Handle:         handle,
		VaultID:        vaultID,
		TokenHash:      hash,
		Challenge:      challenge,
		ProtectionTier: request.ProtectionTier,
		PolicyDigest:   policyDigest,
		ExpiresAt:      now.Add(pendingEnrollmentTTL).Format(time.RFC3339),
		CreatedAt:      now.Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	cfg := s.runtimeConfig()
	return &EnrollStartResponse{
		Handle:               pending.Handle,
		VaultID:              pending.VaultID,
		Challenge:            hex.EncodeToString(pending.Challenge),
		RPID:                 cfg.RPID,
		RPName:               "Arkade Vault",
		UserID:               hex.EncodeToString([]byte(pending.VaultID)),
		UserName:             "vault",
		TimeoutMS:            int(pendingEnrollmentTTL / time.Millisecond),
		ProtectionTier:       pending.ProtectionTier,
		SpendingPolicy:       request.SpendingPolicy,
		SpendingPolicyDigest: hex.EncodeToString(pending.PolicyDigest),
	}, nil
}

func requireSpendingPolicyDigest(network string, selected program.SpendingPolicy, encoded string) ([]byte, error) {
	digest, err := program.SpendingPolicyDigestFor(network, selected)
	if err != nil {
		return nil, err
	}
	want := hex.EncodeToString(digest)
	if encoded == "" || encoded != want {
		return nil, fmt.Errorf("spending policy digest does not match the selected policy")
	}
	return digest, nil
}

func requirePendingSpendingPolicy(network string, pending *policy.PendingEnrollment, selected program.SpendingPolicy, encoded string) error {
	digest, err := requireSpendingPolicyDigest(network, selected, encoded)
	if err != nil {
		return err
	}
	if pending == nil || subtle.ConstantTimeCompare(pending.PolicyDigest, digest) != 1 {
		return fmt.Errorf("spending policy does not match pending enrollment")
	}
	return nil
}

func requirePendingProtectionTier(pending *policy.PendingEnrollment, tier string) error {
	if err := program.ValidateProtectionTier(tier); err != nil {
		return err
	}
	if pending == nil || pending.ProtectionTier != tier {
		return fmt.Errorf("protection tier does not match pending enrollment")
	}
	return nil
}

// ProposeEnrollment returns the descriptor that Finish will persist. It does
// not consume the invite or write a vault row.
func (s *Service) ProposeEnrollment(token string, req EnrollFinishRequest) (*ProposedEnrollment, error) {
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Stores.Identity.GetPendingByHandle(req.Handle)
	if err != nil || pending == nil {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if subtle.ConstantTimeCompare(pending.TokenHash, hash) != 1 {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	now := s.currentEnrollmentTime().UTC()
	if pending.ExpiresAt != "" && pending.ExpiresAt < now.Format(time.RFC3339) {
		return nil, fmt.Errorf("pending enrollment expired")
	}
	if req.VaultID != "" && req.VaultID != pending.VaultID {
		return nil, fmt.Errorf("vault id does not match pending enrollment")
	}
	if err := requirePendingProtectionTier(pending, req.ProtectionTier); err != nil {
		return nil, err
	}
	if err := requirePendingSpendingPolicy(s.runtimeConfig().Network, pending, req.SpendingPolicy, req.SpendingPolicyDigest); err != nil {
		return nil, err
	}
	return s.previewVaultBoardEnrollmentDescriptor(pending.VaultID, req.RegisterRequest)
}

// FinishEnrollment verifies the create ceremony and CAS-consumes the invite.
func (s *Service) FinishEnrollment(ctx context.Context, token string, req EnrollFinishRequest) (*Status, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Stores.Identity.GetPendingByHandle(req.Handle)
	if err != nil {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if pending == nil {
		if status, ok := s.acceptDuplicateFinishFromToken(hash, req); ok {
			return status, nil
		}
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if subtle.ConstantTimeCompare(pending.TokenHash, hash) != 1 {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if err := requirePendingProtectionTier(pending, req.ProtectionTier); err != nil {
		return nil, err
	}
	if err := requirePendingSpendingPolicy(s.runtimeConfig().Network, pending, req.SpendingPolicy, req.SpendingPolicyDigest); err != nil {
		return nil, err
	}
	now := s.currentEnrollmentTime().UTC()
	if pending.ExpiresAt != "" && pending.ExpiresAt < now.Format(time.RFC3339) {
		return nil, fmt.Errorf("pending enrollment expired")
	}
	if err := s.validateEnrollmentCreate(pending, req); err != nil {
		return nil, err
	}
	if req.ExternalOwnerWalletXOnly == "" {
		return nil, fmt.Errorf("tenant owner pub required")
	}
	if s.afterLoadPending != nil {
		s.afterLoadPending()
	}
	err = s.createTenantVault(pending.VaultID, pending.TokenHash, req.RegisterRequest, pending)
	if err != nil {
		if status, ok := s.acceptDuplicateFinish(pending.VaultID, req.RegisterRequest); ok {
			return status, nil
		}
		return nil, err
	}
	st, err := s.statusFor(ctx, pending.VaultID)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// validateEnrollmentCreate verifies the same attested passkey ceremony for each
// explicitly named enrollment profile. Profile keys and policy are checked separately.
func (s *Service) validateEnrollmentCreate(pending *policy.PendingEnrollment, req EnrollFinishRequest) error {
	cfg := s.runtimeConfig()
	clientData, err := decodeHex(req.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("clientDataJSON: %w", err)
	}
	authData, err := decodeHex(req.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("authenticatorData: %w", err)
	}
	if req.AttestationObject != "" {
		obj, err := decodeHex(req.AttestationObject)
		if err != nil {
			return fmt.Errorf("attestationObject: %w", err)
		}
		fromObj, err := webauthn.ParseAttestationObject(obj)
		if err != nil {
			return fmt.Errorf("attestationObject: %w", err)
		}
		if !bytesEqualConst(fromObj, authData) {
			return fmt.Errorf("attestationObject authData mismatch")
		}
	}
	created, err := webauthn.ValidateCreate(clientData, authData, pending.Challenge, cfg.ClientOrigin, cfg.RPID)
	if err != nil {
		return fmt.Errorf("webauthn create: %w", err)
	}
	userHandle, err := decodeHex(req.UserHandle)
	if err != nil {
		return fmt.Errorf("userHandle: %w", err)
	}
	if !bytesEqualConst([]byte(pending.VaultID), userHandle) {
		return fmt.Errorf("userHandle does not match assigned vault")
	}
	postedID, err := decodeHex(req.CredentialID)
	if err != nil || !bytesEqualConst(created.CredentialID, postedID) {
		return fmt.Errorf("credential id does not match authenticator")
	}
	postedP256, err := decodeHex(req.WebAuthnP256)
	if err != nil || !bytesEqualConst(created.WebAuthnP256, postedP256) {
		return fmt.Errorf("webauthn p256 does not match authenticator")
	}
	return nil
}

func (s *Service) acceptDuplicateFinishFromToken(tokenHash []byte, req EnrollFinishRequest) (*Status, bool) {
	inv, err := s.Stores.Identity.GetInvite(tokenHash)
	if err != nil || inv == nil || inv.ConsumedVaultID == "" {
		return nil, false
	}
	userHandle, err := decodeHex(req.UserHandle)
	if err != nil || !bytesEqualConst([]byte(inv.ConsumedVaultID), userHandle) {
		return nil, false
	}
	return s.acceptDuplicateFinish(inv.ConsumedVaultID, req.RegisterRequest)
}

func (s *Service) acceptDuplicateFinish(vaultID string, req RegisterRequest) (*Status, bool) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, false
	}
	defer zeroServiceBytes(key)
	rec, cred, err := s.Stores.Identity.LoadVerifiedVault(vaultID, key)
	if err != nil || rec == nil || cred == nil {
		return nil, false
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, false
	}
	parsed, err = s.applyVaultBoardEnrollmentRequest(parsed, req)
	if err != nil {
		return nil, false
	}
	preview, err := s.previewVaultBoardEnrollmentDescriptor(vaultID, req)
	if err != nil || req.DescriptorHash == "" || req.DescriptorHash != preview.DescriptorHash {
		return nil, false
	}
	childPub, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return nil, false
	}
	descriptor, _, err := s.mintSavingsCredential(vaultID, parsed, childPub)
	if err != nil {
		return nil, false
	}
	wantRecord := vaultRecordFromDescriptor(descriptor)
	wantCredential := policy.VaultCredential{
		CredentialID: parsed.id, VaultID: vaultID, WebAuthnP256: parsed.webauthnP256,
		UserHandle: []byte(vaultID), Resident: true,
	}
	if policy.VaultRecordsCanonicallyEqual(*rec, wantRecord) != nil ||
		policy.VaultCredentialsCanonicallyEqual(*cred, wantCredential) != nil {
		return nil, false
	}
	if s.Stores.VaultBoard == nil {
		return nil, false
	}
	storedBoard, loadErr := s.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	wantBoard, _, buildErr := s.mintVaultBoardEnrollment(vaultID, parsed)
	if loadErr != nil || buildErr != nil || storedBoard == nil || wantBoard == nil ||
		storedBoard.Program != wantBoard.Program || !bytesEqualConst(storedBoard.BoardingPub, wantBoard.BoardingPub) ||
		!bytesEqualConst(storedBoard.CosignerPub, wantBoard.CosignerPub) || !bytesEqualConst(storedBoard.OperatorPub, wantBoard.OperatorPub) ||
		storedBoard.ExitDelay != wantBoard.ExitDelay || storedBoard.ExitDelayUnit != wantBoard.ExitDelayUnit ||
		!bytesEqualConst(storedBoard.PkScript, wantBoard.PkScript) || storedBoard.Address != wantBoard.Address {
		return nil, false
	}
	st, err := s.statusFor(context.Background(), vaultID)
	if err != nil {
		return nil, false
	}
	return &st, true
}

func newOpaqueVaultID() (string, error) {
	return randomHex(16)
}

func randomHex(n int) (string, error) {
	raw, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// EnrollmentSession removes manual admission without removing one-vault,
// expiring enrollment authorization. No token is logged or persisted in plaintext.
type EnrollmentSession struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

func (s *Service) IssueEnrollmentSession() (*EnrollmentSession, error) {
	if !s.OpenEnrollment {
		return nil, fmt.Errorf("invite required")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	raw, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, err
	}
	expires, err := s.Stores.Identity.IssueEnrollmentSession(hash, s.currentEnrollmentTime().UTC())
	if err != nil {
		return nil, err
	}
	return &EnrollmentSession{Token: token, ExpiresAt: expires.Format(time.RFC3339)}, nil
}
