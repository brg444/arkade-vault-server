package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

var errLightEnrollmentExpired = errors.New("Light enrollment expired")

// Light has an explicit enrollment surface: no hardware, Savings or boarding
// keys can be posted, and its policy digest commits to its own named program.
type LightEnrollStartRequest struct {
	SpendingPolicy       light.Policy `json:"spendingPolicy"`
	SpendingPolicyDigest string       `json:"spendingPolicyDigest"`
}

type LightEnrollFinishRequest struct {
	Handle            string `json:"handle"`
	VaultID           string `json:"vaultId"`
	UserHandle        string `json:"userHandle"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	AttestationObject string `json:"attestationObject,omitempty"`
	CredentialID      string `json:"credentialId"`
	WebAuthnP256      string `json:"webauthnP256"`
	PhoneDirectP256   string `json:"phoneDirectP256"`
	OwnerPub          string `json:"ownerPub"`
	DescriptorHash    string `json:"descriptorHash"`
	LightEnrollStartRequest
}

type ProposedLightEnrollment struct {
	Descriptor     light.Descriptor `json:"descriptor"`
	DescriptorHash string           `json:"descriptorHash"`
}

func (s *Service) requireLightPolicy(req LightEnrollStartRequest) ([]byte, error) {
	digest, err := light.PolicyDigest(s.runtimeConfig().Network, req.SpendingPolicy)
	if err != nil {
		return nil, err
	}
	if req.SpendingPolicyDigest != digest {
		return nil, fmt.Errorf("Light policy digest mismatch")
	}
	return hex.DecodeString(digest)
}

func (s *Service) StartLightEnrollment(token string, req LightEnrollStartRequest) (*EnrollStartResponse, error) {
	if !s.LightEnabled {
		return nil, fmt.Errorf("Light enrollment unavailable")
	}
	if err := s.runtimeConfig().Validate(); err != nil {
		return nil, err
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	digest, err := s.requireLightPolicy(req)
	if err != nil {
		return nil, err
	}
	id, err := randomHex(32)
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
	now := s.currentEnrollmentTime().UTC()
	pending, err := s.Stores.Identity.ReservePendingEnrollment(policy.PendingEnrollment{
		Handle: handle, VaultID: id, TokenHash: hash, Challenge: challenge, ProtectionTier: program.ProtectionTierStandard, PolicyDigest: digest,
		ExpiresAt: now.Add(pendingEnrollmentTTL).Format(time.RFC3339), CreatedAt: now.Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	// A Standard pending ceremony must never be reinterpreted as Light.
	if len(pending.VaultID) != 64 || !bytes.Equal(pending.PolicyDigest, digest) {
		return nil, fmt.Errorf("pending enrollment profile mismatch")
	}
	cfg := s.runtimeConfig()
	return &EnrollStartResponse{Handle: pending.Handle, VaultID: pending.VaultID, Challenge: hex.EncodeToString(pending.Challenge), RPID: cfg.RPID, RPName: "Vaulted", UserID: hex.EncodeToString([]byte(pending.VaultID)), UserName: "Vaulted Light", TimeoutMS: int(pendingEnrollmentTTL / time.Millisecond), ProtectionTier: "light", SpendingPolicy: program.SpendingPolicy(req.SpendingPolicy), SpendingPolicyDigest: hex.EncodeToString(digest)}, nil
}

func (s *Service) pendingLightEnrollment(token string, req LightEnrollFinishRequest) (*policy.PendingEnrollment, error) {
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Stores.Identity.GetPendingByHandle(req.Handle)
	if err != nil || pending == nil || !bytesEqualConst(pending.TokenHash, hash) {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	digest, err := s.requireLightPolicy(req.LightEnrollStartRequest)
	if err != nil {
		return nil, err
	}
	if pending.ProtectionTier != program.ProtectionTierStandard || len(pending.VaultID) != 64 || req.VaultID != pending.VaultID || !bytesEqualConst(digest, pending.PolicyDigest) {
		return nil, fmt.Errorf("pending Light enrollment mismatch")
	}
	expiry, err := time.Parse(time.RFC3339, pending.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("pending enrollment expiry invalid")
	}
	if !s.currentEnrollmentTime().Before(expiry) {
		return nil, errLightEnrollmentExpired
	}
	return pending, nil
}

func (s *Service) lightEnrollmentCredential(req LightEnrollFinishRequest) (policy.Credential, error) {
	var empty policy.Credential
	if _, err := s.requireLightPolicy(req.LightEnrollStartRequest); err != nil {
		return empty, err
	}
	id, err := decodeHex(req.CredentialID)
	if err != nil || len(id) == 0 || len(id) > 1024 {
		return empty, fmt.Errorf("invalid credential id")
	}
	pass, err := decodeHex(req.WebAuthnP256)
	if err != nil {
		return empty, err
	}
	if _, err := webauthn.ParseCompressedP256(pass); err != nil {
		return empty, err
	}
	direct, err := decodeHex(req.PhoneDirectP256)
	if err != nil {
		return empty, err
	}
	if _, err := webauthn.ParseCompressedP256(direct); err != nil {
		return empty, err
	}
	if bytes.Equal(pass, direct) {
		return empty, fmt.Errorf("direct-auth key must be distinct from passkey")
	}
	owner, err := s.parseOnboardingKey("ownerPub", req.OwnerPub)
	if err != nil {
		return empty, err
	}
	operator, err := btcec.ParsePubKey(s.operatorSignerPub())
	if err != nil {
		return empty, err
	}
	cfg := s.runtimeConfig()
	keyContext, err := newVtxoKeyContext(req.VaultID, cfg.Network, operator.SerializeCompressed())
	if err != nil {
		return empty, err
	}
	keyContext.lightProfile = true
	cosigner, err := s.keys.vtxoPublic(keyContext)
	if err != nil {
		return empty, err
	}
	p := req.SpendingPolicy
	cred := policy.Credential{ID: id, WebAuthnP256: pass, PhoneDirectP256: direct, PhoneBIP340: owner.SerializeCompressed(),
		VaultID: req.VaultID, Network: cfg.Network, Origin: cfg.ClientOrigin, RPID: cfg.RPID,
		TemplateVersion: light.Profile, PolicyVersion: light.PolicySchema, ProtectionTier: program.ProtectionTierStandard,
		VaultCosignerBase: cosigner.SerializeCompressed(), RecipientDustSats: program.DustSats,
		TxRecipientCapSats: p.TxRecipientCapSats, PeriodAllowanceSats: p.PeriodAllowanceSats, AbsoluteFeeCapSats: p.AbsoluteFeeCapSats, FeerateCapSatPerV: p.FeerateCapSatPerV}
	if _, err := s.lightDescriptorForCredential(&cred); err != nil {
		return empty, err
	}
	return cred, nil
}

func (s *Service) ProposeLightEnrollment(token string, req LightEnrollFinishRequest) (*ProposedLightEnrollment, error) {
	if _, err := s.pendingLightEnrollment(token, req); err != nil {
		return nil, err
	}
	cred, err := s.lightEnrollmentCredential(req)
	if err != nil {
		return nil, err
	}
	d, err := s.lightDescriptorForCredential(&cred)
	if err != nil {
		return nil, err
	}
	hash, err := light.DescriptorDigest(d)
	if err != nil {
		return nil, err
	}
	return &ProposedLightEnrollment{Descriptor: d, DescriptorHash: hash}, nil
}

func lightCreateCeremony(req LightEnrollFinishRequest) EnrollFinishRequest {
	return EnrollFinishRequest{Handle: req.Handle, UserHandle: req.UserHandle, ClientDataJSON: req.ClientDataJSON, AuthenticatorData: req.AuthenticatorData, AttestationObject: req.AttestationObject, RegisterRequest: RegisterRequest{VaultID: req.VaultID, CredentialID: req.CredentialID, WebAuthnP256: req.WebAuthnP256}}
}

func (s *Service) FinishLightEnrollment(ctx context.Context, token string, req LightEnrollFinishRequest) (*Status, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	pending, err := s.pendingLightEnrollment(token, req)
	if err != nil {
		if st, ok := s.acceptDuplicateLightFinish(ctx, token, req); ok {
			return st, nil
		}
		return nil, err
	}
	if err := s.validateEnrollmentCreate(pending, lightCreateCeremony(req)); err != nil {
		return nil, err
	}
	cred, err := s.lightEnrollmentCredential(req)
	if err != nil {
		return nil, err
	}
	d, err := s.lightDescriptorForCredential(&cred)
	if err != nil {
		return nil, err
	}
	hash, err := light.DescriptorDigest(d)
	if err != nil {
		return nil, err
	}
	if req.DescriptorHash != hash {
		return nil, fmt.Errorf("Light descriptor hash mismatch")
	}
	rec := policy.VaultRecordFromCredential(cred)
	// Schema v1 deliberately stores absence as empty BLOBs, never invented keys.
	rec.ExternalOwnerWallet = []byte{}
	rec.ArkadeCosignerBase = []byte{}
	rec.SavingsScript = []byte{}
	if err := sealVaultRecordForService(&rec, s); err != nil {
		return nil, err
	}
	pass := policy.VaultCredential{CredentialID: cred.ID, VaultID: cred.VaultID, WebAuthnP256: cred.WebAuthnP256, UserHandle: []byte(cred.VaultID), Resident: true}
	if err := sealVaultCredentialForService(&pass, s); err != nil {
		return nil, err
	}
	s.mu.Lock()
	err = s.Stores.Identity.CreateVault(policy.CreateVaultInput{Record: rec, Credential: pass, TokenHash: pending.TokenHash, Pending: pending})
	if err == nil {
		err = s.publishStoredLightEnrollment(&cred)
	}
	s.mu.Unlock()
	if err != nil {
		if st, ok := s.acceptDuplicateLightFinish(ctx, token, req); ok {
			return st, nil
		}
		return nil, err
	}
	st, err := s.statusFor(ctx, cred.VaultID)
	return &st, err
}

func (s *Service) acceptDuplicateLightFinish(ctx context.Context, token string, req LightEnrollFinishRequest) (*Status, bool) {
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, false
	}
	inv, err := s.Stores.Identity.GetInvite(hash)
	if err != nil || inv == nil || inv.ConsumedVaultID != req.VaultID || req.VaultID == "" {
		return nil, false
	}
	handle, err := decodeHex(req.UserHandle)
	if err != nil || !bytesEqualConst(handle, []byte(req.VaultID)) {
		return nil, false
	}
	stored, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil || stored == nil {
		return nil, false
	}
	want, err := s.lightEnrollmentCredential(req)
	if err != nil {
		return nil, false
	}
	d, err := s.lightDescriptorForCredential(&want)
	if err != nil {
		return nil, false
	}
	digest, err := light.DescriptorDigest(d)
	if err != nil || digest != req.DescriptorHash {
		return nil, false
	}
	if policy.VaultRecordsCanonicallyEqual(policy.VaultRecordFromCredential(*stored), policy.VaultRecordFromCredential(want)) != nil || !bytesEqualConst(stored.ID, want.ID) || !bytesEqualConst(stored.WebAuthnP256, want.WebAuthnP256) {
		return nil, false
	}
	st, err := s.statusFor(ctx, req.VaultID)
	return &st, err == nil
}
