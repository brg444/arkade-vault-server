package application

import (
	"bytes"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Light uses Standard's no-recovery-key row variant inside its own profile.
// Template and policy schema are MAC-bound; no hardware or Savings key is invented.
func lightPolicyFromCredential(c *policy.Credential) light.Policy {
	p := spendingPolicyFromCredential(c)
	p.Program, p.Schema = light.Program, light.PolicySchema
	return light.Policy(p)
}

func validateRecordSpendingPolicy(network string, rec *policy.VaultRecord) error {
	if rec.TemplateVersion == light.Profile {
		p := spendingPolicyFromRecord(rec)
		p.Program, p.Schema = light.Program, light.PolicySchema
		if rec.PolicyVersion != light.PolicySchema || rec.ProtectionTier != program.ProtectionTierStandard || len(rec.RecoveryKey) > 0 || len(rec.ExternalOwnerWallet) > 0 || rec.SavingsAddress != "" || len(rec.SavingsScript) > 0 || len(rec.ArkadeCosignerBase) > 0 || rec.ArkadeCosignerOrigin != "" || rec.ArkadeCosignerVersion != "" {
			return fmt.Errorf("invalid Light profile identity")
		}
		return light.ValidatePolicy(network, light.Policy(p))
	}
	return program.ValidateSpendingPolicyFor(network, spendingPolicyFromRecord(rec))
}

func (s *Service) lightDescriptorForCredential(c *policy.Credential) (light.Descriptor, error) {
	cfg := s.runtimeConfig()
	if c == nil || c.TemplateVersion != light.Profile || c.Network != cfg.Network || c.Origin != cfg.ClientOrigin || c.RPID != cfg.RPID || c.RecipientDustSats != program.DustSats {
		return light.Descriptor{}, fmt.Errorf("Light identity incompatible with runtime")
	}
	record := policy.VaultRecordFromCredential(*c)
	if err := validateRecordSpendingPolicy(cfg.Network, &record); err != nil {
		return light.Descriptor{}, err
	}
	phone, err := btcec.ParsePubKey(c.PhoneBIP340)
	if err != nil {
		return light.Descriptor{}, err
	}
	operator, err := btcec.ParsePubKey(s.operatorSignerPub())
	if err != nil {
		return light.Descriptor{}, err
	}
	context, err := newVtxoKeyContext(c.VaultID, c.Network, operator.SerializeCompressed())
	if err != nil {
		return light.Descriptor{}, err
	}
	context.lightProfile = true
	cosigner, err := s.keys.vtxoPublic(context)
	if err != nil {
		return light.Descriptor{}, err
	}
	if !bytes.Equal(cosigner.SerializeCompressed(), c.VaultCosignerBase) {
		return light.Descriptor{}, fmt.Errorf("Light scoped cosigner does not match persisted identity")
	}
	pins, err := program.PinsFor(c.Network)
	if err != nil {
		return light.Descriptor{}, err
	}
	return light.BuildDescriptor(c.VaultID, light.Params{Network: c.Network, OwnerPub: hex.EncodeToString(schnorr.SerializePubKey(phone)), CosignerPub: hex.EncodeToString(schnorr.SerializePubKey(cosigner)), OperatorPub: hex.EncodeToString(schnorr.SerializePubKey(operator)), ExitDelaySeconds: pins.PolicyExitDelay}, lightPolicyFromCredential(c))
}

func (s *Service) publishStoredLightEnrollment(c *policy.Credential) error {
	descriptor, err := s.lightDescriptorForCredential(c)
	if err != nil {
		return err
	}
	phone, err := btcec.ParsePubKey(c.PhoneBIP340)
	if err != nil {
		return err
	}
	s.publishSnapshot(&enrolledSnapshot{VaultID: c.VaultID, CredentialID: bytes.Clone(c.ID), PhoneBIP340: phone, Light: &descriptor})
	return nil
}

func (s *Service) buildLightPolicyTree(d light.Descriptor) (*vtxoPolicyTree, error) {
	return buildLightPolicyTree(d, s.operatorSignerPub(), s.vtxoAddrHRP())
}

func buildLightPolicyTree(d light.Descriptor, operatorPub []byte, hrp string) (*vtxoPolicyTree, error) {
	if err := light.ValidateDescriptor(d); err != nil {
		return nil, err
	}
	encoded, err := light.BuildTree(d.Params)
	if err != nil {
		return nil, err
	}
	tap, err := schnorr.ParsePubKey(encoded.TapKey)
	if err != nil {
		return nil, err
	}
	operator, err := btcec.ParsePubKey(operatorPub)
	if err != nil {
		return nil, err
	}
	cosignerRaw, err := hex.DecodeString(d.CosignerPub)
	if err != nil {
		return nil, err
	}
	cosigner, err := schnorr.ParsePubKey(cosignerRaw)
	if err != nil {
		return nil, err
	}
	address := &arklib.Address{Version: 0, HRP: hrp, Signer: operator, VtxoTapKey: tap}
	encodedAddress, err := address.EncodeV0()
	if err != nil {
		return nil, err
	}
	return &vtxoPolicyTree{CosignerPub: cosigner, ArkdPub: operator, TapKey: tap, PkScript: encoded.PkScript, SpendLeaf: encoded.SpendScript, SpendControl: encoded.SpendControlBlock, RevealedScripts: []string{hex.EncodeToString(encoded.SpendScript), hex.EncodeToString(encoded.ExitScript)}, ArkAddress: encodedAddress}, nil
}
