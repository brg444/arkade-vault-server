package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

type lightRenewalAuthorizer interface {
	authorizeLightRenewal(context.Context, lightRenewalAuthorization) (string, error)
}

// Every request carries the complete named contract. Verification is repeated
// inside the key capability; no caller can substitute a digest or input list.
type lightRenewalAuthorization struct {
	descriptor          light.Descriptor
	plan                lightRenewalPlan
	registrationPSBT    string
	registrationMessage string
	final               *lightRenewalFinalEvidence
}

func (k *fileBackedVaultKeys) authorizeLightRenewal(ctx context.Context, r lightRenewalAuthorization) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := light.ValidateDescriptor(r.descriptor); err != nil {
		return "", err
	}
	// Reconstruct using the release pin, rather than an application-supplied tree.
	service := &Service{}
	service.Deployment.Network = r.descriptor.Network
	pins, err := deployment.IdentityFor(r.descriptor.Network)
	if err != nil {
		return "", err
	}
	tree, err := buildLightPolicyTree(r.descriptor, mustDecodeRenewalHex(pins.OperatorSignerPubHex), service.vtxoAddrHRP())
	if err != nil {
		return "", err
	}
	registration, err := verifyLightRenewalRegistration(r.registrationPSBT, r.registrationMessage, r.plan, r.descriptor, tree)
	if err != nil {
		return "", err
	}
	raw := registration.CanonicalPSBT
	indexes := []int{0, 1}
	sighash := txscript.SigHashAll
	if r.final != nil {
		verified, err := verifyLightRenewalFinal(*r.final, r.plan, r.descriptor, tree, registration)
		if err != nil {
			return "", err
		}
		raw = verified.CanonicalForfeitPSBT
		indexes = []int{0}
		sighash = txscript.SigHashDefault
	}
	key, err := newVtxoKeyContext(r.descriptor.VaultID, r.descriptor.Network, tree.ArkdPub.SerializeCompressed())
	if err != nil {
		return "", err
	}
	key.lightProfile = true
	expected, err := hex.DecodeString(r.descriptor.CosignerPub)
	if err != nil {
		return "", err
	}
	var signed string
	err = k.withMaster(func(master *btcec.PrivateKey) error {
		private, err := deriveVtxoKey(master, key)
		if err != nil {
			return err
		}
		defer private.Key.Zero()
		if !bytes.Equal(expected, schnorr.SerializePubKey(private.PubKey())) {
			return fmt.Errorf("Light renewal scoped key mismatch")
		}
		signed, err = signExactVaultBoardStage(ctx, raw, private, expected, tree.SpendLeaf, indexes, sighash)
		return err
	})
	return signed, err
}

func (k KeyCapabilities) lightRenewalAuthorization(ctx context.Context, r lightRenewalAuthorization) (string, error) {
	if isNilInterface(k.lightRenewal) {
		return "", fmt.Errorf("Light renewal capability unavailable")
	}
	return k.lightRenewal.authorizeLightRenewal(ctx, r)
}
