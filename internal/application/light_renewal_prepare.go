package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type lightRenewalPrepareRequest struct {
	VaultID        string `json:"vaultId"`
	OperationID    string `json:"operationId"`
	Txid           string `json:"txid"`
	Vout           uint32 `json:"vout"`
	OwnerSignature string `json:"ownerSignature"`
}
type lightRenewalPrepared struct {
	Plan       lightRenewalPlan `json:"plan"`
	PlanDigest string           `json:"planDigest"`
	State      string           `json:"state"`
}

func lightRenewalPrepareDigest(r lightRenewalPrepareRequest) ([]byte, error) {
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return nil, err
	}
	if requireTxid(r.VaultID) != nil || requireTxid(r.Txid) != nil {
		return nil, fmt.Errorf("Light renewal prepare identity")
	}
	raw, err := json.Marshal(struct {
		VaultID     string `json:"vaultId"`
		OperationID string `json:"operationId"`
		Txid        string `json:"txid"`
		Vout        uint32 `json:"vout"`
	}{r.VaultID, r.OperationID, r.Txid, r.Vout})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("vaulted-light/renewal-prepare/v1:"), raw...))
	return sum[:], nil
}
func (s *Service) lightRenewalContext(vaultID string) (light.Descriptor, *vtxoPolicyTree, error) {
	if s == nil || s.Stores.LightRenewal == nil {
		return light.Descriptor{}, nil, fmt.Errorf("Light renewal store unavailable")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return light.Descriptor{}, nil, err
	}
	if err := s.requireArkResolver(); err != nil {
		return light.Descriptor{}, nil, err
	}
	id, snapshot, _, err := s.resolveSpendVaultRecord(vaultID)
	if err != nil || id != vaultID || snapshot.Light == nil {
		return light.Descriptor{}, nil, fmt.Errorf("enrolled Light wallet required")
	}
	tree, err := s.buildLightPolicyTree(*snapshot.Light)
	return *snapshot.Light, tree, err
}
func (s *Service) liveLightRenewalInput(ctx context.Context, d light.Descriptor, tree *vtxoPolicyTree, txid string, vout uint32) (ports.ResolvedVtxo, error) {
	all, err := s.ArkResolver.SpendableVtxos(ctx, tree.PkScript)
	if err != nil {
		return ports.ResolvedVtxo{}, err
	}
	var found *ports.ResolvedVtxo
	for _, v := range all {
		if v.Txid != txid || v.Vout != vout {
			continue
		}
		if found != nil || !bytes.Equal(v.Script, tree.PkScript) || v.ValueSats < 330 || v.ValueSats > 21_000_000*100_000_000 || v.IsSwept || v.ExpiresAt == nil || *v.ExpiresAt <= s.vtxoNow().Unix() || len(v.CommitmentTxids) == 0 {
			return ports.ResolvedVtxo{}, fmt.Errorf("Light renewal requires one live committed output")
		}
		copy := v
		found = &copy
	}
	if found == nil {
		return ports.ResolvedVtxo{}, fmt.Errorf("Light renewal input unavailable")
	}
	return *found, nil
}
func (s *Service) lightRenewalFee(ctx context.Context, v ports.ResolvedVtxo, script []byte, receiver uint64) (uint64, string, error) {
	policy, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return 0, "", err
	}
	estimator, digest, err := newVtxoFeeEstimator(policy)
	if err != nil {
		return 0, "", err
	}
	release, err := s.acquireFeeSelection(ctx)
	if err != nil {
		return 0, "", err
	}
	defer release()
	amount, err := estimator.Eval([]arkfee.OffchainInput{resolvedArkFeeInput(v)}, nil, []arkfee.Output{{Amount: receiver, Script: hex.EncodeToString(script)}}, nil)
	if err != nil {
		return 0, "", err
	}
	fee, err := exactFeeSats(amount)
	return fee, hex.EncodeToString(digest), err
}
func (s *Service) prepareLightRenewal(ctx context.Context, r lightRenewalPrepareRequest) (lightRenewalPrepared, error) {
	d, tree, err := s.lightRenewalContext(r.VaultID)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	digest, err := lightRenewalPrepareDigest(r)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	owner, err := schnorr.ParsePubKey(mustDecodeRenewalHex(d.OwnerPub))
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	raw, err := hex.DecodeString(r.OwnerSignature)
	if err != nil || hex.EncodeToString(raw) != r.OwnerSignature {
		return lightRenewalPrepared{}, fmt.Errorf("Light renewal owner signature")
	}
	signature, err := schnorr.ParseSignature(raw)
	if err != nil || !signature.Verify(digest, owner) {
		return lightRenewalPrepared{}, fmt.Errorf("Light renewal owner authorization required")
	}
	if prior, err := s.Stores.LightRenewal.GetLightRenewal(ctx, r.OperationID); err != nil {
		return lightRenewalPrepared{}, err
	} else if prior != nil {
		if prior.Operation.VaultID != r.VaultID || prior.Operation.InputTxid != r.Txid || prior.Operation.InputVout != r.Vout {
			return lightRenewalPrepared{}, fmt.Errorf("Light renewal operation already bound")
		}
		return lightRenewalPreparedSnapshot(prior, d)
	}
	v, err := s.liveLightRenewalInput(ctx, d, tree, r.Txid, r.Vout)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	receiver := v.ValueSats
	fee := uint64(0)
	feeDigest := ""
	stable := false
	for i := 0; i < 8; i++ {
		fee, feeDigest, err = s.lightRenewalFee(ctx, v, tree.PkScript, receiver)
		if err != nil {
			return lightRenewalPrepared{}, err
		}
		if fee > uint64(d.SpendingPolicy.AbsoluteFeeCapSats) || fee > v.ValueSats-330 {
			return lightRenewalPrepared{}, fmt.Errorf("Light renewal fee exceeds policy")
		}
		next := v.ValueSats - fee
		if next == receiver {
			stable = true
			break
		}
		receiver = next
	}
	if !stable {
		return lightRenewalPrepared{}, fmt.Errorf("Light renewal fee did not converge")
	}
	hash, err := light.DescriptorDigest(d)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	p := lightRenewalPlan{OperationID: r.OperationID, VaultID: r.VaultID, DescriptorHash: hash, Txid: r.Txid, Vout: r.Vout, ValueSats: int64(v.ValueSats), ReceiverSats: int64(receiver), FeeSats: int64(fee), FeePolicyDigest: feeDigest, RegisterExpireAt: s.vtxoNow().Add(5 * time.Minute).Unix()}
	digest, err = p.digest(d)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	saved, err := s.Stores.LightRenewal.ReserveLightRenewal(ctx, policy.LightRenewalOperation{OperationID: p.OperationID, VaultID: p.VaultID, InputTxid: p.Txid, InputVout: p.Vout, FeeSats: p.FeeSats, PlanDigest: hex.EncodeToString(digest), Plan: string(encoded), ExpiresAt: time.Unix(p.RegisterExpireAt, 0).UTC().Format(time.RFC3339)}, d.SpendingPolicy.PeriodAllowanceSats)
	if err != nil {
		return lightRenewalPrepared{}, err
	}
	return lightRenewalPreparedSnapshot(saved, d)
}
func lightRenewalPreparedSnapshot(s *policy.LightRenewalSnapshot, d light.Descriptor) (lightRenewalPrepared, error) {
	var p lightRenewalPlan
	if err := json.Unmarshal([]byte(s.Operation.Plan), &p); err != nil {
		return lightRenewalPrepared{}, err
	}
	digest, err := p.digest(d)
	if err != nil || hex.EncodeToString(digest) != s.Operation.PlanDigest || p.OperationID != s.Operation.OperationID || p.Txid != s.Operation.InputTxid || p.Vout != s.Operation.InputVout || p.FeeSats != s.Operation.FeeSats || time.Unix(p.RegisterExpireAt, 0).UTC().Format(time.RFC3339) != s.Operation.ExpiresAt {
		return lightRenewalPrepared{}, fmt.Errorf("Light renewal stored plan mismatch")
	}
	return lightRenewalPrepared{Plan: p, PlanDigest: s.Operation.PlanDigest, State: lightRenewalState(s)}, nil
}
func lightRenewalState(s *policy.LightRenewalSnapshot) string {
	for _, phase := range []string{"confirmed", "released", "cancelled", "final_result", "final_dispatched", "final_authorized", "delete_result", "delete_dispatched", "delete_authorized", "register_result", "register_dispatched", "register_authorized"} {
		if e, ok := s.Events[phase]; ok {
			if e.Outcome != "" {
				return e.Outcome
			}
			return phase
		}
	}
	return "prepared"
}
func (s *Service) requireFreshLightRenewal(ctx context.Context, p lightRenewalPlan, d light.Descriptor, tree *vtxoPolicyTree) error {
	if p.RegisterExpireAt-s.vtxoNow().Unix() < 15 {
		return fmt.Errorf("Light renewal authorization expired")
	}
	v, err := s.liveLightRenewalInput(ctx, d, tree, p.Txid, p.Vout)
	if err != nil {
		return err
	}
	if v.ValueSats != uint64(p.ValueSats) {
		return fmt.Errorf("Light renewal value changed")
	}
	fee, digest, err := s.lightRenewalFee(ctx, v, tree.PkScript, uint64(p.ReceiverSats))
	if err != nil || fee != uint64(p.FeeSats) || digest != p.FeePolicyDigest {
		return fmt.Errorf("Light renewal fee changed")
	}
	return nil
}
