package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
)

type lightRenewalIndexer interface {
	lightRenewalSettled(context.Context, lightRenewalPlan, verifiedLightRenewalFinal, []byte) (bool, error)
}

func (r *arkResolver) lightRenewalSettled(ctx context.Context, p lightRenewalPlan, final verifiedLightRenewalFinal, script []byte) (bool, error) {
	oldKey := p.Txid + ":" + strconv.FormatUint(uint64(p.Vout), 10)
	newKey := final.ReceiverTxid + ":" + strconv.FormatUint(uint64(final.ReceiverVout), 10)
	listed, err := r.listVtxosByOutpoint(ctx, []string{oldKey, newKey})
	if err != nil {
		return false, err
	}
	byID := map[string]indexerVtxo{}
	for _, v := range listed {
		if v.Outpoint.Vout == nil {
			return false, fmt.Errorf("Light renewal indexer outpoint")
		}
		id := v.Outpoint.Txid + ":" + strconv.FormatUint(uint64(*v.Outpoint.Vout), 10)
		if id != oldKey && id != newKey {
			return false, fmt.Errorf("Light renewal indexer unrelated output")
		}
		if _, ok := byID[id]; ok {
			return false, fmt.Errorf("Light renewal indexer duplicate")
		}
		byID[id] = v
	}
	old, ok := byID[oldKey]
	if !ok {
		return false, nil
	}
	if old.IsSpent && old.SettledBy != final.CommitmentTxid {
		return false, fmt.Errorf("Light renewal input settled elsewhere")
	}
	if !old.IsSpent || old.SettledBy != final.CommitmentTxid {
		return false, nil
	}
	prior, err := parseResolvedVtxo(old, script)
	if err != nil || prior.ValueSats != uint64(p.ValueSats) {
		return false, fmt.Errorf("Light renewal old output changed")
	}
	replacement, ok := byID[newKey]
	if !ok {
		return false, nil
	}
	current, err := parseResolvedVtxo(replacement, script)
	if err != nil || current.ValueSats != uint64(p.ReceiverSats) || current.ExpiresAt == nil || prior.ExpiresAt == nil || *current.ExpiresAt <= *prior.ExpiresAt {
		return false, fmt.Errorf("Light renewal replacement did not extend expiry")
	}
	matched := false
	for _, commitment := range current.CommitmentTxids {
		if commitment == final.CommitmentTxid {
			matched = true
		}
	}
	if !matched {
		return false, fmt.Errorf("Light renewal replacement commitment changed")
	}
	return true, nil
}

type lightRenewalOperationRequest struct {
	VaultID     string `json:"vaultId"`
	OperationID string `json:"operationId"`
}

func (s *Service) reconcileLightRenewal(ctx context.Context, r lightRenewalOperationRequest) (lightRenewalResponse, error) {
	snapshot, p, d, tree, err := s.loadLightRenewal(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["final_dispatched"]; !ok {
		return lightRenewalResponse{State: lightRenewalState(snapshot), IntentID: snapshot.Events["register_result"].OperatorRef}, nil
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	registration, err := lightRenewalStoredRegistration(snapshot, p, d, tree)
	if err != nil {
		release()
		return lightRenewalResponse{}, err
	}
	var evidence lightRenewalFinalEvidence
	if err := json.Unmarshal([]byte(snapshot.Events["final_authorized"].Evidence), &evidence); err != nil {
		release()
		return lightRenewalResponse{}, err
	}
	final, err := verifyLightRenewalFinal(evidence, p, d, tree, registration)
	release()
	if err != nil || hex.EncodeToString(final.RequestDigest) != snapshot.Events["final_dispatched"].RequestDigest {
		return lightRenewalResponse{}, fmt.Errorf("Light renewal persisted final mismatch")
	}
	response := lightRenewalResponse{State: "uncertain", CommitmentTxid: final.CommitmentTxid, ReceiverTxid: final.ReceiverTxid, ReceiverVout: final.ReceiverVout}
	if _, ok := snapshot.Events["final_result"]; ok {
		response.State = "submitted"
	}
	if _, ok := snapshot.Events["confirmed"]; ok {
		response.State = "confirmed"
		return response, nil
	}
	indexer, ok := s.ArkResolver.(lightRenewalIndexer)
	if !ok {
		return lightRenewalResponse{}, fmt.Errorf("Light renewal reconciliation unavailable")
	}
	settled, err := indexer.lightRenewalSettled(ctx, p, final, tree.PkScript)
	if err != nil {
		return response, err
	}
	if !settled {
		return response, nil
	}
	// A projected VTXO alone is insufficient: independently check the exact
	// Bitcoin commitment output backing the signed replacement tree.
	chain, err := s.lightRenewalChain()
	if err != nil {
		return response, err
	}
	confirmed, err := chain.confirmedOutpoint(ctx, final.CommitmentTxid, 0)
	if err != nil {
		return response, nil
	}
	packet, err := parseCanonicalVaultBoardPSBT(evidence.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || confirmed.ValueSats != packet.UnsignedTx.TxOut[0].Value || !bytes.Equal(confirmed.PkScript, packet.UnsignedTx.TxOut[0].PkScript) {
		return response, fmt.Errorf("Light renewal Bitcoin commitment mismatch")
	}
	proof, err := json.Marshal(struct {
		Commitment string `json:"commitmentTxid"`
		Block      string `json:"blockHash"`
		Height     int64  `json:"blockHeight"`
		Receiver   string `json:"receiverTxid"`
		Vout       uint32 `json:"receiverVout"`
	}{final.CommitmentTxid, confirmed.FundingBlockHash, confirmed.FundingBlockHeight, final.ReceiverTxid, final.ReceiverVout})
	if err != nil {
		return response, err
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "confirmed", RequestDigest: hex.EncodeToString(final.RequestDigest), Outcome: "confirmed", OperatorRef: final.CommitmentTxid, Evidence: string(proof)}); err != nil {
		return response, err
	}
	response.State = "confirmed"
	return response, nil
}
func (s *Service) lightRenewalChain() (vaultBoardChain, error) {
	if s.vaultBoardRuntime != nil {
		return s.vaultBoardRuntime.chain, nil
	}
	return dialVaultBoardChain(s.runtimeConfig().Network)
}
func (s *Service) releaseLightRenewal(ctx context.Context, r lightRenewalOperationRequest) (lightRenewalResponse, error) {
	snapshot, p, d, tree, err := s.loadLightRenewal(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return lightRenewalResponse{State: "released"}, nil
	}
	if _, ok := snapshot.Events["cancelled"]; ok {
		return lightRenewalResponse{State: "cancelled"}, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; ok {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	// No cosignature leaves this process before the durable final-dispatch CAS.
	// Fence even a prepared final after expiry if it never reached that boundary.
	// A racing dispatcher will fail its CAS before contacting the Operator.
	phase := "cancelled"
	digest := snapshot.Operation.PlanDigest
	proof := ""
	if dispatch, ok := snapshot.Events["register_dispatched"]; ok {
		if s.vtxoNow().Before(time.Unix(p.RegisterExpireAt, 0).Add(15 * time.Second)) {
			return lightRenewalResponse{State: "waiting_expiry"}, nil
		}
		input, err := s.liveLightRenewalInput(ctx, d, tree, p.Txid, p.Vout)
		if err != nil || input.ValueSats != uint64(p.ValueSats) {
			return lightRenewalResponse{State: "uncertain"}, nil
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			return lightRenewalResponse{}, err
		}
		phase = "released"
		digest = dispatch.RequestDigest
		proof = string(encoded)
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: phase, RequestDigest: digest, Evidence: proof}); err != nil {
		return lightRenewalResponse{}, err
	}
	return lightRenewalResponse{State: phase}, nil
}
