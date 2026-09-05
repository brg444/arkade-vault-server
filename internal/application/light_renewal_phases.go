package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
)

type lightRenewalOperator interface {
	registerIntent(context.Context, string, string) (string, error)
	submitLightForfeit(context.Context, string) error
}

func (o *stockVaultBoardOperator) submitLightForfeit(ctx context.Context, signed string) error {
	return o.post(ctx, "/v1/batch/submitForfeitTxs", struct {
		SignedForfeitTxs   []string `json:"signedForfeitTxs"`
		SignedCommitmentTx string   `json:"signedCommitmentTx"`
	}{[]string{signed}, ""}, nil)
}
func (s *Service) dialLightRenewalOperator(ctx context.Context) (lightRenewalOperator, error) {
	if s.lightRenewalOperatorDial != nil {
		return s.lightRenewalOperatorDial(ctx)
	}
	operator, err := dialVaultBoardOperator(ctx, s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	stock, ok := operator.(*stockVaultBoardOperator)
	if !ok {
		return nil, fmt.Errorf("Light renewal public Operator required")
	}
	return stock, nil
}

type lightRenewalRegisterRequest struct {
	VaultID     string                   `json:"vaultId"`
	OperationID string                   `json:"operationId"`
	PSBT        string                   `json:"psbt"`
	Message     string                   `json:"message"`
	Assertion   WebAuthnAssertionRequest `json:"assertion"`
	DirectSig   string                   `json:"directSig"`
}
type lightRenewalRegistrationEvidence struct {
	PSBT    string `json:"psbt"`
	Message string `json:"message"`
}
type lightRenewalResponse struct {
	State          string `json:"state"`
	IntentID       string `json:"intentId,omitempty"`
	CommitmentTxid string `json:"commitmentTxid,omitempty"`
	ReceiverTxid   string `json:"receiverTxid,omitempty"`
	ReceiverVout   uint32 `json:"receiverVout,omitempty"`
}
type lightRenewalFinalRequest struct {
	VaultID     string                    `json:"vaultId"`
	OperationID string                    `json:"operationId"`
	Evidence    lightRenewalFinalEvidence `json:"evidence"`
}

func (s *Service) loadLightRenewal(ctx context.Context, vault, id string) (*policy.LightRenewalSnapshot, lightRenewalPlan, light.Descriptor, *vtxoPolicyTree, error) {
	d, tree, err := s.lightRenewalContext(vault)
	if err != nil {
		return nil, lightRenewalPlan{}, d, nil, err
	}
	if _, err := canonicalVtxoOperationID(id); err != nil {
		return nil, lightRenewalPlan{}, d, nil, err
	}
	snapshot, err := s.Stores.LightRenewal.GetLightRenewal(ctx, id)
	if err != nil || snapshot == nil || snapshot.Operation.VaultID != vault {
		return nil, lightRenewalPlan{}, d, nil, fmt.Errorf("Light renewal operation unavailable")
	}
	prepared, err := lightRenewalPreparedSnapshot(snapshot, d)
	return snapshot, prepared.Plan, d, tree, err
}
func (s *Service) persistLightRenewalEvent(e policy.LightRenewalEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, e, nil, 0)
	return err
}
func (s *Service) registerLightRenewal(ctx context.Context, r lightRenewalRegisterRequest) (lightRenewalResponse, error) {
	snapshot, p, d, tree, err := s.loadLightRenewal(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	verified, err := verifyLightRenewalRegistration(r.PSBT, r.Message, p, d, tree)
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	credential, count, err := s.verifyVtxoAuthorization(ctx, r.VaultID, verified.PlanDigest, r.Assertion, r.DirectSig)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	requestDigest := hex.EncodeToString(verified.RequestDigest)
	if prior, ok := snapshot.Events["register_authorized"]; ok && prior.RequestDigest != requestDigest {
		return lightRenewalResponse{}, fmt.Errorf("Light renewal registration changed")
	}
	for _, phase := range []string{"confirmed", "released", "cancelled", "final_result", "final_dispatched", "final_authorized"} {
		if _, ok := snapshot.Events[phase]; ok {
			return lightRenewalResponse{State: lightRenewalState(snapshot)}, nil
		}
	}
	if result, ok := snapshot.Events["register_result"]; ok {
		return lightRenewalResponse{State: result.Outcome, IntentID: result.OperatorRef}, nil
	}
	if _, ok := snapshot.Events["register_dispatched"]; ok {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	if err := s.requireFreshLightRenewal(ctx, p, d, tree); err != nil {
		return lightRenewalResponse{}, err
	}
	evidence, err := json.Marshal(lightRenewalRegistrationEvidence{verified.CanonicalPSBT, verified.Message})
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, _, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_authorized", RequestDigest: requestDigest, Evidence: string(evidence)}, credential, count); err != nil {
		return lightRenewalResponse{}, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	signed, err := s.keys.lightRenewalAuthorization(ctx, lightRenewalAuthorization{descriptor: d, plan: p, registrationPSBT: verified.CanonicalPSBT, registrationMessage: verified.Message})
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	operator, err := s.dialLightRenewalOperator(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if err := s.requireFreshLightRenewal(ctx, p, d, tree); err != nil {
		return lightRenewalResponse{}, err
	}
	_, created, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_dispatched", RequestDigest: requestDigest}, nil, 0)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if !created {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	intent, err := operator.registerIntent(ctx, signed, verified.Message)
	if err != nil {
		if isDefiniteVaultBoardRegisterRejection(err) {
			if persistErr := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_result", RequestDigest: requestDigest, Outcome: "rejected"}); persistErr == nil {
				return lightRenewalResponse{State: "rejected"}, nil
			}
		}
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_result", RequestDigest: requestDigest, Outcome: "registered", OperatorRef: intent}); err != nil {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	return lightRenewalResponse{State: "registered", IntentID: intent}, nil
}
func lightRenewalStoredRegistration(snapshot *policy.LightRenewalSnapshot, p lightRenewalPlan, d light.Descriptor, tree *vtxoPolicyTree) (verifiedLightRenewalRegistration, error) {
	event, ok := snapshot.Events["register_authorized"]
	if !ok {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal registration missing")
	}
	var evidence lightRenewalRegistrationEvidence
	if err := json.Unmarshal([]byte(event.Evidence), &evidence); err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	verified, err := verifyLightRenewalRegistration(evidence.PSBT, evidence.Message, p, d, tree)
	if err != nil || hex.EncodeToString(verified.RequestDigest) != event.RequestDigest {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal registration evidence changed")
	}
	return verified, nil
}
func (s *Service) finalizeLightRenewal(ctx context.Context, r lightRenewalFinalRequest) (lightRenewalResponse, error) {
	snapshot, p, d, tree, err := s.loadLightRenewal(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
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
	verified, err := verifyLightRenewalFinal(r.Evidence, p, d, tree, registration)
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	digest := hex.EncodeToString(verified.RequestDigest)
	response := lightRenewalResponse{CommitmentTxid: verified.CommitmentTxid, ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout}
	if previous, ok := snapshot.Events["final_authorized"]; ok && previous.RequestDigest != digest {
		return lightRenewalResponse{}, fmt.Errorf("Light renewal final request changed")
	}
	if _, ok := snapshot.Events["confirmed"]; ok {
		response.State = "confirmed"
		return response, nil
	}
	if _, ok := snapshot.Events["final_result"]; ok {
		response.State = "submitted"
		return response, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; ok {
		response.State = "uncertain"
		return response, nil
	}
	if err := s.requireFreshLightRenewal(ctx, p, d, tree); err != nil {
		return lightRenewalResponse{}, err
	}
	raw, err := json.Marshal(r.Evidence)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, _, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "final_authorized", RequestDigest: digest, Evidence: string(raw)}, nil, 0); err != nil {
		return lightRenewalResponse{}, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	signed, err := s.keys.lightRenewalAuthorization(ctx, lightRenewalAuthorization{descriptor: d, plan: p, registrationPSBT: registration.CanonicalPSBT, registrationMessage: registration.Message, final: &r.Evidence})
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	operator, err := s.dialLightRenewalOperator(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if err := s.requireFreshLightRenewal(ctx, p, d, tree); err != nil {
		return lightRenewalResponse{}, err
	}
	_, created, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "final_dispatched", RequestDigest: digest}, nil, 0)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if !created {
		response.State = "uncertain"
		return response, nil
	}
	if err := operator.submitLightForfeit(ctx, signed); err != nil {
		response.State = "uncertain"
		return response, nil
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "final_result", RequestDigest: digest, Outcome: "submitted"}); err != nil {
		response.State = "uncertain"
		return response, nil
	}
	response.State = "submitted"
	return response, nil
}
