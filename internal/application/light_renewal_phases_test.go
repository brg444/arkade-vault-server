package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

type lightRenewalTestOperator struct {
	registers, finals        int
	registerErr, finalErr    error
	signedProof, signedFinal string
}

func (o *lightRenewalTestOperator) registerIntent(_ context.Context, proof, _ string) (string, error) {
	o.registers++
	o.signedProof = proof
	return "renewal-intent", o.registerErr
}
func (o *lightRenewalTestOperator) submitLightForfeit(_ context.Context, raw string) error {
	o.finals++
	o.signedFinal = raw
	return o.finalErr
}

func setupLightRenewalPhases(t *testing.T, f lightRenewalProofFixture) (*Service, *lightRenewalTestOperator, lightRenewalRegisterRequest) {
	t.Helper()
	s := f.env.svc
	expiry := time.Now().Add(time.Hour).Unix()
	fees := ports.IntentFeePolicy{OffchainInput: "100.0"}
	f.plan.FeePolicyDigest = hex.EncodeToString(policy.ComputeIntentFeePolicyDigest(fees.OffchainInput, "", "", ""))
	// The fixture's plan is returned through its stored canonical representation.
	encoded, _ := json.Marshal(f.plan)
	digest, err := f.plan.digest(f.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	s.ArkResolver = &stubArkResolver{signer: s.operatorSignerPub(), feePolicy: fees, vtxos: []ports.ResolvedVtxo{{Txid: f.plan.Txid, Vout: f.plan.Vout, ValueSats: uint64(f.plan.ValueSats), Script: f.tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{strings.Repeat("aa", 32)}}}}
	if _, err := s.Stores.LightRenewal.ReserveLightRenewal(context.Background(), policy.LightRenewalOperation{OperationID: f.plan.OperationID, VaultID: f.plan.VaultID, InputTxid: f.plan.Txid, InputVout: f.plan.Vout, FeeSats: f.plan.FeeSats, PlanDigest: hex.EncodeToString(digest), Plan: string(encoded), ExpiresAt: time.Unix(f.plan.RegisterExpireAt, 0).UTC().Format(time.RFC3339)}, 100000); err != nil {
		t.Fatal(err)
	}
	operator := &lightRenewalTestOperator{}
	s.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	proof, err := f.proof(t).B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.SynthWithSignCount(f.env.p256, f.env.credID, digest, s.ClientOrigin(), s.runtimeConfig().RPID, true, true, 7)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.SignDigestLowS(f.env.direct, digest)
	if err != nil {
		t.Fatal(err)
	}
	return s, operator, lightRenewalRegisterRequest{VaultID: f.plan.VaultID, OperationID: f.plan.OperationID, PSBT: proof, Message: f.message, Assertion: WebAuthnAssertionRequest{CredentialID: hex.EncodeToString(f.env.credID), ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature)}, DirectSig: hex.EncodeToString(direct)}
}
func TestLightRenewalRegisterLostResponseDoesNotRedispatch(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint(ambiguous), func(t *testing.T) {
			f := newLightRenewalProofFixture(t)
			s, operator, request := setupLightRenewalPhases(t, f)
			if ambiguous {
				operator.registerErr = fmt.Errorf("response lost")
			}
			result, err := s.registerLightRenewal(context.Background(), request)
			expected := "registered"
			if ambiguous {
				expected = "uncertain"
			}
			if err != nil || result.State != expected {
				t.Fatalf("register: %+v %v", result, err)
			}
			if err := intent.Verify(operator.signedProof, request.Message, []*btcec.PublicKey{f.tree.ArkdPub}); err != nil {
				t.Fatalf("dual-signed proof: %v", err)
			}
			if result, err = s.registerLightRenewal(context.Background(), request); err != nil || result.State != expected || operator.registers != 1 {
				t.Fatalf("replay dispatched: %+v %v count=%d", result, err, operator.registers)
			}
		})
	}
}
func TestLightRenewalFinalLostResponseDoesNotRedispatch(t *testing.T) {
	f, _, evidence := newLightRenewalFinalFixture(t)
	s, operator, request := setupLightRenewalPhases(t, f)
	if result, err := s.registerLightRenewal(context.Background(), request); err != nil || result.State != "registered" {
		t.Fatalf("register: %+v %v", result, err)
	}
	operator.finalErr = fmt.Errorf("response lost after forfeit accepted")
	final := lightRenewalFinalRequest{VaultID: f.plan.VaultID, OperationID: f.plan.OperationID, Evidence: evidence}
	result, err := s.finalizeLightRenewal(context.Background(), final)
	if err != nil || result.State != "uncertain" || operator.finals != 1 {
		t.Fatalf("final: %+v %v count=%d", result, err, operator.finals)
	}
	packet, err := parsePSBT(operator.signedFinal)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireVerifiedSignersWithSighash(packet, 0, [][]byte{mustDecodeRenewalHex(f.descriptor.OwnerPub), mustDecodeRenewalHex(f.descriptor.CosignerPub)}, f.tree.SpendLeaf, txscript.SigHashDefault); err != nil {
		t.Fatal(err)
	}
	if len(packet.Inputs[1].TaprootScriptSpendSig) != 0 {
		t.Fatal("cosigned connector")
	}
	if _, err := s.finalizeLightRenewal(context.Background(), final); err != nil || operator.finals != 1 {
		t.Fatalf("final replay: %v count=%d", err, operator.finals)
	}
}
func TestLightRenewalKeyCapabilityRejectsSubstitution(t *testing.T) {
	f, registered, final := newLightRenewalFinalFixture(t)
	r := lightRenewalAuthorization{descriptor: f.descriptor, plan: f.plan, registrationPSBT: registered.CanonicalPSBT, registrationMessage: registered.Message, final: &final}
	if _, err := f.env.svc.keys.lightRenewalAuthorization(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	changed := r
	changed.plan.ReceiverSats--
	changed.plan.FeeSats++
	if _, err := f.env.svc.keys.lightRenewalAuthorization(context.Background(), changed); err == nil {
		t.Fatal("key capability signed substituted contract")
	}
	changed = r
	changed.descriptor.VaultID = strings.Repeat("ab", 32)
	if _, err := f.env.svc.keys.lightRenewalAuthorization(context.Background(), changed); err == nil {
		t.Fatal("key capability signed another wallet")
	}
	f.env.svc.keys.Wipe()
	if _, err := f.env.svc.keys.lightRenewalAuthorization(context.Background(), r); err == nil {
		t.Fatal("wiped renewal capability signed")
	}
}
func TestLightRenewalPrepareAuthenticatesOwnerAndPreservesPrincipal(t *testing.T) {
	f := newLightRenewalProofFixture(t)
	s := f.env.svc
	expiry := time.Now().Add(time.Hour).Unix()
	s.ArkResolver = &stubArkResolver{signer: s.operatorSignerPub(), vtxos: []ports.ResolvedVtxo{{Txid: f.plan.Txid, Vout: f.plan.Vout, ValueSats: 80000, Script: f.tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{strings.Repeat("aa", 32)}}}}
	request := lightRenewalPrepareRequest{VaultID: f.plan.VaultID, OperationID: f.plan.OperationID, Txid: f.plan.Txid, Vout: f.plan.Vout}
	if _, err := s.prepareLightRenewal(context.Background(), request); err == nil {
		t.Fatal("unauthenticated reservation")
	}
	digest, err := lightRenewalPrepareDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := schnorr.Sign(f.owner, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.OwnerSignature = hex.EncodeToString(signature.Serialize())
	result, err := s.prepareLightRenewal(context.Background(), request)
	if err != nil || result.Plan.ReceiverSats != 80000 || result.Plan.FeeSats != 0 {
		t.Fatalf("principal renewal: %+v %v", result, err)
	}
	replay, err := s.prepareLightRenewal(context.Background(), request)
	if err != nil || replay.PlanDigest != result.PlanDigest {
		t.Fatalf("prepare replay: %v", err)
	}
}

type lightRenewalSettledResolver struct {
	stubArkResolver
	settled bool
}

func (r *lightRenewalSettledResolver) lightRenewalSettled(context.Context, lightRenewalPlan, verifiedLightRenewalFinal, []byte) (bool, error) {
	return r.settled, nil
}
func TestLightRenewalReconciliationRequiresConfirmedBitcoinCommitment(t *testing.T) {
	f, _, evidence := newLightRenewalFinalFixture(t)
	s, _, request := setupLightRenewalPhases(t, f)
	resolver := &lightRenewalSettledResolver{stubArkResolver: *s.ArkResolver.(*stubArkResolver)}
	s.ArkResolver = resolver
	if _, err := s.registerLightRenewal(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	final, err := s.finalizeLightRenewal(context.Background(), lightRenewalFinalRequest{VaultID: f.plan.VaultID, OperationID: f.plan.OperationID, Evidence: evidence})
	if err != nil || final.State != "submitted" {
		t.Fatalf("final %+v %v", final, err)
	}
	commitment, err := parsePSBT(evidence.CommitmentPSBT)
	if err != nil {
		t.Fatal(err)
	}
	chain := &vaultBoardTestChain{state: vaultBoardConfirmedOutpoint{ValueSats: commitment.UnsignedTx.TxOut[0].Value, PkScript: commitment.UnsignedTx.TxOut[0].PkScript, FundingBlockHash: strings.Repeat("a5", 32), FundingBlockHeight: 1}}
	s.vaultBoardRuntime = &vaultBoardRuntime{chain: chain}
	op := lightRenewalOperationRequest{VaultID: f.plan.VaultID, OperationID: f.plan.OperationID}
	result, err := s.reconcileLightRenewal(context.Background(), op)
	if err != nil || result.State != "submitted" || chain.calls != 0 {
		t.Fatalf("unprojected finalized: %+v %v", result, err)
	}
	resolver.settled = true
	chain.err = fmt.Errorf("not confirmed yet")
	result, err = s.reconcileLightRenewal(context.Background(), op)
	if err != nil || result.State != "submitted" {
		t.Fatalf("unconfirmed finalized: %+v %v", result, err)
	}
	chain.err = nil
	chain.state.ValueSats++
	if _, err := s.reconcileLightRenewal(context.Background(), op); err == nil {
		t.Fatal("changed Bitcoin output accepted")
	}
	chain.state.ValueSats--
	result, err = s.reconcileLightRenewal(context.Background(), op)
	if err != nil || result.State != "confirmed" || result.CommitmentTxid != final.CommitmentTxid {
		t.Fatalf("confirmed result %+v %v", result, err)
	}
	if used, err := s.Stores.Allowance.SpentInPeriod(context.Background(), f.plan.VaultID, ""); err != nil || used != 100 {
		t.Fatalf("renewal charged principal: %d %v", used, err)
	}
}
