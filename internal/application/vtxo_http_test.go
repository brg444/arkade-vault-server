package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
)

type stubArkResolver struct {
	network      string
	vtxos        []ports.ResolvedVtxo
	feePolicy    ports.IntentFeePolicy
	feeErr       error
	checkpoint   []byte
	signer       []byte
	spentBy      string
	spentErr     error
	changeExists bool
}

func (s stubArkResolver) SpendableVtxos(context.Context, []byte) ([]ports.ResolvedVtxo, error) {
	return append([]ports.ResolvedVtxo(nil), s.vtxos...), nil
}

func (s stubArkResolver) IntentFeePolicy(context.Context) (ports.IntentFeePolicy, error) {
	return s.feePolicy, s.feeErr
}

func (s stubArkResolver) SubmittedVtxoState(_ context.Context, _ []byte, reserved []ports.ResolvedVtxo, arkTxid string, changeVout *uint32, _ uint64) (ports.SubmittedVtxoState, error) {
	if s.spentErr != nil {
		return ports.SubmittedVtxoPending, s.spentErr
	}
	if len(reserved) == 0 {
		return ports.SubmittedVtxoPending, fmt.Errorf("reserved outpoints required")
	}
	if s.spentBy == "" {
		return ports.SubmittedVtxoPending, nil
	}
	if !strings.EqualFold(s.spentBy, arkTxid) {
		return ports.SubmittedVtxoConflict, nil
	}
	if changeVout != nil && (!s.changeExists || *changeVout != 1) {
		return ports.SubmittedVtxoPending, nil
	}
	return ports.SubmittedVtxoFinalized, nil
}

func (s stubArkResolver) CheckpointTapscript() []byte { return append([]byte(nil), s.checkpoint...) }
func (s stubArkResolver) OperatorSignerPub() []byte   { return append([]byte(nil), s.signer...) }
func (s stubArkResolver) Network() string {
	if s.network != "" {
		return s.network
	}
	return program.NetworkMutinynet
}

func vtxoTestEnv(t *testing.T) (*env, *stubArkResolver, *btcec.PrivateKey) {
	t.Helper()
	e := newEnv(t)
	arkd, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubArkResolver{
		checkpoint: []byte{0xc0, 0x01},
		signer:     arkd.PubKey().SerializeCompressed(),
	}
	e.svc.ArkResolver = resolver
	return e, resolver, arkd
}

func mustTaprootDest(t *testing.T) string {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(k.PubKey()), &arklib.MutinyNetSigNetParams)
	if err != nil {
		t.Fatal(err)
	}
	return addr.EncodeAddress()
}

func mustArkadeDest(t *testing.T, operator *btcec.PrivateKey) string {
	return mustArkadeDestForPub(t, operator.PubKey())
}
func mustArkadeDestForPub(t *testing.T, operator *btcec.PublicKey) string {
	t.Helper()
	destination, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := (&arklib.Address{
		Version: 0, HRP: arklib.BitcoinMutinyNet.Addr,
		Signer: operator, VtxoTapKey: destination.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func signedReserveRequest(t *testing.T, e *env, req VtxoReserveRequest) VtxoReserveRequest {
	t.Helper()
	destScript, _, err := e.svc.decodeVtxoDest(req.DestAddress)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := policy.ComputeVtxoReserveDigest(req.OperationID, req.VaultID, req.Purpose, destScript, req.AmountSats)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(e.hot, digest)
	if err != nil {
		t.Fatal(err)
	}
	req.PhoneSignature = hex.EncodeToString(sig.Serialize())
	return req
}

func mustOddYPrivateKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	for scalar := byte(1); scalar != 0; scalar++ {
		priv, _ := btcec.PrivKeyFromBytes([]byte{scalar})
		if priv.PubKey().SerializeCompressed()[0] == 0x03 {
			return priv
		}
	}
	t.Fatal("odd-Y private key not found")
	return nil
}

func TestDecodeVtxoDestAcceptsXOnlyOperatorWithOddY(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	operator := mustOddYPrivateKey(t)
	resolver.signer = operator.PubKey().SerializeCompressed()
	if _, _, err := e.svc.decodeVtxoDest(mustArkadeDest(t, operator)); err != nil {
		t.Fatalf("x-only Operator identity rejected: %v", err)
	}
}

func TestDefaultVtxoDestinationGuardUsesOperatorNetworkDelay(t *testing.T) {
	for _, test := range []struct {
		network string
		delay   uint32
	}{
		{deployment.NetworkMainnet, 605184},
		{deployment.NetworkMutinynet, 2048},
	} {
		t.Run(test.network, func(t *testing.T) {
			e, _, operator := vtxoTestEnv(t)
			e.svc.Deployment.Network = test.network
			snap := enrolledSnapshot{PhoneBIP340: e.hot.PubKey()}
			if err := e.svc.refuseDefaultVtxoChange(snap, defaultVtxoPkScript(e.hot.PubKey(), operator.PubKey(), test.delay)); err == nil {
				t.Fatal("accepted this phone's ordinary wallet destination")
			}
			other, _ := btcec.NewPrivateKey()
			if err := e.svc.refuseDefaultVtxoChange(snap, defaultVtxoPkScript(other.PubKey(), operator.PubKey(), test.delay)); err != nil {
				t.Fatalf("refused a different recipient: %v", err)
			}
		})
	}
}

func TestDecodeVtxoDestPinsHRPToTheReleaseNetwork(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	operator := mustOddYPrivateKey(t)
	resolver.signer = operator.PubKey().SerializeCompressed()
	mainnetAddr, err := (&arklib.Address{
		Version: 0, HRP: arklib.Bitcoin.Addr,
		Signer: operator.PubKey(), VtxoTapKey: operator.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.decodeVtxoDest(mainnetAddr); err == nil {
		t.Fatal("mutinynet env accepted a mainnet ark address")
	}

	e.svc.Deployment.Network = deployment.NetworkMainnet
	if _, _, err := e.svc.decodeVtxoDest(mainnetAddr); err != nil {
		t.Fatalf("mainnet env rejected ark HRP: %v", err)
	}
	if _, _, err := e.svc.decodeVtxoDest(mustArkadeDest(t, operator)); err == nil {
		t.Fatal("mainnet env accepted a mutinynet tark address")
	}
}

func TestReserveSpendWithoutPackExitRejected(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	falseVal := false
	e.svc.vaultPolicyHasExit = &falseVal
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("ab", 32), Vout: 0, ValueSats: 40_000, Script: tree.PkScript,
	}}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "REJECTED") {
		t.Fatalf("pack without exit = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsBoardPurpose(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"board","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "spend") {
		t.Fatalf("board purpose = %d %s", rec.Code, rec.Body.String())
	}
}

func TestBoardAuthorizeRouteRemoved(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/board/authorize", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`"}`)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("board route still present = %d %s", rec.Code, rec.Body.String())
	}
}

func TestVaultBoardV1StatusUsesDistinctStandardBoardingTree(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	status, err := e.svc.StatusFor(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if !status.VtxoBoardingActive || status.VtxoBoardingProgram != program.VaultBoardV1 {
		t.Fatalf("boarding status = %+v", status)
	}
	if status.VtxoBoardingExitDelay != program.VaultBoardV1ExitDelay ||
		status.VtxoBoardingExitDelayUnit != program.VaultBoardV1ExitDelayUnit {
		t.Fatalf("boarding delay = %d %s", status.VtxoBoardingExitDelay, status.VtxoBoardingExitDelayUnit)
	}
	if !strings.HasPrefix(status.VtxoBoardingAddress, "tb1p") || len(status.VtxoBoardingScript) != 68 {
		t.Fatalf("boarding descriptor = %s %s", status.VtxoBoardingAddress, status.VtxoBoardingScript)
	}
	policyTree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	if status.VtxoBoardingAddress == policyTree.OnchainAddress ||
		status.VtxoBoardingScript == hex.EncodeToString(policyTree.PkScript) {
		t.Fatal("vault-board-v1 must be distinct from vault-policy-v1")
	}
}

func TestVaultBoardV1MatchesSDKVector(t *testing.T) {
	phone, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 1))
	master, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 2))
	boarding, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 3))
	operator, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 4))
	svc := &Service{
		Deployment:  deployment.Config{Network: deployment.NetworkMutinynet},
		ArkResolver: stubArkResolver{signer: operator.PubKey().SerializeCompressed()},
		keys:        testKeys(t, master, LocalSigner{Priv: operator}),
	}
	tree, err := svc.buildVtxoBoardTree(fixture.VaultID, enrolledSnapshot{PhoneBIP340: phone.PubKey()}, boarding.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tree.PkScript); got != "51205b05e624da25f8a138c64253650383731d40990ca80f5ab1855f86868be0d122" {
		t.Fatalf("vault-board-v1 script = %s", got)
	}
	if tree.OnchainAddress != "tb1ptvz7vfx6yhu2zwxxgffk2qurwvw5pxgv4q844vv9t7rgdzlq6y3qnu6rvj" {
		t.Fatalf("vault-board-v1 address = %s", tree.OnchainAddress)
	}
}

func TestReserveSpendHappyPathCanonicalDigest(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	low := strings.Repeat("01", 32)
	resolver.vtxos = []ports.ResolvedVtxo{
		{Txid: low, Vout: 1, ValueSats: 45_000, Script: tree.PkScript},
	}
	h := testAuthorizer(e.svc)
	dest := mustArkadeDest(t, arkd)
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("01", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: dest, AmountSats: 30_000,
	})
	raw := httpJSON(t, h, http.MethodPost, "/v1/vtxo/reserve", req)
	var out VtxoReserveResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID == "" || len(out.BundleDigest) != 64 {
		t.Fatalf("reserve = %+v", out)
	}
	if _, err := hex.DecodeString(out.BundleDigest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unsigned") || strings.Contains(strings.ToLower(string(raw)), "psbt") {
		t.Fatal("reserve must not return an unsigned PSBT")
	}
	if out.CheckpointTapscript == "" {
		t.Fatal("spend reserve missing checkpoint tapscript")
	}
	digest, err := hex.DecodeString(out.BundleDigest)
	if err != nil {
		t.Fatal(err)
	}
	destScript, err := hex.DecodeString(out.DestScript)
	if err != nil {
		t.Fatal(err)
	}
	changeScript, err := hex.DecodeString(out.ChangeScript)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(changeScript, tree.PkScript) {
		t.Fatal("change must be vault-policy-v1")
	}
	if out.ChangeSats != 15_000 || out.ChangeVout == nil || *out.ChangeVout != 1 || out.ChangeAddress != tree.ArkAddress {
		t.Fatalf("change response = %+v", out)
	}
	op, err := e.ledger.GetVtxoOperation(context.Background(), out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	swapped := []policy.VtxoBundleInput{
		{Txid: []byte(strings.ToUpper(low)), Vout: 1, ValueSats: 45_000},
	}
	again, err := policy.ComputeVtxoBundleDigest(
		policy.VtxoPurposeSpend, fixture.VaultID, destScript, changeScript,
		30_000, out.FeeSats, out.ChangeSats, out.ChangeVout, op.FeePolicyDigest, swapped, op.CreatedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatal("bundle digest depends on input order")
	}
}

func TestReserveSelectsFragmentedInputsWithOperatorFees(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	resolver.feePolicy = ports.IntentFeePolicy{
		OffchainInput: "5.0", OffchainOutput: "amount * 0.001",
		OnchainInput: "7.0", OnchainOutput: "amount * 0.002",
	}
	// Indexer order is deliberately the reverse of effective-value order.
	resolver.vtxos = []ports.ResolvedVtxo{
		{Txid: strings.Repeat("22", 32), Vout: 2, ValueSats: 15_000, Script: tree.PkScript},
		{Txid: strings.Repeat("11", 32), Vout: 1, ValueSats: 20_000, Script: tree.PkScript},
	}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("31", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	out, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Inputs) != 2 || out.Inputs[0].Txid != strings.Repeat("11", 32) || out.Inputs[1].Txid != strings.Repeat("22", 32) {
		t.Fatalf("canonical inputs = %+v", out.Inputs)
	}
	if out.FeeSats != 45 || out.ChangeSats != 4_955 || out.ChangeVout == nil || *out.ChangeVout != 1 {
		t.Fatalf("fee/change = %+v", out)
	}
	if out.FeePolicyDigest != "0315f524ae0610202998492284c074829ab156bea680b8313adfa25bdb782fb4" {
		t.Fatalf("fee policy digest = %s", out.FeePolicyDigest)
	}
	stored, err := e.ledger.GetVtxoOperationInputs(context.Background(), out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || hex.EncodeToString(stored[0].Txid) != out.Inputs[0].Txid || hex.EncodeToString(stored[1].Txid) != out.Inputs[1].Txid {
		t.Fatalf("stored input order = %+v", stored)
	}
}

func TestReserveExactNoChangeReloadShape(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("32", 32), Vout: 0, ValueSats: 20_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("33", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 20_000,
	})
	out, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if out.FeeSats != 0 || out.ChangeSats != 0 || out.ChangeVout != nil || out.ChangeAddress != "" || out.ChangeScript != "" {
		t.Fatalf("no-change reserve = %+v", out)
	}
	if len(out.FeePolicyDigest) != 64 {
		t.Fatalf("fee policy digest = %q", out.FeePolicyDigest)
	}
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.FeeSats != out.FeeSats || view.FeePolicyDigest != out.FeePolicyDigest || view.ChangeSats != 0 || view.ChangeVout != nil || view.ChangeScript != "" {
		t.Fatalf("no-change reload = %+v", view)
	}
}

func TestVtxoFeePolicyDriftFailsBeforeAuthorize(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("34", 32), Vout: 0, ValueSats: 20_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("35", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 20_000,
	})
	out, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	op, err := e.ledger.GetVtxoOperation(context.Background(), out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	resolver.feePolicy.OffchainInput = "1.0"
	if err := e.svc.requireCurrentVtxoFeePolicy(context.Background(), op); err == nil || !strings.Contains(err.Error(), "changed after reservation") {
		t.Fatalf("fee drift = %v", err)
	}
}

func TestSelectSpendVtxosRejectsUnsafeEconomicShapes(t *testing.T) {
	pkScript := []byte{0x51, 0x20, 0x01}
	destScript := []byte{0x51, 0x20, 0x02}
	tests := []struct {
		name      string
		coins     []ports.ResolvedVtxo
		amount    uint64
		fee       ports.IntentFeePolicy
		wantError string
	}{
		{
			name: "subdust change", amount: 20_000,
			coins:     []ports.ResolvedVtxo{{Txid: strings.Repeat("41", 32), ValueSats: 20_329, Script: pkScript}},
			wantError: "insufficient economic",
		},
		{
			name: "uneconomic input", amount: 330,
			coins: []ports.ResolvedVtxo{{Txid: strings.Repeat("42", 32), ValueSats: 1_000, Script: pkScript}},
			fee:   ports.IntentFeePolicy{OffchainInput: "amount"}, wantError: "insufficient economic",
		},
		{
			name: "fee over cap", amount: 20_000,
			coins: []ports.ResolvedVtxo{{Txid: strings.Repeat("43", 32), ValueSats: 30_000, Script: pkScript}},
			fee:   ports.IntentFeePolicy{OffchainInput: "5001.0"}, wantError: "insufficient economic",
		},
		{
			name: "indexed value over signed range", amount: 330,
			coins:     []ports.ResolvedVtxo{{Txid: strings.Repeat("44", 32), ValueSats: uint64(^uint64(0)>>1) + 1, Script: pkScript}},
			wantError: "invalid indexed vtxo",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &stubArkResolver{vtxos: test.coins}
			estimator, _, err := newVtxoFeeEstimator(test.fee)
			if err != nil {
				t.Fatal(err)
			}
			svc := &Service{ArkResolver: resolver}
			_, _, _, err = svc.selectSpendVtxos(context.Background(), pkScript, destScript, test.amount, uint64(program.AbsoluteFeeCeiling), estimator)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestSolveVtxoSpendStopsWhenRequestIsCancelled(t *testing.T) {
	estimator, _, err := newVtxoFeeEstimator(ports.IntentFeePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = solveVtxoSpend(ctx, []reservedCoin{{ValueSats: 30_000}}, []byte{0x51}, []byte{0x52}, 20_000, uint64(program.AbsoluteFeeCeiling), estimator)
	if !errors.Is(err, apperr.ErrBusy) {
		t.Fatalf("cancelled fee selection = %v, want BUSY", err)
	}
}

func TestSelectSpendVtxosBoundsExactFeeProgramWork(t *testing.T) {
	pkScript := []byte{0x51, 0x20, 0x01}
	destScript := []byte{0x51, 0x20, 0x02}
	estimator, _, err := newVtxoFeeEstimator(ports.IntentFeePolicy{OffchainOutput: "5001.0"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubArkResolver{}
	for i := 1; i <= 5; i++ {
		resolver.vtxos = append(resolver.vtxos, ports.ResolvedVtxo{
			Txid: fmt.Sprintf("%064x", i), ValueSats: 10_000, Script: pkScript,
		})
	}
	svc := &Service{ArkResolver: resolver}
	_, _, _, err = svc.selectSpendVtxos(context.Background(), pkScript, destScript, 1_000, uint64(program.AbsoluteFeeCeiling), estimator)
	if !errors.Is(err, apperr.ErrBusy) || !strings.Contains(err.Error(), "evaluation limit") {
		t.Fatalf("unbounded fee schedule = %v", err)
	}
}

func TestSelectSpendVtxosAllowsValidFragmentedExactFee(t *testing.T) {
	pkScript := []byte{0x51, 0x20, 0x01}
	destScript := []byte{0x51, 0x20, 0x02}
	estimator, _, err := newVtxoFeeEstimator(ports.IntentFeePolicy{OffchainOutput: "250.0"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubArkResolver{}
	for i := 1; i <= maxVtxoSpendInputs; i++ {
		resolver.vtxos = append(resolver.vtxos, ports.ResolvedVtxo{
			Txid: fmt.Sprintf("%064x", i), ValueSats: 1_000, Script: pkScript,
		})
	}
	svc := &Service{ArkResolver: resolver}
	coins, fee, change, err := svc.selectSpendVtxos(
		context.Background(), pkScript, destScript, 49_001, uint64(program.AbsoluteFeeCeiling), estimator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(coins) != maxVtxoSpendInputs || fee != 500 || change != 499 {
		t.Fatalf("fragmented selection = inputs %d fee %d change %d", len(coins), fee, change)
	}
}

func TestFeeSelectionConcurrencyIsBounded(t *testing.T) {
	svc := &Service{MaxConcurrentFeeSelections: 1}
	release, err := svc.acquireFeeSelection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := svc.acquireFeeSelection(context.Background()); !errors.Is(err, apperr.ErrBusy) {
		t.Fatalf("second fee selection = %v, want BUSY", err)
	}
}

func TestReserveRequiresPhoneAuthenticationBeforePersisting(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("19", 32), Vout: 0, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := VtxoReserveRequest{
		OperationID: strings.Repeat("18", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	}
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err == nil || !strings.Contains(err.Error(), "phoneSignature") {
		t.Fatalf("unauthenticated reserve = %v", err)
	}
	req = signedReserveRequest(t, e, req)
	req.AmountSats++
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err == nil || !strings.Contains(err.Error(), "phoneSignature") {
		t.Fatalf("mutated authenticated reserve = %v", err)
	}
	ops, err := e.ledger.ListVtxoOperations(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("rejected reserve persisted %d operations", len(ops))
	}
}

func TestReserveLostResponseReplaysExactReservation(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("21", 32), Vout: 2, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("22", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	first, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Discard first as if the HTTP response was lost, then retry the exact
	// durable request identifier.
	second, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("retry changed reservation:\nfirst=%+v\nsecond=%+v", first, second)
	}
	ops, err := e.ledger.ListVtxoOperations(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 {
		t.Fatalf("exact retry created %d operations", len(ops))
	}
}

func TestReserveOperationIDRejectsMutation(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("23", 32), Vout: 0, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("24", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.AmountSats++
	req = signedReserveRequest(t, e, req)
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err == nil || !strings.Contains(err.Error(), "different reserve request") {
		t.Fatalf("mutated retry = %v", err)
	}
}

func TestConcurrentExactReserveHasOneDurableOperation(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("25", 32), Vout: 0, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("26", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	start := make(chan struct{})
	results := make(chan *VtxoReserveResponse, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := e.svc.ReserveVtxo(context.Background(), req)
			results <- out
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first *VtxoReserveResponse
	for out := range results {
		if first == nil {
			first = out
		} else if !reflect.DeepEqual(first, out) {
			t.Fatalf("concurrent exact retry changed reservation: %+v != %+v", first, out)
		}
	}
	ops, err := e.ledger.ListVtxoOperations(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 {
		t.Fatalf("concurrent retry created %d operations", len(ops))
	}
}

func TestReserveRejectsDuplicateOutpoints(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	txid := strings.Repeat("cd", 32)
	resolver.vtxos = []ports.ResolvedVtxo{
		{Txid: txid, Vout: 1, ValueSats: 20_000, Script: tree.PkScript},
		{Txid: txid, Vout: 1, ValueSats: 21_000, Script: tree.PkScript},
	}
	h := testAuthorizer(e.svc)
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("01", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 10_000,
	})
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, string(raw))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("duplicate outpoints = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsBitcoinDestinationInRegularVtxoSlice(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Arkade address") {
		t.Fatalf("Bitcoin VTXO destination = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsArkadeDestinationForAnotherOperator(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	wrongOperator, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destination, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := (&arklib.Address{
		Version: 0, HRP: arklib.BitcoinMutinyNet.Addr,
		Signer: wrongOperator.PubKey(), VtxoTapKey: destination.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+addr+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Operator") {
		t.Fatalf("another Operator = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuthorizeSpendReplayRequiresFreshAuth(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	_, err := e.svc.AuthorizeVtxoSpend(context.Background(), VtxoAuthorizeRequest{
		VaultID: fixture.VaultID, OperationID: "missing", BundleDigest: strings.Repeat("00", 32),
	})
	if err == nil {
		t.Fatal("unsigned replay without reservation must fail")
	}
}

func TestAuthorizeSpendRejectsUnknownFieldsAndMissingGatewaySecret(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/authorize", "application/json", fixture.Origin, `{"vaultId":"x","extra":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d %s", rec.Code, rec.Body.String())
	}

	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	locked := AuthorizerHandler(e.svc)
	denied := httptest.NewRequest(http.MethodPost, "/v1/vtxo/authorize", strings.NewReader(`{"vaultId":"x"}`))
	denied.Header.Set("Content-Type", "application/json")
	denied.Header.Set("Origin", fixture.Origin)
	out := httptest.NewRecorder()
	locked.ServeHTTP(out, denied)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("missing gateway secret = %d %s", out.Code, out.Body.String())
	}
}

func TestFinalizeRequiresSpentByArkTxid(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	now := e.svc.vtxoNow().Format(timeRFC3339)
	digest := bytes.Repeat([]byte{0x33}, 32)
	feePolicyDigest := bytes.Repeat([]byte{0x44}, 32)
	changeVout := uint32(1)
	arkTxid := strings.Repeat("ab", 32)
	op := policy.VtxoOperation{
		OperationID:     "spend-final",
		VaultID:         fixture.VaultID,
		Purpose:         policy.VtxoPurposeSpend,
		BundleDigest:    digest,
		State:           policy.VtxoStateSigned,
		AmountSats:      10_000,
		DestScript:      bytes.Repeat([]byte{0x51}, 34),
		FeePolicyDigest: feePolicyDigest,
		ChangeScript:    bytes.Clone(tree.PkScript), ChangeSats: 10_000, ChangeVout: &changeVout,
		ArkTxid:   arkTxid,
		ExpiresAt: e.svc.vtxoNow().Add(vtxoReserveAuthorizeTimeout).Format(timeRFC3339),
		CreatedAt: now,
	}
	in := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x11}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}
	if err := e.ledger.ReserveVtxoOperation(context.Background(), policy.VtxoOperation{
		OperationID: op.OperationID, VaultID: op.VaultID, Purpose: op.Purpose, BundleDigest: op.BundleDigest,
		State: policy.VtxoStateReserved, AmountSats: op.AmountSats, FeePolicyDigest: op.FeePolicyDigest,
		DestScript: op.DestScript, ChangeScript: op.ChangeScript, ChangeSats: op.ChangeSats, ChangeVout: op.ChangeVout,
		ExpiresAt: op.ExpiresAt, CreatedAt: op.CreatedAt,
	}, []policy.VtxoOperationInput{in}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	stored, err := e.ledger.GetVtxoOperation(context.Background(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	stored, swapped, err := e.ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateReserved, func() policy.VtxoOperation {
		signed := stored
		signed.State = policy.VtxoStateSigned
		return signed
	}())
	if err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	if _, swapped, err := e.ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateSigned, stored); err != nil || !swapped {
		t.Fatal(err)
	}
	_, err = e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err == nil || !strings.Contains(err.Error(), "spent by ark txid") {
		t.Fatalf("disappearance-only finalize = %v", err)
	}
	resolver.spentBy = arkTxid
	_, err = e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err == nil || !strings.Contains(err.Error(), "spent by ark txid") {
		t.Fatalf("accept-only spend treated as finalized: %v", err)
	}
	resolver.changeExists = true
	out, err := e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.State != policy.VtxoStateFinalized {
		t.Fatalf("finalize = %+v", out)
	}
}

func insertSubmittedSpend(t *testing.T, e *env, operationID, arkTxid string, treePkScript []byte) {
	insertSubmittedSpendShape(t, e, operationID, arkTxid, treePkScript, true)
}

func insertSubmittedSpendShape(t *testing.T, e *env, operationID, arkTxid string, treePkScript []byte, withChange bool) {
	insertSpendShape(t, e, operationID, arkTxid, treePkScript, withChange, policy.VtxoStateSubmitted)
}

func insertSpendShape(t *testing.T, e *env, operationID, arkTxid string, treePkScript []byte, withChange bool, targetState string) {
	t.Helper()
	now := e.svc.vtxoNow().Format(timeRFC3339)
	digest := bytes.Repeat([]byte{0x33}, 32)
	feePolicyDigest := bytes.Repeat([]byte{0x44}, 32)
	var changeScript []byte
	var changeSats int64
	var changeVout *uint32
	if withChange {
		vout := uint32(1)
		changeScript = bytes.Clone(treePkScript)
		changeSats = 10_000
		changeVout = &vout
	}
	in := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x11}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(treePkScript),
	}
	if err := e.ledger.ReserveVtxoOperation(context.Background(), policy.VtxoOperation{
		OperationID: operationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend, BundleDigest: digest,
		State: policy.VtxoStateReserved, AmountSats: 10_000, FeePolicyDigest: feePolicyDigest,
		DestScript: bytes.Repeat([]byte{0x51}, 34), ChangeScript: changeScript, ChangeSats: changeSats, ChangeVout: changeVout,
		ExpiresAt: e.svc.vtxoNow().Add(vtxoReserveAuthorizeTimeout).Format(timeRFC3339), CreatedAt: now,
	}, []policy.VtxoOperationInput{in}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	stored, err := e.ledger.GetVtxoOperation(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	stored, swapped, err := e.ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateReserved, func() policy.VtxoOperation {
		signed := stored
		signed.State = policy.VtxoStateSigned
		return signed
	}())
	if err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	if targetState == policy.VtxoStateSigned {
		return
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	if _, swapped, err := e.ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateSigned, stored); err != nil || !swapped {
		t.Fatal(err)
	}
}

func TestRequestedSignedOperationReconcilesFromAuthoritativeIndexerFacts(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("ad", 32)
	insertSpendShape(t, e, "spend-signed", arkTxid, tree.PkScript, true, policy.VtxoStateSigned)
	resolver.spentBy = strings.Repeat("ce", 32)
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-signed")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateUnresolved {
		t.Fatalf("chain-dead signed operation = %s", view.State)
	}
	spent, err := e.ledger.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil || spent < 10_000 {
		t.Fatalf("signed conflict allowance = %d, %v", spent, err)
	}
}

func TestRequestedNoChangeOperationFinalizesWithoutChangeProjection(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("ac", 32)
	insertSubmittedSpendShape(t, e, "spend-no-change", arkTxid, tree.PkScript, false)
	resolver.spentBy = arkTxid
	resolver.changeExists = false
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-no-change")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateFinalized || view.ChangeSats != 0 || view.ChangeVout != nil || view.ChangeScript != "" {
		t.Fatalf("no-change finalize = %+v", view)
	}
}

func TestRequestedOperationReconcilesWhenIndexerShowsStoredArkTxid(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("ab", 32)
	insertSubmittedSpend(t, e, "spend-submitted", arkTxid, tree.PkScript)
	resolver.spentBy = arkTxid
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-submitted")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSubmitted {
		t.Fatalf("accept-only spend was finalized: %s", view.State)
	}
	resolver.changeExists = true
	view, err = e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-submitted")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateFinalized {
		t.Fatalf("submitted was not reconciled: %s", view.State)
	}
}

func TestRequestedOperationDoesNotTrustADifferentArkTxid(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	storedTxid := strings.Repeat("ab", 32)
	insertSubmittedSpend(t, e, "spend-foreign", storedTxid, tree.PkScript)
	resolver.spentBy = strings.Repeat("cd", 32)
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-foreign")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateUnresolved {
		t.Fatalf("foreign spend was not quarantined: %s", view.State)
	}
	spent, err := e.ledger.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil {
		t.Fatal(err)
	}
	if spent < 10_000 {
		t.Fatalf("unresolved spend released allowance: %d", spent)
	}
}

func TestGetVtxoOperationViewKeepsPendingSubmissionPending(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("ab", 32)
	insertSubmittedSpend(t, e, "spend-status", arkTxid, tree.PkScript)
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-status")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSubmitted || view.ArkTxid != arkTxid {
		t.Fatalf("view = %+v", view)
	}
}

func TestGetVtxoOperationViewReturnsSignedPsbt(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("cd", 32)
	insertSubmittedSpend(t, e, "spend-signed", arkTxid, tree.PkScript)
	stored, err := e.ledger.GetVtxoOperation(context.Background(), "spend-signed")
	if err != nil {
		t.Fatal(err)
	}
	finalized := stored
	finalized.State = policy.VtxoStateFinalized
	if _, swapped, err := e.ledger.TransitionVtxoOperation(
		context.Background(), policy.VtxoStateSubmitted, finalized,
	); err != nil || !swapped {
		t.Fatalf("retire submitted fixture: swapped=%v err=%v", swapped, err)
	}
	// The helper created a submitted operation. Use a separate current
	// reservation because state transitions are deliberately irreversible.
	stored.OperationID = "spend-signed-current"
	stored.State = policy.VtxoStateReserved
	stored.AuthorizedPSBT = "cHNidP9signed"
	stored.ArkTxid = arkTxid
	stored.IntegrityMAC = nil
	if err := e.ledger.ReserveVtxoOperation(context.Background(), stored, []policy.VtxoOperationInput{{
		Txid: bytes.Repeat([]byte{0x12}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	stored, err = e.ledger.GetVtxoOperation(context.Background(), stored.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSigned
	if _, swapped, err := e.ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateReserved, stored); err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, stored.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSigned || view.AuthorizedPsbt != "cHNidP9signed" || view.ArkTxid != arkTxid {
		t.Fatalf("signed view = %+v", view)
	}
	if len(view.CheckpointPsbts) != 0 {
		t.Fatalf("signed view leaked checkpoints: %+v", view.CheckpointPsbts)
	}
}

func TestGetVtxoOperationViewAbortsExpiredReservation(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	now := e.svc.vtxoNow()
	digest := bytes.Repeat([]byte{0x33}, 32)
	feePolicyDigest := bytes.Repeat([]byte{0x44}, 32)
	changeVout := uint32(1)
	in := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x11}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}
	if err := e.ledger.ReserveVtxoOperation(context.Background(), policy.VtxoOperation{
		OperationID: "spend-expired", VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend, BundleDigest: digest,
		State: policy.VtxoStateReserved, AmountSats: 10_000, FeePolicyDigest: feePolicyDigest,
		DestScript: bytes.Repeat([]byte{0x51}, 34), ChangeScript: bytes.Clone(tree.PkScript), ChangeSats: 10_000, ChangeVout: &changeVout,
		ExpiresAt: now.Add(-time.Second).Format(timeRFC3339), CreatedAt: now.Add(-2 * time.Minute).Format(timeRFC3339),
	}, []policy.VtxoOperationInput{in}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-expired")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateAborted {
		t.Fatalf("expired reservation = %+v", view)
	}
	stored, err := e.ledger.GetVtxoOperation(context.Background(), "spend-expired")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != policy.VtxoStateAborted {
		t.Fatalf("expired reservation was not persisted aborted: %s", stored.State)
	}
}

const timeRFC3339 = "2006-01-02T15:04:05Z"
