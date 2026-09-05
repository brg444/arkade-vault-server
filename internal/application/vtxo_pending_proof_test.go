package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func pendingProofForInputs(
	t *testing.T,
	message string,
	inputs []policy.VtxoOperationInput,
	tree *vtxoPolicyTree,
	phone *btcec.PrivateKey,
) string {
	t.Helper()
	proofInputs := make([]intent.Input, len(inputs))
	for i, input := range inputs {
		hash, err := chainhash.NewHashFromStr(hex.EncodeToString(input.Txid))
		if err != nil {
			t.Fatal(err)
		}
		proofInputs[i] = intent.Input{
			OutPoint:    &wire.OutPoint{Hash: *hash, Index: uint32(input.Vout)},
			Sequence:    wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{Value: input.ValueSats, PkScript: bytes.Clone(input.Script)},
		}
	}
	proof, err := intent.New(message, proofInputs, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof.Unknowns = []*psbt.Unknown{{Key: []byte{0x09}, Value: []byte(message)}}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			Script:       bytes.Clone(tree.SpendLeaf),
			ControlBlock: bytes.Clone(tree.SpendControl),
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		sig, err := signTapLeafAtWithSighash(&proof.Packet, i, phone, tree.SpendLeaf, txscript.SigHashAll)
		if err != nil {
			t.Fatal(err)
		}
		proof.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	}
	raw, err := proof.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func twoPendingProofInputs(f sdkSpendFixture) []policy.VtxoOperationInput {
	second := f.input
	second.Txid = bytes.Repeat([]byte{0x43}, 32)
	second.Vout = 8
	return []policy.VtxoOperationInput{f.input, second}
}

func TestVerifyPhonePendingProofBindsCanonicalOperation(t *testing.T) {
	f := newSDKSpendFixture(t)
	inputs := twoPendingProofInputs(f)
	raw := pendingProofForInputs(t, canonicalGetPendingTxMessage, inputs, f.tree, f.user)
	if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err != nil {
		t.Fatal(err)
	}
	if digest, err := pendingProofDigest(raw); err != nil || len(digest) != 32 {
		t.Fatalf("digest = %x, %v", digest, err)
	}
}

func TestVerifySDK0465PendingProofFixture(t *testing.T) {
	var fixtureData struct {
		SDKVersion string `json:"sdkVersion"`
		Message    string `json:"message"`
		Input      struct {
			Txid      string `json:"txid"`
			Vout      int    `json:"vout"`
			ValueSats int64  `json:"valueSats"`
		} `json:"input"`
		Proof string `json:"proof"`
	}
	raw, err := os.ReadFile("testdata/sdk-0.4.65-pending-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixtureData); err != nil {
		t.Fatal(err)
	}
	if fixtureData.SDKVersion != "0.4.65" || fixtureData.Message != canonicalGetPendingTxMessage {
		t.Fatal("unexpected SDK pending-proof fixture metadata")
	}
	key := func(scalar byte) *btcec.PrivateKey {
		raw := make([]byte, 32)
		raw[31] = scalar
		priv, _ := btcec.PrivKeyFromBytes(raw)
		return priv
	}
	phone, vault, operator := key(1), key(2), key(4)
	device, hardware := key(6), key(7)
	delegate, err := policy.PinnedDelegateXOnly()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := policy.BuildVaultPolicyV1Tree(policy.VaultPolicyV1Params{
		UserPub:              schnorr.SerializePubKey(phone.PubKey()),
		VtxoVaultCosignerPub: schnorr.SerializePubKey(vault.PubKey()),
		ArkdServerPub:        schnorr.SerializePubKey(operator.PubKey()),
		DelegatePub:          delegate,
		ExitDevicePub:        schnorr.SerializePubKey(device.PubKey()),
		ExitHardwarePub:      schnorr.SerializePubKey(hardware.PubKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	tree := &vtxoPolicyTree{
		CosignerPub:  vault.PubKey(),
		ArkdPub:      operator.PubKey(),
		PkScript:     encoded.PkScript,
		SpendLeaf:    encoded.SpendScript,
		SpendControl: encoded.SpendControlBlock,
	}
	txid, err := hex.DecodeString(fixtureData.Input.Txid)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []policy.VtxoOperationInput{{
		Txid: txid, Vout: fixtureData.Input.Vout,
		ValueSats: fixtureData.Input.ValueSats, Script: encoded.PkScript,
	}}
	if err := verifyPhonePendingProof(fixtureData.Proof, inputs, tree, phone.PubKey()); err != nil {
		t.Fatalf("@arkade-os/sdk %s proof: %v", fixtureData.SDKVersion, err)
	}
}

func TestVerifyPhonePendingProofRejectsForeignMissingAndReorderedInputs(t *testing.T) {
	f := newSDKSpendFixture(t)
	inputs := twoPendingProofInputs(f)
	tests := []struct {
		name  string
		proof []policy.VtxoOperationInput
	}{
		{name: "foreign", proof: []policy.VtxoOperationInput{inputs[0], {
			Txid: bytes.Repeat([]byte{0x77}, 32), Vout: 9, ValueSats: inputs[1].ValueSats, Script: bytes.Clone(inputs[1].Script),
		}}},
		{name: "missing", proof: inputs[:1]},
		{name: "reordered equal value", proof: []policy.VtxoOperationInput{inputs[1], inputs[0]}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := pendingProofForInputs(t, canonicalGetPendingTxMessage, test.proof, f.tree, f.user)
			if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err == nil {
				t.Fatal("operation input mutation accepted")
			}
		})
	}
}

func TestVerifyPhonePendingProofRejectsMessageLeafAndSignatureMutations(t *testing.T) {
	f := newSDKSpendFixture(t)
	inputs := []policy.VtxoOperationInput{f.input}
	valid := pendingProofForInputs(t, canonicalGetPendingTxMessage, inputs, f.tree, f.user)
	t.Run("wrong message", func(t *testing.T) {
		raw := pendingProofForInputs(t, `{"type":"get-pending-tx","expire_at":1}`, inputs, f.tree, f.user)
		if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err == nil {
			t.Fatal("wrong message accepted")
		}
	})
	t.Run("extra global metadata", func(t *testing.T) {
		packet, _ := parsePSBT(valid)
		packet.Unknowns = append(packet.Unknowns, &psbt.Unknown{Key: []byte{0xfc, 0x01}, Value: []byte("extra")})
		raw, _ := packet.B64Encode()
		if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err == nil {
			t.Fatal("extra global metadata accepted")
		}
	})
	t.Run("wrong leaf", func(t *testing.T) {
		packet, _ := parsePSBT(valid)
		packet.Inputs[1].TaprootLeafScript[0].Script = bytes.Clone(f.tree.DelegateLeaf)
		raw, _ := packet.B64Encode()
		if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err == nil {
			t.Fatal("wrong leaf accepted")
		}
	})
	t.Run("mutated phone signature", func(t *testing.T) {
		packet, _ := parsePSBT(valid)
		packet.Inputs[1].TaprootScriptSpendSig[0].Signature[0] ^= 1
		raw, _ := packet.B64Encode()
		if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err == nil {
			t.Fatal("mutated phone signature accepted")
		}
	})
	t.Run("extra signature", func(t *testing.T) {
		packet, _ := parsePSBT(valid)
		packet.Inputs[1].TaprootScriptSpendSig = append(
			packet.Inputs[1].TaprootScriptSpendSig,
			cloneSpendSig(packet.Inputs[1].TaprootScriptSpendSig[0]),
		)
		raw, _ := packet.B64Encode()
		if err := verifyPhonePendingProof(raw, inputs, f.tree, f.user.PubKey()); err == nil {
			t.Fatal("extra signature accepted")
		}
	})
}

func TestAuthorizeVtxoSpendLostResponseReturnsIdenticalPendingProof(t *testing.T) {
	e, resolver, operator := vtxoTestEnv(t)
	assertVtxoSpendLostResponse(t, e, resolver, operator.PubKey(), fixture.VaultID)
}

func assertVtxoSpendLostResponse(t *testing.T, e *env, resolver *stubArkResolver, operator *btcec.PublicKey, vaultID string) {
	t.Helper()

	tree, err := e.svc.buildVtxoPolicyTree(vaultID, e.svc.snapshot(vaultID))
	if err != nil {
		t.Fatal(err)
	}
	unroll := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{operator}}
	resolver.checkpoint, err = unroll.Script()
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("31", 32), Vout: 4, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}}
	reserve, err := e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("32", 16), VaultID: vaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDestForPub(t, operator), AmountSats: 10_000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	op, err := e.ledger.GetVtxoOperation(context.Background(), reserve.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := e.ledger.GetVtxoOperationInputs(context.Background(), reserve.OperationID)
	if err != nil {
		t.Fatal(err)
	}

	var originalHash chainhash.Hash
	copy(originalHash[:], inputs[0].Txid)
	checkpointScript, checkpointControl, err := checkpointDestScript(op.CheckpointTapscript, tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	cpTx := wire.NewMsgTx(3)
	cpTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: originalHash, Index: uint32(inputs[0].Vout)},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	cpTx.AddTxOut(&wire.TxOut{Value: inputs[0].ValueSats, PkScript: checkpointScript})
	cpTx.AddTxOut(txutils.AnchorOutput())
	checkpoint, err := psbt.NewFromUnsignedTx(cpTx)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Inputs[0].WitnessUtxo = &wire.TxOut{Value: inputs[0].ValueSats, PkScript: tree.PkScript}
	checkpoint.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: tree.SpendLeaf, ControlBlock: tree.SpendControl, LeafVersion: txscript.BaseLeafVersion,
	}}
	checkpointRaw, err := checkpoint.B64Encode()
	if err != nil {
		t.Fatal(err)
	}

	arkTx := wire.NewMsgTx(3)
	arkTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: cpTx.TxHash(), Index: 0},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	arkTx.AddTxOut(&wire.TxOut{Value: op.AmountSats, PkScript: op.DestScript})
	arkTx.AddTxOut(&wire.TxOut{Value: op.ChangeSats, PkScript: op.ChangeScript})
	arkTx.AddTxOut(txutils.AnchorOutput())
	arkPacket, err := psbt.NewFromUnsignedTx(arkTx)
	if err != nil {
		t.Fatal(err)
	}
	arkPacket.Inputs[0].WitnessUtxo = &wire.TxOut{Value: inputs[0].ValueSats, PkScript: checkpointScript}
	arkPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: tree.SpendLeaf, ControlBlock: checkpointControl, LeafVersion: txscript.BaseLeafVersion,
	}}
	phoneArkSig, err := signTapLeafAt(arkPacket, 0, e.hot, tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	arkPacket.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{phoneArkSig}
	arkRaw, err := arkPacket.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	pendingRaw := pendingProofForInputs(t, canonicalGetPendingTxMessage, inputs, tree, e.hot)
	assertion, err := webauthn.SynthWithSignCount(e.p256, e.credID, op.BundleDigest, fixture.Origin, fixture.RPID, true, true, 7)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.SignDigestLowS(e.direct, op.BundleDigest)
	if err != nil {
		t.Fatal(err)
	}
	req := VtxoAuthorizeRequest{
		VaultID: vaultID, OperationID: op.OperationID,
		BundleDigest: hex.EncodeToString(op.BundleDigest), UnsignedArkPsbt: arkRaw,
		UnsignedCheckpointPsbts: []string{checkpointRaw}, PendingProof: pendingRaw,
		CredentialID: hex.EncodeToString(e.credID), ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature),
		DirectSig: hex.EncodeToString(direct),
	}
	badDirect := req
	badDirect.DirectSig = strings.Repeat("00", 64)
	if _, err := e.svc.AuthorizeVtxoSpend(context.Background(), badDirect); err == nil {
		t.Fatal("invalid direct proof was accepted")
	}
	// The failed direct proof must not consume the authenticator counter.
	first, err := e.svc.AuthorizeVtxoSpend(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Discard first as though the HTTP response was lost, then repeat the
	// exact authenticated request.
	second, err := e.svc.AuthorizeVtxoSpend(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("authorize retry changed response:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.AuthorizedPendingProof == "" {
		t.Fatal("authorized pending proof missing")
	}
	if err := verifyDualSignedPendingProof(first.AuthorizedPendingProof, inputs, tree, e.hot.PubKey()); err != nil {
		t.Fatal(err)
	}
	stored, err := e.ledger.GetVtxoOperation(context.Background(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := pendingProofDigest(pendingRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.PendingProofDigest, wantDigest) || stored.AuthorizedPendingProof != first.AuthorizedPendingProof {
		t.Fatal("pending recovery proof was not durably bound before response")
	}
	view, err := e.svc.GetVtxoOperationView(context.Background(), vaultID, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.AuthorizedPendingProof != first.AuthorizedPendingProof {
		t.Fatal("lost authorize response is not recoverable from operation view")
	}
}
