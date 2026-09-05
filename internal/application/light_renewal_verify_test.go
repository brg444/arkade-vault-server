package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type lightRenewalProofFixture struct {
	env        *env
	plan       lightRenewalPlan
	descriptor light.Descriptor
	tree       *vtxoPolicyTree
	owner      *btcec.PrivateKey
	message    string
}

func newLightRenewalProofFixture(t *testing.T) lightRenewalProofFixture {
	t.Helper()
	f := newLightEnrollmentFixture(t, true)
	st, err := f.env.svc.FinishLightEnrollment(context.Background(), f.token, f.request)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := f.env.svc.buildVtxoPolicyTree(f.start.VaultID, f.env.svc.snapshot(f.start.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	d := *st.LightDescriptor
	hash, err := light.DescriptorDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	plan := lightRenewalPlan{OperationID: strings.Repeat("18", 16), VaultID: d.VaultID, DescriptorHash: hash, Txid: strings.Repeat("51", 32), Vout: 3, ValueSats: 80000, ReceiverSats: 79900, FeeSats: 100, FeePolicyDigest: strings.Repeat("67", 32), RegisterExpireAt: time.Now().Add(time.Minute).Unix()}
	session, _ := btcec.NewPrivateKey()
	message, err := (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, ExpireAt: plan.RegisterExpireAt, CosignersPublicKeys: []string{hex.EncodeToString(session.PubKey().SerializeCompressed())}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return lightRenewalProofFixture{f.env, plan, d, tree, f.env.hot, message}
}
func (f lightRenewalProofFixture) proof(t *testing.T) *psbt.Packet {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(f.plan.Txid)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := intent.New(f.message, []intent.Input{{OutPoint: &wire.OutPoint{Hash: *hash, Index: f.plan.Vout}, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: &wire.TxOut{Value: f.plan.ValueSats, PkScript: f.tree.PkScript}}}, []*wire.TxOut{{Value: f.plan.ReceiverSats, PkScript: f.tree.PkScript}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{ControlBlock: f.tree.SpendControl, Script: f.tree.SpendLeaf, LeafVersion: txscript.BaseLeafVersion}}
		if i == 1 {
			if err := txutils.SetArkPsbtField(&proof.Packet, i, txutils.VtxoTaprootTreeField, txutils.TapTree(f.tree.RevealedScripts)); err != nil {
				t.Fatal(err)
			}
		}
		sig, err := signTapLeafAtWithSighash(&proof.Packet, i, f.owner, f.tree.SpendLeaf, txscript.SigHashAll)
		if err != nil {
			t.Fatal(err)
		}
		proof.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	}
	return &proof.Packet
}
func TestLightRenewalRegistrationBindsOwnerAndSameWallet(t *testing.T) {
	f := newLightRenewalProofFixture(t)
	raw, err := f.proof(t).B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifyLightRenewalRegistration(raw, f.message, f.plan, f.descriptor, f.tree)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := f.plan.digest(f.descriptor)
	if err != nil || !bytes.Equal(result.PlanDigest, digest) || len(result.RequestDigest) != 32 || len(result.TreeSession) != 33 || result.CanonicalPSBT != raw {
		t.Fatal("renewal binding changed")
	}
	// Renewed principal is not a recipient payment and can exceed the payment cap.
	if f.plan.ReceiverSats <= f.descriptor.SpendingPolicy.TxRecipientCapSats {
		t.Fatal("fixture does not exercise full-balance renewal")
	}
	for name, mutate := range map[string]func(*lightRenewalPlan){
		"wallet":     func(p *lightRenewalPlan) { p.VaultID = strings.Repeat("aa", 32) },
		"descriptor": func(p *lightRenewalPlan) { p.DescriptorHash = strings.Repeat("aa", 32) },
		"outpoint":   func(p *lightRenewalPlan) { p.Vout++ },
		"principal":  func(p *lightRenewalPlan) { p.ValueSats++ },
		"receiver":   func(p *lightRenewalPlan) { p.ReceiverSats--; p.FeeSats++ },
		"expiry":     func(p *lightRenewalPlan) { p.RegisterExpireAt++ },
		"fee cap":    func(p *lightRenewalPlan) { p.FeeSats = 5001; p.ReceiverSats = p.ValueSats - p.FeeSats },
	} {
		t.Run(name, func(t *testing.T) {
			p := f.plan
			mutate(&p)
			if _, err := verifyLightRenewalRegistration(raw, f.message, p, f.descriptor, f.tree); err == nil {
				t.Fatal("changed renewal accepted")
			}
		})
	}
}
func TestLightRenewalRejectsPaymentAndProofSubstitution(t *testing.T) {
	f := newLightRenewalProofFixture(t)
	for name, mutate := range map[string]func(*psbt.Packet){
		"missing owner":     func(p *psbt.Packet) { p.Inputs[1].TaprootScriptSpendSig = nil },
		"synthetic owner":   func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig = nil },
		"external receiver": func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_TRUE} },
		"another output": func(p *psbt.Packet) {
			p.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
			p.Outputs = append(p.Outputs, psbt.POutput{})
		},
		"amount":           func(p *psbt.Packet) { p.Inputs[1].WitnessUtxo.Value++ },
		"synthetic amount": func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo.Value = 1 },
		"sequence":         func(p *psbt.Packet) { p.UnsignedTx.TxIn[1].Sequence-- },
		"sighash":          func(p *psbt.Packet) { p.Inputs[1].SighashType = txscript.SigHashSingle },
		"tree":             func(p *psbt.Packet) { p.Inputs[1].Unknowns = nil },
		"message":          func(p *psbt.Packet) { p.Unknowns[0].Value = []byte("other") },
	} {
		t.Run(name, func(t *testing.T) {
			p := f.proof(t)
			mutate(p)
			raw, err := p.B64Encode()
			if err != nil {
				return
			}
			if _, err := verifyLightRenewalRegistration(raw, f.message, f.plan, f.descriptor, f.tree); err == nil {
				t.Fatal("invalid renewal accepted")
			}
		})
	}
}
