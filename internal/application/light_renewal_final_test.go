package application

import (
	"bytes"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func newLightRenewalFinalFixture(t *testing.T) (lightRenewalProofFixture, verifiedLightRenewalRegistration, lightRenewalFinalEvidence) {
	t.Helper()
	f := newLightRenewalProofFixture(t)
	sessionKey, _ := btcec.NewPrivateKey()
	operatorSessionKey, _ := btcec.NewPrivateKey()
	f.message, _ = (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, ExpireAt: f.plan.RegisterExpireAt, CosignersPublicKeys: []string{hex.EncodeToString(sessionKey.PubKey().SerializeCompressed())}}).Encode()
	raw, _ := f.proof(t).B64Encode()
	registered, err := verifyLightRenewalRegistration(raw, f.message, f.plan, f.descriptor, f.tree)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := deployment.IdentityFor(f.descriptor.Network)
	if err != nil {
		t.Fatal(err)
	}
	forfeitPub, err := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	if err != nil {
		t.Fatal(err)
	}
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: pins.VtxoTreeExpirySeconds}
	sweep := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPub}}, Locktime: expiry}
	sweepScript, err := sweep.Script()
	if err != nil {
		t.Fatal(err)
	}
	root := txscript.NewBaseTapLeaf(sweepScript).TapHash()
	leaves := []arktree.Leaf{{Outputs: []arktree.LeafOutput{{Amount: uint64(f.plan.ReceiverSats), Script: hex.EncodeToString(f.tree.PkScript)}}, CosignersPublicKeys: []string{hex.EncodeToString(sessionKey.PubKey().SerializeCompressed()), hex.EncodeToString(operatorSessionKey.PubKey().SerializeCompressed())}}}
	batchScript, batchAmount, err := arktree.BuildBatchOutput(leaves, root[:])
	if err != nil {
		t.Fatal(err)
	}
	connectorKey, _ := btcec.NewPrivateKey()
	connectorScript, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(connectorKey.PubKey()))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := psbt.New([]*wire.OutPoint{{Hash: chainhash.Hash{7}, Index: 0}}, []*wire.TxOut{{Value: batchAmount, PkScript: batchScript}, {Value: 330, PkScript: connectorScript}}, 2, 0, []uint32{wire.MaxTxInSequenceNum})
	if err != nil {
		t.Fatal(err)
	}
	vtxos, err := arktree.BuildVtxoTree(&wire.OutPoint{Hash: commitment.UnsignedTx.TxHash(), Index: 0}, leaves, root[:], expiry)
	if err != nil {
		t.Fatal(err)
	}

	coordinator, err := arktree.NewTreeCoordinatorSession(root[:], batchAmount, vtxos)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[*btcec.PrivateKey]arktree.SignerSession{}
	for _, key := range []*btcec.PrivateKey{sessionKey, operatorSessionKey} {
		session := arktree.NewTreeSignerSession(key)
		if err := session.Init(root[:], batchAmount, vtxos); err != nil {
			t.Fatal(err)
		}
		nonces, err := session.GetNonces()
		if err != nil {
			t.Fatal(err)
		}
		coordinator.AddNonce(key.PubKey(), nonces)
		sessions[key] = session
	}
	aggregate, err := coordinator.AggregateNonces()
	if err != nil {
		t.Fatal(err)
	}
	for key, session := range sessions {
		session.SetAggregatedNonces(aggregate)
		signatures, err := session.Sign()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.AddSignatures(key.PubKey(), signatures); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := coordinator.SignTree()
	if err != nil {
		t.Fatal(err)
	}
	flat, err := signed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	connector, err := psbt.New([]*wire.OutPoint{{Hash: commitment.UnsignedTx.TxHash(), Index: 1}}, []*wire.TxOut{{Value: 330, PkScript: connectorScript}, txutils.AnchorOutput()}, 3, 0, []uint32{wire.MaxTxInSequenceNum})
	if err != nil {
		t.Fatal(err)
	}
	connector.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 330, PkScript: connectorScript}
	connectorRaw, _ := connector.B64Encode()
	old, _ := chainhash.NewHashFromStr(f.plan.Txid)
	forfeitScript := append([]byte{txscript.OP_0, 0x14}, btcutil.Hash160(forfeitPub.SerializeCompressed())...)
	forfeit, err := arktree.BuildForfeitTx([]*wire.OutPoint{{Hash: *old, Index: f.plan.Vout}, {Hash: connector.UnsignedTx.TxHash(), Index: 0}}, []uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum}, []*wire.TxOut{{Value: f.plan.ValueSats, PkScript: f.tree.PkScript}, {Value: 330, PkScript: connectorScript}}, forfeitScript, 0)
	if err != nil {
		t.Fatal(err)
	}
	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{Script: f.tree.SpendLeaf, ControlBlock: f.tree.SpendControl, LeafVersion: txscript.BaseLeafVersion}}
	sig, err := signTapLeafAt(forfeit, 0, f.owner, f.tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	forfeitRaw, _ := forfeit.B64Encode()
	commitmentRaw, _ := commitment.B64Encode()
	evidence := lightRenewalFinalEvidence{BatchID: "renewal-batch", BatchExpiry: pins.VtxoTreeExpirySeconds, CommitmentPSBT: commitmentRaw, VtxoTree: flat, Connectors: arktree.FlatTxTree{{Txid: connector.UnsignedTx.TxID(), Tx: connectorRaw, Children: map[uint32]string{}}}, OwnerForfeitPSBT: forfeitRaw}
	return f, registered, evidence
}

func TestLightRenewalForfeitRequiresSignedProtectedReplacement(t *testing.T) {
	f, registered, e := newLightRenewalFinalFixture(t)
	result, err := verifyLightRenewalFinal(e, f.plan, f.descriptor, f.tree, registered)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RequestDigest) != 32 || result.CommitmentTxid == "" || result.ReceiverTxid == "" || result.CanonicalForfeitPSBT != e.OwnerForfeitPSBT {
		t.Fatal("missing final binding")
	}
	replay, err := verifyLightRenewalFinal(e, f.plan, f.descriptor, f.tree, registered)
	if err != nil || !bytes.Equal(replay.RequestDigest, result.RequestDigest) {
		t.Fatal("final replay changed")
	}
}

func TestLightRenewalForfeitRejectsIncompleteOrChangedBatch(t *testing.T) {
	f, registered, original := newLightRenewalFinalFixture(t)
	for name, mutate := range map[string]func(*lightRenewalFinalEvidence){
		"missing replacement signatures": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.VtxoTree[0].Tx)
			p.Inputs[0].TaprootKeySpendSig = nil
			e.VtxoTree[0].Tx, _ = p.B64Encode()
		},
		"invalid replacement signatures": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.VtxoTree[0].Tx)
			p.Inputs[0].TaprootKeySpendSig = bytes.Repeat([]byte{7}, 64)
			e.VtxoTree[0].Tx, _ = p.B64Encode()
		},
		"wrong expiry": func(e *lightRenewalFinalEvidence) { e.BatchExpiry++ },
		"different commitment": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.CommitmentPSBT)
			p.UnsignedTx.TxIn[0].PreviousOutPoint.Index++
			e.CommitmentPSBT, _ = p.B64Encode()
		},
		"missing connector": func(e *lightRenewalFinalEvidence) { e.Connectors = nil },
		"forfeit receiver": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.OwnerForfeitPSBT)
			p.UnsignedTx.TxOut[0].PkScript = f.tree.PkScript
			e.OwnerForfeitPSBT, _ = p.B64Encode()
		},
		"forfeit fee": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.OwnerForfeitPSBT)
			p.UnsignedTx.TxOut[0].Value--
			e.OwnerForfeitPSBT, _ = p.B64Encode()
		},
		"forfeit outpoint": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.OwnerForfeitPSBT)
			p.UnsignedTx.TxIn[0].PreviousOutPoint.Index++
			e.OwnerForfeitPSBT, _ = p.B64Encode()
		},
		"forfeit owner": func(e *lightRenewalFinalEvidence) {
			p, _ := parsePSBT(e.OwnerForfeitPSBT)
			p.Inputs[0].TaprootScriptSpendSig = nil
			e.OwnerForfeitPSBT, _ = p.B64Encode()
		},
		"tree self reference": func(e *lightRenewalFinalEvidence) { e.VtxoTree[0].Children = map[uint32]string{0: e.VtxoTree[0].Txid} },
	} {
		t.Run(name, func(t *testing.T) {
			e := original
			e.VtxoTree = append(arktree.FlatTxTree(nil), original.VtxoTree...)
			e.Connectors = append(arktree.FlatTxTree(nil), original.Connectors...)
			mutate(&e)
			if _, err := verifyLightRenewalFinal(e, f.plan, f.descriptor, f.tree, registered); err == nil {
				t.Fatal("invalid final authorization accepted")
			}
		})
	}
}
