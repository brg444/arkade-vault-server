package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type lightRenewalFinalEvidence struct {
	BatchID          string             `json:"batchId"`
	BatchExpiry      uint32             `json:"batchExpiry"`
	CommitmentPSBT   string             `json:"commitmentPsbt"`
	VtxoTree         arktree.FlatTxTree `json:"vtxoTree"`
	Connectors       arktree.FlatTxTree `json:"connectors"`
	OwnerForfeitPSBT string             `json:"ownerForfeitPsbt"`
}

type verifiedLightRenewalFinal struct {
	RequestDigest        []byte
	CanonicalForfeitPSBT string
	CommitmentTxid       string
	ReceiverTxid         string
	ReceiverVout         uint32
}

// Bound graph shape before invoking recursive protocol-library traversal.
func canonicalLightRenewalTree(supplied arktree.FlatTxTree) (arktree.FlatTxTree, *arktree.TxTree, error) {
	flat, err := canonicalVaultBoardTree(supplied)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]arktree.TxTreeNode, len(flat))
	parents := make(map[string]int, len(flat))
	for _, node := range flat {
		p, err := parseCanonicalVaultBoardPSBT(node.Tx, maxVaultBoardProofBytes)
		if err != nil || len(p.Inputs) != 1 || len(p.UnsignedTx.TxIn) != 1 || len(p.UnsignedTx.TxOut) == 0 || len(p.UnsignedTx.TxOut) > 512 {
			return nil, nil, fmt.Errorf("Light renewal graph transaction shape")
		}
		var total int64
		for _, out := range p.UnsignedTx.TxOut {
			if out.Value < 0 || out.Value > 21_000_000*100_000_000 || total > 21_000_000*100_000_000-out.Value || len(out.PkScript) > 10000 {
				return nil, nil, fmt.Errorf("Light renewal graph output bounds")
			}
			total += out.Value
		}
		byID[node.Txid] = node
		for index, child := range node.Children {
			if int64(index) >= int64(len(p.UnsignedTx.TxOut)) || child == node.Txid {
				return nil, nil, fmt.Errorf("Light renewal graph edge")
			}
			parents[child]++
			if parents[child] > 1 {
				return nil, nil, fmt.Errorf("Light renewal graph repeated child")
			}
		}
	}
	roots := []string{}
	for _, node := range flat {
		if parents[node.Txid] == 0 {
			roots = append(roots, node.Txid)
		}
	}
	if len(roots) != 1 {
		return nil, nil, fmt.Errorf("Light renewal graph root")
	}
	queue := append([]string(nil), roots...)
	seen := make(map[string]bool, len(flat))
	for len(queue) > 0 {
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[id] {
			return nil, nil, fmt.Errorf("Light renewal graph cycle")
		}
		seen[id] = true
		for _, child := range byID[id].Children {
			queue = append(queue, child)
		}
	}
	if len(seen) != len(flat) {
		return nil, nil, fmt.Errorf("Light renewal graph disconnected")
	}
	graph, err := arktree.NewTxTree(flat)
	return flat, graph, err
}

// The forfeit is released only against a fully signed replacement VTXO path
// with the same enrolled script and exact post-fee balance. Its connector must
// spend the same commitment, so it cannot execute independently of that batch.
func verifyLightRenewalFinal(e lightRenewalFinalEvidence, plan lightRenewalPlan, d light.Descriptor, tree *vtxoPolicyTree, registration verifiedLightRenewalRegistration) (verifiedLightRenewalFinal, error) {
	digest, err := plan.digest(d)
	if err != nil || !bytes.Equal(digest, registration.PlanDigest) || len(registration.TreeSession) != 33 {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal registration binding")
	}
	if tree == nil || tree.DelegatePub != nil || hex.EncodeToString(tree.PkScript) != d.ScriptPubKey || len(e.BatchID) == 0 || len(e.BatchID) > 256 {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal batch identity")
	}
	pins, err := deployment.IdentityFor(d.Network)
	if err != nil || e.BatchExpiry != pins.VtxoTreeExpirySeconds {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal batch expiry")
	}
	commitment, err := parseCanonicalVaultBoardPSBT(e.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || commitment.UnsignedTx.Version != 2 || commitment.UnsignedTx.LockTime != 0 || len(commitment.UnsignedTx.TxOut) < 2 {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal commitment")
	}
	flat, vtxos, err := canonicalLightRenewalTree(e.VtxoTree)
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	forfeitPub, err := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: e.BatchExpiry}
	if err := arktree.ValidateVtxoTree(vtxos, commitment, forfeitPub, expiry); err != nil {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal replacement tree: %w", err)
	}
	if err := verifyVaultBoardBatchOutput(vtxos, commitment, forfeitPub, expiry); err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	sweep := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPub}}, Locktime: expiry}
	sweepScript, err := sweep.Script()
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	sweepRoot := txscript.NewBaseTapLeaf(sweepScript).TapHash()
	if err := arktree.ValidateTreeSigs(sweepRoot[:], commitment.UnsignedTx.TxOut[0].Value, vtxos); err != nil {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal requires signed recovery paths: %w", err)
	}
	receiverTxid, receiverVout, err := findExactVaultBoardReceiver(vtxos, tree.PkScript, plan.ReceiverSats)
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	for _, leaf := range vtxos.Leaves() {
		if leaf.UnsignedTx.TxID() != receiverTxid {
			continue
		}
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(leaf, 0)
		// Stock batches add an ephemeral Operator tree-signing key to the
		// registered session key. Both signatures are verified above.
		ownsSession := false
		for _, key := range keys {
			if bytes.Equal(key.SerializeCompressed(), registration.TreeSession) {
				ownsSession = true
			}
		}
		if err != nil || len(keys) != 2 || !ownsSession || bytes.Equal(keys[0].SerializeCompressed()[1:], keys[1].SerializeCompressed()[1:]) {
			return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal receiver session changed")
		}
	}
	connectorFlat, connectors, err := canonicalLightRenewalTree(e.Connectors)
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	if err := connectors.Validate(); err != nil {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal connector graph: %w", err)
	}
	rootInput := connectors.Root.UnsignedTx.TxIn[0].PreviousOutPoint
	if rootInput.Hash != commitment.UnsignedTx.TxHash() || rootInput.Index != 1 {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal connector commitment changed")
	}
	var connectorTotal int64
	for _, out := range connectors.Root.UnsignedTx.TxOut {
		connectorTotal += out.Value
	}
	if connectorTotal != commitment.UnsignedTx.TxOut[1].Value {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal connector amount changed")
	}
	p, err := parseCanonicalVaultBoardPSBT(e.OwnerForfeitPSBT, maxVaultBoardProofBytes)
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	if p.UnsignedTx.Version != 3 || p.UnsignedTx.LockTime != 0 || len(p.Inputs) != 2 || len(p.UnsignedTx.TxIn) != 2 || len(p.Outputs) != 2 || len(p.UnsignedTx.TxOut) != 2 || len(p.Unknowns) != 0 {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal forfeit shape")
	}
	old := p.UnsignedTx.TxIn[0].PreviousOutPoint
	if old.Hash.String() != plan.Txid || old.Index != plan.Vout {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal forfeit input changed")
	}
	var connector *wire.TxOut
	funding := p.UnsignedTx.TxIn[1].PreviousOutPoint
	for _, leaf := range connectors.Leaves() {
		if funding.Hash == leaf.UnsignedTx.TxHash() && funding.Index == 0 {
			connector = leaf.UnsignedTx.TxOut[0]
		}
	}
	if connector == nil || connector.Value < 330 || connector.Value > 21_000_000*100_000_000-plan.ValueSats {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal connector leaf")
	}
	for i, want := range []*wire.TxOut{{Value: plan.ValueSats, PkScript: tree.PkScript}, connector} {
		input := p.Inputs[i]
		if p.UnsignedTx.TxIn[i].Sequence != wire.MaxTxInSequenceNum || input.WitnessUtxo == nil || input.WitnessUtxo.Value != want.Value || !bytes.Equal(input.WitnessUtxo.PkScript, want.PkScript) {
			return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal forfeit prevout %d", i)
		}
	}
	owner := mustDecodeRenewalHex(d.OwnerPub)
	if err := requireExactLeafWithSighash(p.Inputs[0], tree.PkScript, tree.SpendLeaf, tree.SpendControl, [][]byte{owner}, txscript.SigHashDefault); err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	if err := requireVerifiedSignersWithSighash(p, 0, [][]byte{owner}, tree.SpendLeaf, txscript.SigHashDefault); err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	if len(p.Inputs[1].TaprootScriptSpendSig) != 0 || len(p.Inputs[1].TaprootKeySpendSig) != 0 || len(p.Inputs[1].PartialSigs) != 0 || len(p.Inputs[1].FinalScriptWitness) != 0 || len(p.Inputs[1].TaprootLeafScript) != 0 {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal connector must remain unsigned")
	}
	forfeited := p.UnsignedTx.TxOut[0]
	forfeitScript := append([]byte{txscript.OP_0, 0x14}, btcutil.Hash160(forfeitPub.SerializeCompressed())...)
	anchor := txutils.AnchorOutput()
	if forfeited.Value != plan.ValueSats+connector.Value-anchor.Value || !bytes.Equal(forfeited.PkScript, forfeitScript) || p.UnsignedTx.TxOut[1].Value != anchor.Value || !bytes.Equal(p.UnsignedTx.TxOut[1].PkScript, anchor.PkScript) {
		return verifiedLightRenewalFinal{}, fmt.Errorf("Light renewal forfeit destination or amount")
	}
	e.VtxoTree = flat
	e.Connectors = connectorFlat
	raw, err := json.Marshal(struct {
		Plan     string                    `json:"plan"`
		Evidence lightRenewalFinalEvidence `json:"evidence"`
	}{hex.EncodeToString(digest), e})
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	sum := sha256.Sum256(append([]byte("vaulted-light/renewal-final/v1:"), raw...))
	return verifiedLightRenewalFinal{sum[:], e.OwnerForfeitPSBT, commitment.UnsignedTx.TxID(), receiverTxid, receiverVout}, nil
}

func mustDecodeRenewalHex(encoded string) []byte { raw, _ := hex.DecodeString(encoded); return raw }
