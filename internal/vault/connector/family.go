package connector

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

const Template = "phone-connector-recovery-savings-v1"

// Family contains the complete recovery family and its new normal path. The
// old phone+hardware admin leaf is replaced, not retained as a parallel path.
// Enrollment must commit this template and all key origins before funding.
type Family struct {
	Recovery               *savings.Family
	Rules                  Rules
	Program, Leaf, Control []byte
	Normal                 savings.TweakPair
}

func BuildFamily(in savings.FamilyInput, kind Kind) (*Family, error) {
	if !in.ServerFreeClawback {
		return nil, fmt.Errorf("connector family requires server-free clawback")
	}
	if in.TemplateVersion != "" && in.TemplateVersion != Template {
		return nil, fmt.Errorf("connector template mismatch")
	}
	in.TemplateVersion = Template
	// Preserve the existing pending and quarantine construction, including its
	// actual initiation cosigners and server-free clawback behavior.
	base, err := savings.BuildFamily(in)
	if err != nil {
		return nil, err
	}
	var net *chaincfg.Params
	switch in.Network {
	case "mainnet":
		net = &chaincfg.MainNetParams
	case "mutinynet":
		net = &chaincfg.SigNetParams
	default:
		return nil, fmt.Errorf("unsupported connector network")
	}
	reserve, err := kind.Script(in.Hardware)
	if err != nil {
		return nil, err
	}
	r := Rules{ConnectorScript: reserve, AbsoluteFeeCapSats: in.SpendingPolicy.AbsoluteFeeCapSats, FeerateCapSatPerV: in.SpendingPolicy.FeerateCapSatPerV}
	roles := []string{"phone", "hardware"}
	if in.Recovery != nil {
		roles = append(roles, "recovery")
	}
	pubs := map[string]*btcec.PublicKey{"phone": in.Phone, "hardware": in.Hardware, "recovery": in.Recovery}
	// First construct the exact tree shape to measure its normal witness.
	normal, err := savings.Checksig(in.Phone, in.VaultCosignerBase, in.ArkadeCosignerBase)
	if err != nil {
		return nil, err
	}
	leaves := []txscript.TapLeaf{txscript.NewBaseTapLeaf(normal)}
	for _, role := range roles {
		pair := base.Initiate[role]
		script, err := savings.Checksig(pubs[role], pair.Vault, pair.Arkade)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, txscript.NewBaseTapLeaf(script))
	}
	internal, err := savings.ContextInternalKeyTemplate(in.VaultID, "savings", "", Template)
	if err != nil {
		return nil, err
	}
	proof := func(leaves []txscript.TapLeaf) ([]byte, []byte, error) {
		tree := txscript.AssembleTaprootScriptTree(leaves...)
		root := tree.RootNode.TapHash()
		out := txscript.ComputeTaprootOutputKey(internal, root[:])
		script, err := txscript.PayToTaprootScript(out)
		if err != nil {
			return nil, nil, err
		}
		control := tree.LeafMerkleProofs[tree.LeafProofIndex[leaves[0].TapHash()]].ToControlBlock(internal)
		encoded, err := control.ToBytes()
		return script, encoded, err
	}
	_, control, err := proof(leaves)
	if err != nil {
		return nil, err
	}
	r.WitnessBytes = WitnessBytes(normal, control, kind)
	policy, err := BuildProgram(r)
	if err != nil {
		return nil, err
	}
	hash := arkade.ArkadeScriptHash(policy)
	pair := savings.TweakPair{Vault: arkade.ComputeArkadeScriptPublicKey(in.VaultCosignerBase, hash), Arkade: arkade.ComputeArkadeScriptPublicKey(in.ArkadeCosignerBase, hash)}
	all := []*btcec.PublicKey{in.Phone, in.Hardware, in.VaultCosignerBase, in.ArkadeCosignerBase, pair.Vault, pair.Arkade}
	if in.Recovery != nil {
		all = append(all, in.Recovery)
	}
	for _, role := range roles {
		i, p := base.Initiate[role], base.PendingTweaks[savings.FamilyKey(role)]
		all = append(all, i.Vault, i.Arkade, p.Vault, p.Arkade)
	}
	for i, key := range all {
		if key == nil {
			return nil, fmt.Errorf("degenerate connector role")
		}
		for _, other := range all[:i] {
			if bytes.Equal(schnorr.SerializePubKey(key), schnorr.SerializePubKey(other)) {
				return nil, fmt.Errorf("connector family roles must be distinct")
			}
		}
	}
	normal, err = savings.Checksig(in.Phone, pair.Vault, pair.Arkade)
	if err != nil {
		return nil, err
	}
	leaves[0] = txscript.NewBaseTapLeaf(normal)
	script, control, err := proof(leaves)
	if err != nil {
		return nil, err
	}
	if WitnessBytes(normal, control, kind) != r.WitnessBytes {
		return nil, fmt.Errorf("connector witness shape changed")
	}
	addr, err := btcutil.NewAddressTaproot(script[2:], net)
	if err != nil {
		return nil, err
	}
	base.Savings = savings.Tree{Address: addr.EncodeAddress(), PkScript: script}
	return &Family{Recovery: base, Rules: r, Program: policy, Leaf: normal, Control: control, Normal: pair}, nil
}
