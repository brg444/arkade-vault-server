package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const lightRenewalDigestDomain = "vaulted-light/renewal-plan/v1"

// A renewal replaces exactly one live output with the same enrolled script.
// Amounts and the fee policy are pinned from the indexer before this plan is
// persisted. This verifier alone grants no signing capability or HTTP route.
type lightRenewalPlan struct {
	OperationID      string `json:"operationId"`
	VaultID          string `json:"vaultId"`
	DescriptorHash   string `json:"descriptorHash"`
	Txid             string `json:"txid"`
	Vout             uint32 `json:"vout"`
	ValueSats        int64  `json:"valueSats"`
	ReceiverSats     int64  `json:"receiverSats"`
	FeeSats          int64  `json:"feeSats"`
	FeePolicyDigest  string `json:"feePolicyDigest"`
	RegisterExpireAt int64  `json:"registerExpireAt"`
}

func (p lightRenewalPlan) digest(d light.Descriptor) ([]byte, error) {
	hash, err := light.DescriptorDigest(d)
	if err != nil || hash != p.DescriptorHash || p.VaultID != d.VaultID || requireTxid(p.Txid) != nil || requireTxid(p.FeePolicyDigest) != nil {
		return nil, fmt.Errorf("Light renewal identity mismatch")
	}
	op, err := hex.DecodeString(p.OperationID)
	if err != nil || len(op) != 16 || hex.EncodeToString(op) != p.OperationID || p.ValueSats <= 0 || p.ValueSats > 21_000_000*100_000_000 || p.ReceiverSats < 330 || p.ReceiverSats > p.ValueSats || p.FeeSats < 0 || p.ValueSats-p.ReceiverSats != p.FeeSats || p.FeeSats > d.SpendingPolicy.AbsoluteFeeCapSats || p.RegisterExpireAt <= 0 || p.RegisterExpireAt > (1<<53)-1 {
		return nil, fmt.Errorf("Light renewal amounts or operation mismatch")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(lightRenewalDigestDomain+":"), raw...))
	return sum[:], nil
}

type verifiedLightRenewalRegistration struct {
	PlanDigest    []byte
	RequestDigest []byte
	TreeSession   []byte
	CanonicalPSBT string
	Message       string
}

// Registration proof is a bounded BIP-322 intent, never a payment PSBT. Both
// the synthetic input and the one real input must carry the owner's exact
// cooperative leaf signature. The renewal receiver cannot leave this wallet.
func verifyLightRenewalRegistration(raw, message string, plan lightRenewalPlan, d light.Descriptor, tree *vtxoPolicyTree) (verifiedLightRenewalRegistration, error) {
	digest, err := plan.digest(d)
	if err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	if tree == nil || tree.DelegatePub != nil || tree.CosignerPub == nil || tree.ArkdPub == nil || hex.EncodeToString(tree.PkScript) != d.ScriptPubKey || len(tree.RevealedScripts) != 2 {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal script required")
	}
	var register intent.RegisterMessage
	if err := register.Decode(message); err != nil {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal register message")
	}
	canonical, err := register.Encode()
	if err != nil || canonical != message || register.ExpireAt != plan.RegisterExpireAt || register.ValidAt != 0 || register.OnchainOutputIndexes == nil || len(register.OnchainOutputIndexes) != 0 || len(register.CosignersPublicKeys) != 1 {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal registration conditions")
	}
	session, err := hex.DecodeString(register.CosignersPublicKeys[0])
	if err != nil || len(session) != 33 || hex.EncodeToString(session) != register.CosignersPublicKeys[0] {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal tree session")
	}
	if _, err := btcec.ParsePubKey(session); err != nil {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal tree session")
	}
	packet, err := parseCanonicalVaultBoardPSBT(raw, maxVaultBoardProofBytes)
	if err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	if packet.UnsignedTx.Version != 2 || packet.UnsignedTx.LockTime != 0 || len(packet.Inputs) != 2 || len(packet.UnsignedTx.TxIn) != 2 || len(packet.Outputs) != 1 || len(packet.UnsignedTx.TxOut) != 1 || len(packet.Unknowns) != 1 || packet.Unknowns[0] == nil || !bytes.Equal(packet.Unknowns[0].Key, []byte{0x09}) || !bytes.Equal(packet.Unknowns[0].Value, []byte(message)) {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal proof shape")
	}
	previous := packet.UnsignedTx.TxIn[1].PreviousOutPoint
	if previous.Hash.String() != plan.Txid || previous.Index != plan.Vout || packet.UnsignedTx.TxOut[0].Value != plan.ReceiverSats || !bytes.Equal(packet.UnsignedTx.TxOut[0].PkScript, tree.PkScript) {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal exact input and receiver required")
	}
	owner, err := hex.DecodeString(d.OwnerPub)
	if err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	for i, input := range packet.Inputs {
		value := int64(0)
		if i == 1 {
			value = plan.ValueSats
		}
		if packet.UnsignedTx.TxIn[i].Sequence != wire.MaxTxInSequenceNum || input.WitnessUtxo == nil || input.WitnessUtxo.Value != value || !bytes.Equal(input.WitnessUtxo.PkScript, tree.PkScript) {
			return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal prevout %d", i)
		}
		if err := requireExactLeafWithSighash(input, tree.PkScript, tree.SpendLeaf, tree.SpendControl, [][]byte{owner}, txscript.SigHashAll); err != nil {
			return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal leaf: %w", err)
		}
		if err := requireVerifiedSignersWithSighash(packet, i, [][]byte{owner}, tree.SpendLeaf, txscript.SigHashAll); err != nil {
			return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal owner proof: %w", err)
		}
		fields, err := txutils.GetArkPsbtFields(packet, i, txutils.VtxoTaprootTreeField)
		if err != nil {
			return verifiedLightRenewalRegistration{}, err
		}
		if i == 0 {
			if len(fields) != 0 {
				return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal synthetic tree")
			}
		} else {
			if len(fields) != 1 || len(fields[0]) != len(tree.RevealedScripts) {
				return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal revealed tree")
			}
			for j, script := range tree.RevealedScripts {
				if fields[0][j] != script {
					return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal revealed tree changed")
				}
			}
		}
	}
	if err := intent.Verify(raw, message, []*btcec.PublicKey{tree.CosignerPub, tree.ArkdPub}); err != nil {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Light renewal BIP-322 proof: %w", err)
	}
	encoded, err := json.Marshal(struct {
		Plan    string `json:"plan"`
		PSBT    string `json:"psbt"`
		Message string `json:"message"`
	}{hex.EncodeToString(digest), raw, message})
	if err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	request := sha256.Sum256(append([]byte("vaulted-light/renewal-register/v1:"), encoded...))
	return verifiedLightRenewalRegistration{PlanDigest: digest, RequestDigest: request[:], TreeSession: session, CanonicalPSBT: raw, Message: message}, nil
}
