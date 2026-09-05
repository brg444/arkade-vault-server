// Package light implements the candidate Light contract. It is not mounted in
// the production profile and cannot enroll, reserve, or sign live funds.
package light

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const (
	Profile          = "vaulted-light-v1"
	Program          = "vault-light-policy-v1"
	PolicySchema     = "vault-light-spending-policy-v1"
	DescriptorSchema = "vaulted-light/descriptor-v1"
)

// Policy preserves the numeric policy semantics with a separate program domain.
type Policy program.SpendingPolicy

func DefaultPolicy(network string) (Policy, error) {
	p, err := program.DefaultSpendingPolicyFor(network)
	if err != nil {
		return Policy{}, err
	}
	p.Program, p.Schema = Program, PolicySchema
	return Policy(p), nil
}

func ValidatePolicy(network string, p Policy) error {
	if p.Program != Program || p.Schema != PolicySchema {
		return fmt.Errorf("unsupported Light policy")
	}
	base := program.SpendingPolicy(p)
	base.Program, base.Schema = program.SpendingPolicyProgram, program.PolicyVersion
	return program.ValidateSpendingPolicyFor(network, base)
}

func PolicyDigest(network string, p Policy) (string, error) {
	if err := ValidatePolicy(network, p); err != nil {
		return "", err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type Params struct {
	Network          string `json:"network"`
	OwnerPub         string `json:"ownerPub"`
	CosignerPub      string `json:"cosignerPub"`
	OperatorPub      string `json:"operatorPub"`
	ExitDelaySeconds uint32 `json:"exitDelaySeconds"`
}

func operatorFor(network string) string {
	switch network {
	case program.NetworkMainnet:
		return "8202bebddeb1f7442803897a85eaf3ce9254d07df0172fc3725ab5f0d097779c"
	case program.NetworkMutinynet:
		return "301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a"
	default:
		return ""
	}
}

func parseKey(value string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value {
		return nil, fmt.Errorf("Light key must be x-only hex")
	}
	return schnorr.ParsePubKey(raw)
}

func ValidateParams(p Params) error {
	pins, err := program.PinsFor(p.Network)
	if err != nil {
		return err
	}
	for _, value := range []string{p.OwnerPub, p.CosignerPub, p.OperatorPub} {
		if _, err := parseKey(value); err != nil {
			return err
		}
	}
	if p.OwnerPub == p.CosignerPub || p.OwnerPub == p.OperatorPub || p.CosignerPub == p.OperatorPub {
		return fmt.Errorf("Light signing keys must be distinct")
	}
	if p.OperatorPub != operatorFor(p.Network) {
		return fmt.Errorf("Light Operator does not match network pin")
	}
	if p.ExitDelaySeconds != pins.PolicyExitDelay {
		return fmt.Errorf("Light exit delay does not match network pin")
	}
	return nil
}

type Tree struct {
	SpendScript       []byte
	ExitScript        []byte
	SpendControlBlock []byte
	ExitControlBlock  []byte
	TapKey            []byte
	PkScript          []byte
}

func BuildTree(p Params) (*Tree, error) {
	if err := ValidateParams(p); err != nil {
		return nil, err
	}
	owner, _ := parseKey(p.OwnerPub)
	cosigner, _ := parseKey(p.CosignerPub)
	operator, _ := parseKey(p.OperatorPub)
	spend := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{owner, cosigner, operator}}
	exit := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{owner}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: p.ExitDelaySeconds},
	}
	tree := &arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{spend, exit}}
	tapKey, tapTree, err := tree.TapTree()
	if err != nil {
		return nil, err
	}
	pkScript, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return nil, err
	}
	spendScript, err := spend.Script()
	if err != nil {
		return nil, err
	}
	exitScript, err := exit.Script()
	if err != nil {
		return nil, err
	}
	spendProof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(spendScript).TapHash())
	if err != nil {
		return nil, err
	}
	exitProof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(exitScript).TapHash())
	if err != nil {
		return nil, err
	}
	return &Tree{spendScript, exitScript, spendProof.ControlBlock, exitProof.ControlBlock, schnorr.SerializePubKey(tapKey), pkScript}, nil
}

type Descriptor struct {
	Schema  string `json:"schema"`
	Profile string `json:"profile"`
	Program string `json:"program"`
	VaultID string `json:"vaultId"`
	Params
	SpendingPolicy       Policy `json:"spendingPolicy"`
	SpendingPolicyDigest string `json:"spendingPolicyDigest"`
	ScriptPubKey         string `json:"scriptPubKey"`
}

func BuildDescriptor(id string, params Params, p Policy) (Descriptor, error) {
	rawID, err := hex.DecodeString(id)
	if err != nil || len(rawID) != 32 || hex.EncodeToString(rawID) != id {
		return Descriptor{}, fmt.Errorf("Light vault ID must be 32-byte hex")
	}
	tree, err := BuildTree(params)
	if err != nil {
		return Descriptor{}, err
	}
	digest, err := PolicyDigest(params.Network, p)
	if err != nil {
		return Descriptor{}, err
	}
	return Descriptor{DescriptorSchema, Profile, Program, id, params, p, digest, hex.EncodeToString(tree.PkScript)}, nil
}

func ValidateDescriptor(d Descriptor) error {
	rebuilt, err := BuildDescriptor(d.VaultID, d.Params, d.SpendingPolicy)
	if err != nil {
		return err
	}
	if d != rebuilt {
		return fmt.Errorf("Light descriptor does not match its program")
	}
	return nil
}

func DescriptorDigest(d Descriptor) (string, error) {
	if err := ValidateDescriptor(d); err != nil {
		return "", err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ParseDescriptor rejects unknown fields and trailing JSON before reconstruction.
func ParseDescriptor(raw []byte) (Descriptor, error) {
	if len(raw) > 8192 {
		return Descriptor{}, fmt.Errorf("Light descriptor too large")
	}
	var d Descriptor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return Descriptor{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Descriptor{}, fmt.Errorf("trailing Light descriptor data")
	}
	if err := ValidateDescriptor(d); err != nil {
		return Descriptor{}, err
	}
	return d, nil
}
