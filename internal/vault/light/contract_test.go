package light

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type vector struct {
	Descriptor        Descriptor `json:"descriptor"`
	DescriptorDigest  string     `json:"descriptorDigest"`
	SpendScript       string     `json:"spendScript"`
	ExitScript        string     `json:"exitScript"`
	TapKey            string     `json:"tapKey"`
	SpendControlBlock string     `json:"spendControlBlock"`
	ExitControlBlock  string     `json:"exitControlBlock"`
}

func vectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var values []vector
	if err := json.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestSharedContractVectors(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Descriptor.Network, func(t *testing.T) {
			d := v.Descriptor
			if err := ValidateDescriptor(d); err != nil {
				t.Fatal(err)
			}
			digest, err := DescriptorDigest(d)
			if err != nil || digest != v.DescriptorDigest {
				t.Fatalf("descriptor digest %s %v", digest, err)
			}
			tree, err := BuildTree(d.Params)
			if err != nil {
				t.Fatal(err)
			}
			for name, pair := range map[string][2]string{
				"spend":       {hex.EncodeToString(tree.SpendScript), v.SpendScript},
				"exit":        {hex.EncodeToString(tree.ExitScript), v.ExitScript},
				"tap key":     {hex.EncodeToString(tree.TapKey), v.TapKey},
				"pk script":   {hex.EncodeToString(tree.PkScript), d.ScriptPubKey},
				"spend proof": {hex.EncodeToString(tree.SpendControlBlock), v.SpendControlBlock},
				"exit proof":  {hex.EncodeToString(tree.ExitControlBlock), v.ExitControlBlock},
			} {
				if pair[0] != pair[1] {
					t.Fatalf("%s: %s != %s", name, pair[0], pair[1])
				}
			}
			spend, err := arkscript.DecodeClosure(tree.SpendScript)
			if err != nil {
				t.Fatal(err)
			}
			if multisig, ok := spend.(*arkscript.MultisigClosure); !ok || len(multisig.PubKeys) != 3 {
				t.Fatal("Light needs three cooperative signatures")
			}
			exit, err := arkscript.DecodeClosure(tree.ExitScript)
			if err != nil {
				t.Fatal(err)
			}
			if csv, ok := exit.(*arkscript.CSVMultisigClosure); !ok || len(csv.PubKeys) != 1 || csv.Locktime.Value != d.ExitDelaySeconds {
				t.Fatal("Light needs exactly one delayed owner exit")
			}
			raw, _ := json.Marshal(d)
			if _, err := ParseDescriptor(raw); err != nil {
				t.Fatal(err)
			}
			if _, err := ParseDescriptor(append(raw, raw...)); err == nil {
				t.Fatal("accepted trailing JSON")
			}
			extra := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"hardwarePub":"unused"}`)...)
			if _, err := ParseDescriptor(extra); err == nil {
				t.Fatal("accepted extra fields")
			}
		})
	}
}

func TestRejectCrossProfileAndNetworkSubstitution(t *testing.T) {
	original := vectors(t)[0].Descriptor
	changes := map[string]func(*Descriptor){
		"standard":        func(d *Descriptor) { d.Profile = "arkade-vault-v1" },
		"program":         func(d *Descriptor) { d.Program = program.VaultPolicyV1 },
		"network":         func(d *Descriptor) { d.Network = "mainnet" },
		"missing network": func(d *Descriptor) { d.Network = "" },
		"delay":           func(d *Descriptor) { d.ExitDelaySeconds = 2048 },
		"duplicate key":   func(d *Descriptor) { d.OwnerPub = d.CosignerPub },
		"invalid key":     func(d *Descriptor) { d.OwnerPub = hex.EncodeToString(bytes.Repeat([]byte{255}, 32)) },
		"operator":        func(d *Descriptor) { d.OperatorPub = d.CosignerPub },
		"policy":          func(d *Descriptor) { d.SpendingPolicy.TxRecipientCapSats = 25000 },
		"policy digest":   func(d *Descriptor) { d.SpendingPolicyDigest = "" },
		"script":          func(d *Descriptor) { d.ScriptPubKey = "" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			d := original
			change(&d)
			if ValidateDescriptor(d) == nil {
				t.Fatal("accepted substituted descriptor")
			}
		})
	}
	old, _ := program.DefaultSpendingPolicyFor(original.Network)
	if ValidatePolicy(original.Network, Policy(old)) == nil {
		t.Fatal("accepted Standard policy in Light")
	}
	if program.ValidateSpendingPolicyFor(original.Network, program.SpendingPolicy(original.SpendingPolicy)) == nil {
		t.Fatal("accepted Light policy in Standard")
	}
	if program.ValidateProtectionTier("light") == nil {
		t.Fatal("candidate Light must not activate existing enrollment")
	}
}

func TestPolicyBoundsAndDigest(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		original, err := DefaultPolicy(network)
		if err != nil {
			t.Fatal(err)
		}
		for _, edit := range []func(*Policy){
			func(p *Policy) { p.TxRecipientCapSats = 329 },
			func(p *Policy) { p.PeriodAllowanceSats = p.TxRecipientCapSats - 1 },
			func(p *Policy) { p.AbsoluteFeeCapSats = 0 },
			func(p *Policy) { p.FeerateCapSatPerV = 100 },
			func(p *Policy) { p.Period = "calendar-day" },
		} {
			p := original
			edit(&p)
			if ValidatePolicy(network, p) == nil {
				t.Fatal("accepted invalid policy")
			}
		}
		first, _ := PolicyDigest(network, original)
		original.TxRecipientCapSats = 25000
		second, _ := PolicyDigest(network, original)
		if first == second {
			t.Fatal("policy digest does not bind selected limit")
		}
	}
}

// Bitcoin's script engine verifies the committed owner-only exit and CSV units.
func TestOwnerExitExecution(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Descriptor.Network, func(t *testing.T) {
			tree, err := BuildTree(v.Descriptor.Params)
			if err != nil {
				t.Fatal(err)
			}
			sequence := uint32(1<<22) | v.Descriptor.ExitDelaySeconds/512
			cases := []struct {
				name     string
				sequence uint32
				version  int32
				key      byte
				succeeds bool
			}{
				{"mature", sequence, 2, 1, true},
				{"early", sequence - 1, 2, 1, false},
				{"wrong unit", v.Descriptor.ExitDelaySeconds / 512, 2, 1, false},
				{"disabled", sequence | 1<<31, 2, 1, false},
				{"old transaction version", sequence, 1, 1, false},
				{"wrong owner", sequence, 2, 2, false},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					tx := wire.NewMsgTx(test.version)
					tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0}, Sequence: test.sequence})
					tx.AddTxOut(&wire.TxOut{Value: 99000, PkScript: []byte{txscript.OP_TRUE}})
					fetcher := txscript.NewCannedPrevOutputFetcher(tree.PkScript, 100000)
					hashes := txscript.NewTxSigHashes(tx, fetcher)
					secret := make([]byte, 32)
					secret[31] = test.key
					key, _ := btcec.PrivKeyFromBytes(secret)
					sig, err := txscript.RawTxInTapscriptSignature(tx, hashes, 0, 100000, tree.PkScript, txscript.NewBaseTapLeaf(tree.ExitScript), txscript.SigHashDefault, key)
					if err != nil {
						t.Fatal(err)
					}
					tx.TxIn[0].Witness = wire.TxWitness{sig, tree.ExitScript, tree.ExitControlBlock}
					engine, err := txscript.NewEngine(tree.PkScript, tx, 0, txscript.StandardVerifyFlags, nil, hashes, 100000, fetcher)
					if err == nil {
						err = engine.Execute()
					}
					if (err == nil) != test.succeeds {
						t.Fatalf("success=%v err=%v", test.succeeds, err)
					}
				})
			}
		})
	}
}
