package connector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/program"
	candidate "github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func familyInput(t *testing.T, network, tier string) savings.FamilyInput {
	t.Helper()
	p, err := program.DefaultSpendingPolicyFor(network)
	p = must(t, p, err)
	d, err := hex.DecodeString("02c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	in := savings.FamilyInput{VaultID: "connector-family-fixture", Network: network, Phone: key(3).PubKey(), Hardware: key(4).PubKey(), PhoneDirectP256: must(t, d, err), VaultCosignerBase: key(14).PubKey(), ArkadeCosignerBase: key(15).PubKey(), ProtectionTier: tier, SpendingPolicy: p, ServerFreeClawback: true}
	if tier == program.ProtectionTierAdvanced {
		in.Recovery = key(5).PubKey()
	}
	return in
}

func TestConnectorFamilyCore(t *testing.T) {
	c := startCore(t, "-datacarriersize=100000")
	for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
		in := familyInput(t, "mainnet", tier)
		fam, err := candidate.BuildFamily(in, candidate.Taproot)
		fam = must(t, fam, err)
		t.Run(tier+"_complete_withdrawal", func(t *testing.T) {
			f, _ := protocolFixture(t)
			f.savingsScript = fam.Recovery.Savings.PkScript
			f.leaf = txscript.NewBaseTapLeaf(fam.Leaf)
			f.control = fam.Control
			f.policy = fam.Program
			hash := arkade.ArkadeScriptHash(fam.Program)
			f.authorities = []*btcec.PrivateKey{f.phone, arkade.ComputeArkadeScriptPrivateKey(f.guardian, hash), arkade.ComputeArkadeScriptPrivateKey(f.emulator, hash)}
			f.setParent()
			c.fund(t, f)
			req := protocolRequest(f, fam.Rules)
			req.AmountSats = 8760
			req.DestinationScript = taproot(t, key(70))
			d, err := candidate.Prepare(req)
			d = must(t, d, err)
			p, err := d.PSBT()
			p = must(t, p, err)
			f.tx = p.UnsignedTx.Copy()
			f.signSavings(t, f.authorities...)
			h, err := d.ForHardware(f.tx.TxIn[0].Witness)
			h = must(t, h, err)
			final, err := h.Accept(hardwareResponse(t, f, h))
			final = must(t, final, err)
			c.accepted(t, final, true)
			c.mine(t, final)
			if len(final.TxOut) != 4 {
				t.Fatal("unexpected Savings remainder")
			}
		})
		roles := []string{"phone", "hardware"}
		if tier == program.ProtectionTierAdvanced {
			roles = append(roles, "recovery")
		}
		for _, role := range roles {
			t.Run(tier+"_pending_"+role, func(t *testing.T) {
				f := newFixture(t)
				f.family = fam.Recovery
				f, delay := pendingFamilyFixture(t, f, role, in.VaultID, candidate.Template)
				c.fund(t, f)
				f.tx.TxIn = f.tx.TxIn[:1]
				f.tx.TxIn[0].Sequence = delay
				f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.destination)}
				f.signSavings(t, f.authorities...)
				c.accepted(t, f.tx, false)
				rpc[[]string](t, c, "generatetoaddress", delay-2, c.miningAddress)
				c.accepted(t, f.tx, false)
				rpc[[]string](t, c, "generatetoaddress", 1, c.miningAddress)
				c.accepted(t, f.tx, true)
				c.mine(t, f.tx)
			})
		}
	}
}

func TestConnectorFamilyVectors(t *testing.T) {
	var vectors []map[string]any
	for _, style := range []string{"p2tr", "p2wpkh", "electrum"} {
		kind := candidate.Kind(style)
		if style == "electrum" {
			kind = candidate.NativeSegwit
		}
		for _, network := range []string{"mainnet", "mutinynet"} {
			for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
				in := familyInput(t, network, tier)
				var hardware *btcec.PrivateKey
				var softwareOrigin candidate.KeyOrigin
				if kind == candidate.NativeSegwit {
					hardware, softwareOrigin = softwareKey(t, network, kind)
					if style == "electrum" {
						hardware, softwareOrigin = electrumKey(t)
					}
					in.Hardware = hardware.PubKey()
				}
				fam, err := candidate.BuildFamily(in, kind)
				fam = must(t, fam, err)
				original, err := savings.BuildFamily(in)
				original = must(t, original, err)
				if bytes.Equal(original.Savings.PkScript, fam.Recovery.Savings.PkScript) {
					t.Fatal("new contract reused old Savings")
				}
				in.TemplateVersion = candidate.Template
				base, err := savings.BuildFamily(in)
				base = must(t, base, err)
				pending, quarantine := map[string]string{}, map[string]string{}
				for role, tree := range base.Pending {
					if !bytes.Equal(tree.PkScript, fam.Recovery.Pending[role].PkScript) || !bytes.Equal(base.Quarantine[role].PkScript, fam.Recovery.Quarantine[role].PkScript) {
						t.Fatal("recovery construction changed")
					}
					pending[role] = hex.EncodeToString(tree.PkScript)
					quarantine[role] = hex.EncodeToString(base.Quarantine[role].PkScript)
				}
				coin := uint32(0x80000000)
				if network == "mutinynet" {
					coin++
				}
				origin := candidate.KeyOrigin{Type: candidate.Taproot, PublicKey: in.Hardware.SerializeCompressed(), Fingerprint: 0x12345678, Path: []uint32{0x80000056, coin, 0x80000000, 0, 0}}
				if kind == candidate.NativeSegwit {
					origin = softwareOrigin
				}
				digest, err := candidate.EnrollmentDigest(in, origin)
				digest = must(t, digest, err)
				bad := origin
				bad.Path = append([]uint32(nil), origin.Path...)
				bad.Path[1] ^= 1
				if _, err := candidate.EnrollmentDigest(in, bad); err == nil && style != "electrum" {
					t.Fatal("cross-network origin accepted")
				}
				bad = origin
				bad.Fingerprint++
				other, err := candidate.EnrollmentDigest(in, bad)
				if err != nil || other == digest {
					t.Fatal("fingerprint not bound")
				}
				f, _ := protocolFixture(t)
				if hardware != nil {
					f.hardware = hardware
				}
				f.connector = fam.Rules.ConnectorScript
				f.savingsScript = fam.Recovery.Savings.PkScript
				f.leaf = txscript.NewBaseTapLeaf(fam.Leaf)
				f.control = fam.Control
				f.policy = fam.Program
				hash := arkade.ArkadeScriptHash(fam.Program)
				f.authorities = []*btcec.PrivateKey{f.phone, arkade.ComputeArkadeScriptPrivateKey(f.guardian, hash), arkade.ComputeArkadeScriptPrivateKey(f.emulator, hash)}
				f.setParent()
				var payments []map[string]any
				for _, full := range []bool{false, true} {
					req := protocolRequest(f, fam.Rules)
					req.Origin = origin
					req.DestinationScript = taproot(t, key(70))
					if full {
						req.AmountSats = 8760
					}
					d, err := candidate.Prepare(req)
					d = must(t, d, err)
					p, err := d.PSBT()
					p = must(t, p, err)
					f.tx = p.UnsignedTx.Copy()
					f.signSavings(t, f.authorities...)
					h, err := d.ForHardware(f.tx.TxIn[0].Witness)
					h = must(t, h, err)
					response := hardwareResponse(t, f, h)
					final, err := h.Accept(response)
					final = must(t, final, err)
					var buf bytes.Buffer
					if err := response.Serialize(&buf); err != nil {
						t.Fatal(err)
					}
					witness := []string{}
					for _, w := range f.tx.TxIn[0].Witness {
						witness = append(witness, hex.EncodeToString(w))
					}
					payments = append(payments, map[string]any{"full": full, "amount": req.AmountSats, "fee": req.FeeSats, "parent": txHex(t, f.parent), "parentTxid": f.parent.TxHash().String(), "recipientScript": hex.EncodeToString(req.DestinationScript), "unsigned": txHex(t, p.UnsignedTx), "savingsWitness": witness, "responsePSBT": hex.EncodeToString(buf.Bytes()), "finalTx": txHex(t, final), "txid": final.TxHash().String()})
				}
				vectors = append(vectors, map[string]any{"payments": payments, "connectorType": string(kind), "originType": style, "originFingerprint": origin.Fingerprint, "originPath": origin.Path, "network": network, "tier": tier, "phone": hex.EncodeToString(in.Phone.SerializeCompressed()), "hardware": hex.EncodeToString(in.Hardware.SerializeCompressed()), "guardian": hex.EncodeToString(in.VaultCosignerBase.SerializeCompressed()), "emulator": hex.EncodeToString(in.ArkadeCosignerBase.SerializeCompressed()), "recovery": hex.EncodeToString(key(5).PubKey().SerializeCompressed()), "phoneDirect": hex.EncodeToString(in.PhoneDirectP256), "program": hex.EncodeToString(fam.Program), "script": hex.EncodeToString(fam.Recovery.Savings.PkScript), "address": fam.Recovery.Savings.Address, "leaf": hex.EncodeToString(fam.Leaf), "control": hex.EncodeToString(fam.Control), "reserve": hex.EncodeToString(fam.Rules.ConnectorScript), "witnessBytes": fam.Rules.WitnessBytes, "pending": pending, "quarantine": quarantine, "enrollmentDigest": digest})
			}
		}
	}
	raw, err := json.MarshalIndent(vectors, "", "  ")
	raw = must(t, raw, err)
	raw = append(raw, '\n')
	const path = "testdata/family-vectors.json"
	if os.Getenv("UPDATE_CONNECTOR_VECTORS") == "1" {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, raw) {
		t.Fatal("connector vectors changed")
	}
}

func TestConnectorFamilyWithdrawals(t *testing.T) {
	for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
		t.Run(tier, func(t *testing.T) {
			in := familyInput(t, "mainnet", tier)
			fam, err := candidate.BuildFamily(in, candidate.Taproot)
			fam = must(t, fam, err)
			for _, full := range []bool{false, true} {
				f, r := protocolFixture(t)
				f.savingsScript = fam.Recovery.Savings.PkScript
				f.leaf = txscript.NewBaseTapLeaf(fam.Leaf)
				f.control = fam.Control
				f.policy = fam.Program
				r = fam.Rules
				hash := arkade.ArkadeScriptHash(fam.Program)
				f.authorities = []*btcec.PrivateKey{f.phone, arkade.ComputeArkadeScriptPrivateKey(f.guardian, hash), arkade.ComputeArkadeScriptPrivateKey(f.emulator, hash)}
				f.setParent()
				req := protocolRequest(f, r)
				req.DestinationScript = taproot(t, key(70))
				if full {
					req.AmountSats = 8760
				}
				d, err := candidate.Prepare(req)
				d = must(t, d, err)
				p, err := d.PSBT()
				p = must(t, p, err)
				if err := executePacket(p, f, f.emulator.PubKey()); err != nil {
					t.Fatal(err)
				}
				f.tx = p.UnsignedTx.Copy()
				f.signSavings(t, f.authorities...)
				h, err := d.ForHardware(f.tx.TxIn[0].Witness)
				h = must(t, h, err)
				final, err := h.Accept(hardwareResponse(t, f, h))
				final = must(t, final, err)
				if full && len(final.TxOut) != 4 {
					t.Fatal("full withdrawal left change")
				}
				for i := range final.TxIn {
					if err := verifyInput(final, f.prevouts(), i); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}
