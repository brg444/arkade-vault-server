package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	candidate "github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func protocolFixture(t *testing.T) (*fixture, candidate.Rules) {
	return protocolFixtureWithRules(t, nil)
}

func protocolFixtureWithRules(t *testing.T, configure func(*candidate.Rules)) (*fixture, candidate.Rules) {
	t.Helper()
	f := newFixture(t)
	r := candidate.Rules{ConnectorScript: f.connector,
		WitnessBytes: candidate.WitnessBytes(f.leaf.Script, f.control, candidate.Taproot), AbsoluteFeeCapSats: 5000, FeerateCapSatPerV: 10}
	if configure != nil {
		configure(&r)
	}
	script, err := candidate.BuildProgram(r)
	f.policy = must(t, script, err)
	hash := arkade.ArkadeScriptHash(f.policy)
	f.authorities = []*btcec.PrivateKey{f.phone, arkade.ComputeArkadeScriptPrivateKey(f.guardian, hash), arkade.ComputeArkadeScriptPrivateKey(f.emulator, hash)}
	leaf, err := savings.Checksig(f.authorities[0].PubKey(), f.authorities[1].PubKey(), f.authorities[2].PubKey())
	leaf = must(t, leaf, err)
	internal, err := savings.ContextInternalKey("connector-protocol-fixture", "savings", "")
	f.setTree(t, must(t, internal, err), [][]byte{leaf}, 0)
	f.setParent()
	return f, r
}

func TestConnectorPreparationRejectsUnpinnedData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*candidate.Request)
	}{
		{"unknown_parent", func(r *candidate.Request) { r.Savings.Hash[0] ^= 1 }},
		{"duplicate_input", func(r *candidate.Request) { r.Connector = r.Savings }},
		{"wrong_savings", func(r *candidate.Request) { r.SavingsScript = r.DestinationScript }},
		{"wrong_connector", func(r *candidate.Request) { r.Connector.Index = 2 }},
		{"wrong_origin", func(r *candidate.Request) { r.Origin.PublicKey = key(40).PubKey().SerializeCompressed() }},
		{"origin_path", func(r *candidate.Request) { r.Origin.Path[0] = 0x80000054 }},
		{"leaf", func(r *candidate.Request) { r.Leaf[1] ^= 1 }},
		{"control", func(r *candidate.Request) { r.Control[1] ^= 1 }},
		{"witness_size", func(r *candidate.Request) { r.Rules.WitnessBytes++ }},
		{"missing_authority", func(r *candidate.Request) { r.EmulatorBase = nil }},
		{"different_authority", func(r *candidate.Request) { r.EmulatorBase = key(50).PubKey() }},
		{"duplicate_authority", func(r *candidate.Request) { r.EmulatorBase = r.GuardianBase }},
		{"different_program", func(r *candidate.Request) { r.Rules.AbsoluteFeeCapSats++ }},
		{"negative_amount", func(r *candidate.Request) { r.AmountSats = -1 }},
		{"overflow_amount", func(r *candidate.Request) { r.AmountSats = 1<<63 - 1 }},
		{"negative_fee", func(r *candidate.Request) { r.FeeSats = -1 }},
		{"dust_change", func(r *candidate.Request) { r.AmountSats = 8700 }},
		{"oversized_fee", func(r *candidate.Request) { r.FeeSats = 6000 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, r := protocolFixture(t)
			req := protocolRequest(f, r)
			tc.mutate(&req)
			if _, err := candidate.Prepare(req); err == nil {
				t.Fatal("accepted unpinned or malformed request")
			}
		})
	}
}

func TestConnectorForeignInputAndSnapshot(t *testing.T) {
	for _, mode := range []string{"missing", "invalid_signature", "weak_sighash", "different_leaf", "annex"} {
		t.Run(mode, func(t *testing.T) {
			f, r := protocolFixture(t)
			d, _ := prepareProtocol(t, f, r)
			w := f.tx.TxIn[0].Witness
			switch mode {
			case "missing":
				w = w[:4]
			case "invalid_signature":
				w[0][0] ^= 1
			case "weak_sighash":
				w[0] = append(w[0], byte(txscript.SigHashAll))
			case "different_leaf":
				w[3][0] ^= 1
			case "annex":
				w = append(w, []byte{0x50})
			}
			if _, err := d.ForHardware(w); err == nil {
				t.Fatal("accepted unverified foreign input")
			}
		})
	}
	f, r := protocolFixture(t)
	req := protocolRequest(f, r)
	d, err := candidate.Prepare(req)
	d = must(t, d, err)
	p, err := d.PSBT()
	p = must(t, p, err)
	f.tx = p.UnsignedTx.Copy()
	f.signSavings(t, f.authorities...)
	h, err := d.ForHardware(f.tx.TxIn[0].Witness)
	h = must(t, h, err)
	response := hardwareResponse(t, f, h)
	// Change caller-owned data after preparation. None may affect the snapshot.
	req.DestinationScript[2] ^= 1
	req.Parents[req.Savings].TxOut[0].Value++
	req.Leaf[0] ^= 1
	req.Control[0] ^= 1
	response.Inputs[0].FinalScriptWitness = []byte{0}
	final, err := h.Accept(response)
	final = must(t, final, err)
	if final.TxOut[0].Value != 8000 || len(final.TxIn[0].Witness) != 5 {
		t.Fatal("snapshot changed")
	}
	// The imported signature must still validate against the original parents.
	p.Inputs[0].NonWitnessUtxo.TxOut[0].Value = 10000
	parents := candidate.Parents{p.UnsignedTx.TxIn[0].PreviousOutPoint: p.Inputs[0].NonWitnessUtxo, p.UnsignedTx.TxIn[1].PreviousOutPoint: p.Inputs[1].NonWitnessUtxo}
	for i, in := range final.TxIn {
		out := parents.FetchPrevOutput(in.PreviousOutPoint)
		engine, err := txscript.NewEngine(out.PkScript, final, i, txscript.StandardVerifyFlags, nil, txscript.NewTxSigHashes(final, parents), out.Value, parents)
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Execute(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConnectorFeeLimits(t *testing.T) {
	for _, mode := range []string{"absolute", "feerate"} {
		t.Run(mode, func(t *testing.T) {
			f, r := protocolFixtureWithRules(t, func(r *candidate.Rules) {
				if mode == "feerate" {
					r.AbsoluteFeeCapSats = 100000
					r.FeerateCapSatPerV = 1
				}
			})
			f.parent.TxOut[0].Value = 100000
			f.resetSpend()
			req := protocolRequest(f, r)
			req.FeeSats = 100
			d, err := candidate.Prepare(req)
			d = must(t, d, err)
			p, err := d.PSBT()
			p = must(t, p, err)
			limit := r.AbsoluteFeeCapSats
			if mode == "feerate" {
				limit = (int64(p.UnsignedTx.SerializeSizeStripped()*4) + r.WitnessBytes + 3) / 4 * r.FeerateCapSatPerV
			}
			p.UnsignedTx.TxOut[4].Value = 100000 - 8000 - 240 - limit
			if err := executePacket(p, f, f.emulator.PubKey()); err != nil {
				t.Fatal("rejected fee at boundary", err)
			}
			p.UnsignedTx.TxOut[4].Value--
			if err := candidate.Validate(r, p.UnsignedTx, candidate.Parents(f.prevouts())); err == nil {
				t.Fatal("accepted fee over limit")
			}
			if err := executePacket(p, f, f.emulator.PubKey()); err == nil {
				t.Fatal("independent signer accepted fee over limit")
			}
		})
	}
}

func TestConnectorProtocolCore(t *testing.T) {
	t.Run("default_relay_policy", func(t *testing.T) {
		c := startCore(t)
		f, r := protocolFixture(t)
		c.fund(t, f)
		_, h := prepareProtocol(t, f, r)
		final, err := h.Accept(hardwareResponse(t, f, h))
		final = must(t, final, err)
		version := rpc[struct{ Version int }](t, c, "getnetworkinfo")
		// The complete packet exceeds the pre-30 default OP_RETURN limit.
		if version.Version < 300000 {
			result := rpc[[]struct {
				Allowed      bool
				RejectReason string `json:"reject-reason"`
			}](t, c, "testmempoolaccept", []string{txHex(t, final)})
			if len(result) != 1 || result[0].Allowed || result[0].RejectReason != "scriptpubkey" {
				t.Fatalf("expected data-output policy rejection: %+v", result)
			}
			t.Logf("packet %d bytes exceeds Core pre-30 default data limit; signatures verified separately", len(final.TxOut[3].PkScript))
		} else {
			c.accepted(t, final, true)
			c.mine(t, final)
		}
	})
	t.Run("complete_packet_and_reserve_successor", func(t *testing.T) {
		// Explicitly exercise the larger data-output policy used by Core 30.
		// All signature, dust, fee, and script verification remains enabled.
		c := startCore(t, "-datacarriersize=100000")
		f, r := protocolFixture(t)
		f.parent.TxOut[0].Value = 100000
		f.resetSpend()
		c.fund(t, f)
		for round := 0; round < 2; round++ {
			oldConnector := f.tx.TxIn[1].PreviousOutPoint
			d, h := prepareProtocol(t, f, r)
			p, err := d.PSBT()
			p = must(t, p, err)
			if err := executePacket(p, f, f.emulator.PubKey()); err != nil {
				t.Fatal(err)
			}
			final, err := h.Accept(hardwareResponse(t, f, h))
			final = must(t, final, err)
			c.accepted(t, final, true)
			c.mine(t, final)
			if out := rpc[json.RawMessage](t, c, "gettxout", oldConnector.Hash.String(), oldConnector.Index); string(out) != "null" {
				t.Fatal("old connector remains spendable")
			}
			successor := rpc[*struct {
				Value         float64
				Confirmations int
			}](t, c, "gettxout", final.TxHash().String(), 1)
			if successor == nil || successor.Confirmations != 1 || successor.Value != 0.00001000 {
				t.Fatal("connector successor missing or value changed")
			}
			c.accepted(t, final, false)
			f.parent = final.Copy()
			f.resetSpend()
			f.tx.TxIn[0].PreviousOutPoint.Index = 4
			f.tx.TxIn[1].PreviousOutPoint.Index = 1
		}
	})
}

func protocolRequest(f *fixture, r candidate.Rules) candidate.Request {
	return candidate.Request{Rules: r, Parents: candidate.Parents(f.prevouts()), Savings: f.tx.TxIn[0].PreviousOutPoint, Connector: f.tx.TxIn[1].PreviousOutPoint,
		DestinationScript: f.destination, SavingsScript: f.savingsScript, Leaf: f.leaf.Script, Control: f.control,
		Phone: f.phone.PubKey(), GuardianBase: f.guardian.PubKey(), EmulatorBase: f.emulator.PubKey(),
		Origin:     candidate.KeyOrigin{Type: candidate.Taproot, PublicKey: f.hardware.PubKey().SerializeCompressed(), Fingerprint: 0x12345678, Path: []uint32{0x80000056, 0x80000000, 0x80000000, 0, 0}},
		AmountSats: 8000, FeeSats: 1000}
}

func prepareProtocol(t *testing.T, f *fixture, r candidate.Rules) (*candidate.Draft, *candidate.HardwareRequest) {
	t.Helper()
	d, err := candidate.Prepare(protocolRequest(f, r))
	d = must(t, d, err)
	p, err := d.PSBT()
	f.tx = must(t, p, err).UnsignedTx.Copy()
	f.signSavings(t, f.authorities...)
	h, err := d.ForHardware(f.tx.TxIn[0].Witness)
	return d, must(t, h, err)
}

func hardwareResponse(t *testing.T, f *fixture, h *candidate.HardwareRequest) *psbt.Packet {
	t.Helper()
	hashType := txscript.SigHashDefault
	if txscript.IsPayToWitnessPubKeyHash(f.connector) {
		hashType = txscript.SigHashAll
	}
	f.signConnector(t, f.hardware, hashType)
	p, err := h.PSBT()
	p = must(t, p, err)
	if hashType == txscript.SigHashAll {
		p.Inputs[1].PartialSigs = []*psbt.PartialSig{{PubKey: f.hardware.PubKey().SerializeCompressed(), Signature: bytes.Clone(f.tx.TxIn[1].Witness[0])}}
	} else {
		p.Inputs[1].TaprootKeySpendSig = bytes.Clone(f.tx.TxIn[1].Witness[0])
	}
	return p
}

func executePacket(p *psbt.Packet, f *fixture, signer *btcec.PublicKey) error {
	entries, err := arkade.FindEmulatorPacket(p.UnsignedTx)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Vin != 0 {
		return fmt.Errorf("unexpected packet entries")
	}
	script, err := arkade.ReadArkadeScript(p, signer, entries[0])
	if err != nil {
		return err
	}
	if err := arkade.VerifyTaprootLeafCommitment(f.savingsScript, p.Inputs[0].TaprootLeafScript[0]); err != nil {
		return err
	}
	return script.Execute(p.UnsignedTx, f.prevouts(), 0)
}

func TestConnectorProtocolHandoff(t *testing.T) {
	f, r := protocolFixture(t)
	d, h := prepareProtocol(t, f, r)
	p, err := d.PSBT()
	p = must(t, p, err)
	if err := runProgram(p.UnsignedTx, f.policy, f.prevouts()); err != nil {
		t.Fatal(err)
	}
	for _, signer := range []*btcec.PublicKey{f.guardian.PubKey(), f.emulator.PubKey()} {
		if err := executePacket(p, f, signer); err != nil {
			t.Fatal(err)
		}
	}
	response := hardwareResponse(t, f, h)
	final, err := h.Accept(response)
	final = must(t, final, err)
	for i := range final.TxIn {
		if err := verifyInput(final, f.prevouts(), i); err != nil {
			t.Fatal(err)
		}
	}
	if int64(final.SerializeSize()-final.SerializeSizeStripped()) != r.WitnessBytes {
		t.Fatal("fee weight differs from final witness size")
	}
	if final.TxOut[4].Value != 760 || final.TxOut[1].Value != 1000 || final.TxOut[2].Value != 240 {
		t.Fatal("reserve or Savings accounting")
	}
	if len(response.Inputs[0].FinalScriptWitness) == 0 || len(response.Inputs[0].TaprootLeafScript) != 0 {
		t.Fatal("foreign input not finalized")
	}
	if len(response.Inputs[1].TaprootBip32Derivation) != 1 || len(response.Outputs[1].TaprootBip32Derivation) != 1 {
		t.Fatal("connector origin metadata missing")
	}
	// A finalized PSBT response is accepted without requiring redundant metadata.
	response.Inputs[1].FinalScriptWitness = append([]byte{1, 64}, response.Inputs[1].TaprootKeySpendSig...)
	response.Inputs[1].TaprootKeySpendSig = nil
	response.Inputs[0].WitnessUtxo = nil
	response.Inputs[1].WitnessUtxo = nil
	if _, err := h.Accept(response); err != nil {
		t.Fatal(err)
	}
	// Neither returned transaction nor PSBT copies may mutate stored authority.
	final.TxOut[0].Value--
	p.UnsignedTx.TxOut[0].Value--
	again, err := h.Accept(response)
	if err != nil || again.TxOut[0].Value != 8000 {
		t.Fatal("mutable handoff snapshot", err)
	}
}

func TestConnectorProtocolRejectsMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*psbt.Packet)
	}{
		{"destination", func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].PkScript[4] ^= 1 }},
		{"amount", func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].Value-- }},
		{"reserve", func(p *psbt.Packet) { p.UnsignedTx.TxOut[1].Value-- }},
		{"packet", func(p *psbt.Packet) { p.UnsignedTx.TxOut[3].PkScript[5] ^= 1 }},
		{"prevout_amount", func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo.Value++ }},
		{"parent", func(p *psbt.Packet) { p.Inputs[1].NonWitnessUtxo.TxOut[1].Value++ }},
		{"metadata_sighash", func(p *psbt.Packet) { p.Inputs[1].SighashType = txscript.SigHashAll }},
		{"encoded_sighash", func(p *psbt.Packet) {
			p.Inputs[1].TaprootKeySpendSig = append(p.Inputs[1].TaprootKeySpendSig, byte(txscript.SigHashAll))
		}},
		{"invalid_signature", func(p *psbt.Packet) { p.Inputs[1].TaprootKeySpendSig[0] ^= 1 }},
		{"missing_signature", func(p *psbt.Packet) { p.Inputs[1].TaprootKeySpendSig = nil }},
		{"annex", func(p *psbt.Packet) {
			p.Inputs[1].FinalScriptWitness = append([]byte{2, 64}, p.Inputs[1].TaprootKeySpendSig...)
			p.Inputs[1].FinalScriptWitness = append(p.Inputs[1].FinalScriptWitness, 1, 0x50)
		}},
		{"omitted_connector", func(p *psbt.Packet) { p.UnsignedTx.TxIn = p.UnsignedTx.TxIn[:1] }},
		{"extra_input", func(p *psbt.Packet) { p.UnsignedTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil)) }},
		{"changed_sequence", func(p *psbt.Packet) { p.UnsignedTx.TxIn[1].Sequence-- }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, r := protocolFixture(t)
			_, h := prepareProtocol(t, f, r)
			p := hardwareResponse(t, f, h)
			tc.mutate(p)
			if _, err := h.Accept(p); err == nil {
				t.Fatal("accepted changed approval")
			}
		})
	}
}

func TestConnectorProgramChecksBeforeHardware(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*wire.MsgTx)
	}{
		{"substitute_connector", func(tx *wire.MsgTx) { tx.TxIn[1].PreviousOutPoint.Index = 2 }},
		{"savings_change", func(tx *wire.MsgTx) { tx.TxOut[4].PkScript = tx.TxOut[0].PkScript }},
		{"steal_reserve", func(tx *wire.MsgTx) { tx.TxOut[1].PkScript = tx.TxOut[0].PkScript }},
		{"reduce_reserve", func(tx *wire.MsgTx) { tx.TxOut[1].Value-- }},
		{"anchor_value", func(tx *wire.MsgTx) { tx.TxOut[2].Value-- }},
		{"anchor_script", func(tx *wire.MsgTx) { tx.TxOut[2].PkScript[3] ^= 1 }},
		{"funded_packet", func(tx *wire.MsgTx) { tx.TxOut[3].Value++ }},
		{"packet_content", func(tx *wire.MsgTx) { tx.TxOut[3].PkScript[20] ^= 1 }},
		{"missing_change", func(tx *wire.MsgTx) { tx.TxOut[4].Value = 0 }},
		{"negative_fee", func(tx *wire.MsgTx) { tx.TxOut[0].Value += 1001 }},
		{"sequence", func(tx *wire.MsgTx) { tx.TxIn[0].Sequence-- }},
		{"locktime", func(tx *wire.MsgTx) { tx.LockTime = 1 }},
		{"extra_output", func(tx *wire.MsgTx) { tx.AddTxOut(wire.NewTxOut(0, []byte{0x6a})) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, r := protocolFixture(t)
			d, _ := prepareProtocol(t, f, r)
			p, err := d.PSBT()
			p = must(t, p, err)
			tc.mutate(p.UnsignedTx)
			if err := candidate.Validate(r, p.UnsignedTx, candidate.Parents(f.prevouts())); err == nil {
				t.Fatal("candidate accepted mutation")
			}
			if err := executePacket(p, f, f.emulator.PubKey()); err == nil {
				t.Fatal("independent program accepted mutation")
			}
		})
	}
}
