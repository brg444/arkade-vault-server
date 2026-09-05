package connector

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestProgramAndBitcoinAcceptEnrolledConnector(t *testing.T) {
	f := newFixture(t)
	if err := runProgram(f.tx, f.policy, f.prevouts()); err != nil {
		t.Fatal(err)
	}
	f.signSavings(t, f.authorities...)
	f.signConnector(t, f.hardware, txscript.SigHashDefault)
	for i := range f.tx.TxIn {
		if err := verifyInput(f.tx, f.prevouts(), i); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProgramRejectsUnauthorizedShape(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"missing_connector", func(f *fixture) { f.tx.TxIn = f.tx.TxIn[:1] }},
		{"attacker_connector", func(f *fixture) { f.tx.TxIn[1].PreviousOutPoint.Index = 2 }},
		{"unknown_outpoint", func(f *fixture) { f.tx.TxIn[1].PreviousOutPoint.Index = 99 }},
		{"duplicate_input", func(f *fixture) { f.tx.TxIn[1].PreviousOutPoint = f.tx.TxIn[0].PreviousOutPoint }},
		{"extra_input", func(f *fixture) {
			f.tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: f.parent.TxHash(), Index: 3}, nil, nil))
		}},
		{"recipient", func(f *fixture) { f.tx.TxOut[0].PkScript = f.attackerScript }},
		{"savings_change", func(f *fixture) { f.tx.TxOut[1].PkScript = f.attackerScript }},
		{"connector_return", func(f *fixture) { f.tx.TxOut[2].PkScript = f.attackerScript }},
		{"reserve_reduced", func(f *fixture) { f.tx.TxOut[2].Value-- }},
		{"reserve_increased", func(f *fixture) { f.tx.TxOut[2].Value++ }},
		{"extra_attacker_output", func(f *fixture) { f.tx.AddTxOut(wire.NewTxOut(400, f.attackerScript)) }},
		{"excessive_fee", func(f *fixture) { f.tx.TxOut[0].Value -= 501 }},
		{"negative_fee", func(f *fixture) { f.tx.TxOut[0].Value += 501 }},
		{"negative_output", func(f *fixture) { f.tx.TxOut[0].Value = -1 }},
		{"version", func(f *fixture) { f.tx.Version = 3 }},
		{"locktime", func(f *fixture) { f.tx.LockTime = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			test.mutate(f)
			if err := runProgram(f.tx, f.policy, f.prevouts()); err == nil {
				t.Fatal("unauthorized shape accepted")
			}
		})
	}
}

func TestHardwareSignatureCommitsWholePayment(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"recipient", func(f *fixture) { f.tx.TxOut[0].PkScript = f.attackerScript }},
		{"amount_redistribution", func(f *fixture) { f.tx.TxOut[0].Value--; f.tx.TxOut[1].Value++ }},
		{"savings_change", func(f *fixture) { f.tx.TxOut[1].PkScript = f.attackerScript }},
		{"connector_return", func(f *fixture) { f.tx.TxOut[2].PkScript = f.attackerScript }},
		{"fee_increase", func(f *fixture) { f.tx.TxOut[0].Value-- }},
		{"extra_output", func(f *fixture) { f.tx.AddTxOut(wire.NewTxOut(0, f.attackerScript)) }},
		{"connector_same_key_different_outpoint", func(f *fixture) { f.tx.TxIn[1].PreviousOutPoint.Index = 3 }},
		{"savings_outpoint", func(f *fixture) { f.tx.TxIn[0].PreviousOutPoint.Index = 2 }},
		{"input_sequence", func(f *fixture) { f.tx.TxIn[0].Sequence-- }},
		{"version", func(f *fixture) { f.tx.Version++ }},
		{"locktime", func(f *fixture) { f.tx.LockTime++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.signConnector(t, f.hardware, txscript.SigHashDefault)
			if err := verifyInput(f.tx, f.prevouts(), 1); err != nil {
				t.Fatal(err)
			}
			test.mutate(f)
			if err := verifyInput(f.tx, f.prevouts(), 1); err == nil {
				t.Fatal("mutated transaction retained hardware approval")
			}
		})
	}
}

func TestPSBTMetadataIsNotPrevoutAuthority(t *testing.T) {
	for _, name := range []string{"amount", "script", "missing", "sighash_none", "sighash_single", "sighash_anyonecanpay"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p, err := psbt.NewFromUnsignedTx(f.tx)
			p = must(t, p, err)
			for i, in := range f.tx.TxIn {
				out := *f.prevouts().FetchPrevOutput(in.PreviousOutPoint)
				p.Inputs[i].WitnessUtxo = &out
			}
			if err := verifyPSBT(p, f.prevouts()); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "amount":
				p.Inputs[1].WitnessUtxo.Value++
			case "script":
				p.Inputs[1].WitnessUtxo.PkScript = f.attackerScript
			case "missing":
				p.Inputs[1].WitnessUtxo = nil
			case "sighash_none":
				p.Inputs[1].SighashType = txscript.SigHashNone
			case "sighash_single":
				p.Inputs[1].SighashType = txscript.SigHashSingle
			case "sighash_anyonecanpay":
				p.Inputs[1].SighashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
			}
			if err := verifyPSBT(p, f.prevouts()); err == nil {
				t.Fatal("forged metadata accepted")
			}
		})
	}
}

func TestActualSignatureMustUseDefaultSighash(t *testing.T) {
	for _, hashType := range []txscript.SigHashType{txscript.SigHashNone, txscript.SigHashSingle, txscript.SigHashAll | txscript.SigHashAnyOneCanPay} {
		f := newFixture(t)
		f.signConnector(t, f.hardware, hashType)
		// Bitcoin permits these modes; the approval importer must reject them,
		// regardless of the PSBT metadata's declared SighashType.
		if err := verifyInput(f.tx, f.prevouts(), 1); err != nil {
			t.Fatal(err)
		}
		if err := verifyApproval(f); err == nil {
			t.Fatalf("accepted sighash %x", hashType)
		}
	}
	f := newFixture(t)
	f.signConnector(t, f.hardware, txscript.SigHashDefault)
	if err := verifyApproval(f); err != nil {
		t.Fatal(err)
	}
}

// These success expectations are counterexamples, not desirable policy behavior.
// Both program-derived cosigner keys are used, but the interpreter is bypassed.
func TestCompromisedAuthoritiesCanOmitOrReplaceConnector(t *testing.T) {
	for _, mode := range []string{"omit", "replace"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.attackerScript)}
			if mode == "omit" {
				f.tx.TxIn = f.tx.TxIn[:1]
			} else {
				f.tx.TxIn[1].PreviousOutPoint.Index = 2
				f.tx.TxOut[0].Value += 1000
				f.signConnector(t, f.attacker, txscript.SigHashDefault)
			}
			if err := runProgram(f.tx, f.policy, f.prevouts()); err == nil {
				t.Fatal("program must reject attack")
			}
			f.signSavings(t, f.authorities...)
			for i := range f.tx.TxIn {
				if err := verifyInput(f.tx, f.prevouts(), i); err != nil {
					t.Fatalf("counterexample invalid: %v", err)
				}
			}
		})
	}
}

func TestCandidateStillRequiresEverySavingsAuthority(t *testing.T) {
	for missing := 0; missing < 3; missing++ {
		t.Run([]string{"phone", "guardian", "emulator"}[missing], func(t *testing.T) {
			f := newFixture(t)
			keys := append([]*btcec.PrivateKey(nil), f.authorities...)
			keys[missing] = f.attacker
			f.signSavings(t, keys...)
			f.signConnector(t, f.hardware, txscript.SigHashDefault)
			if err := verifyInput(f.tx, f.prevouts(), 0); err == nil {
				t.Fatal("missing Savings authority accepted")
			}
		})
	}
}

func TestExistingAdminRequiresHardware(t *testing.T) {
	f := existingFixture(t, "admin")
	f.tx.TxIn = f.tx.TxIn[:1]
	f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.destination)}
	f.signSavings(t, f.phone, f.attacker)
	if err := verifyInput(f.tx, f.prevouts(), 0); err == nil {
		t.Fatal("admin accepted wrong hardware key")
	}
	f.signSavings(t, f.authorities...)
	if err := verifyInput(f.tx, f.prevouts(), 0); err != nil {
		t.Fatal(err)
	}
}

func TestExistingRecoveryInitiationAlsoReliesOnCosignerEnforcement(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		t.Run(network, func(t *testing.T) {
			for _, role := range []string{"phone", "recovery"} {
				t.Run(role, func(t *testing.T) {
					f := existingFixtureFor(t, role, network)
					f.tx.TxIn = f.tx.TxIn[:1]
					f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.attackerScript)}
					if err := runProgram(f.tx, f.policy, f.prevouts()); err == nil {
						t.Fatal("recovery program accepted direct theft")
					}
					// This genuine normal-tree initiate leaf has no Bitcoin timelock. The
					// pending destination/delay is enforced by the online signing programs.
					f.signSavings(t, f.authorities...)
					if err := verifyInput(f.tx, f.prevouts(), 0); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestPresignedCandidateBindsConnectorButOnlyThatTransaction(t *testing.T) {
	f := newFixture(t)
	f.signSavings(t, f.authorities...)
	// Model handing over a fixed signature, with no further signing authority.
	f.signConnector(t, f.hardware, txscript.SigHashDefault)
	if err := verifyInput(f.tx, f.prevouts(), 0); err != nil {
		t.Fatal(err)
	}
	f.tx.TxOut[0].Value-- // Even an ordinary fee adjustment needs a new presignature.
	f.signConnector(t, f.hardware, txscript.SigHashDefault)
	if err := verifyInput(f.tx, f.prevouts(), 0); err == nil {
		t.Fatal("presignature allowed a changed fee")
	}
	f.tx.TxIn = f.tx.TxIn[:1]
	f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.attackerScript)}
	if err := verifyInput(f.tx, f.prevouts(), 0); err == nil {
		t.Fatal("presignature permitted omitted connector")
	}
}
