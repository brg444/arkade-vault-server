// Package connector implements the unreleased Savings connector candidate.
// It is not registered in a profile or reachable from the authorizer binary.
package connector

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	Name                      = "savings-connector-v1"
	ReserveSats         int64 = 1000
	SavingsInput              = 0
	ConnectorInput            = 1
	DestinationOutput         = 0
	SavingsChangeOutput       = 4
	ConnectorOutput           = 1
	AnchorOutput              = 2
	PacketOutput              = 3
)

// Rules are reconstructed from an independently pinned enrollment, never from
// the signer response. WitnessBytes bounds marker/flag and both witnesses from below.
// This stage supports one Savings input and optional non-dust Savings change.
type Rules struct {
	ConnectorScript                                     []byte
	WitnessBytes, AbsoluteFeeCapSats, FeerateCapSatPerV int64
}

func validP2TR(script []byte) bool {
	if len(script) != 34 || script[0] != txscript.OP_1 || script[1] != 32 {
		return false
	}
	_, err := schnorr.ParsePubKey(script[2:])
	return err == nil
}

func (r Rules) validate() error {
	if !validP2TR(r.ConnectorScript) && !txscript.IsPayToWitnessPubKeyHash(r.ConnectorScript) {
		return fmt.Errorf("connector native SegWit or Taproot script required")
	}
	if r.WitnessBytes < 1 || r.WitnessBytes > 10000 {
		return fmt.Errorf("invalid committed witness size")
	}
	if r.AbsoluteFeeCapSats < program.MinAbsoluteFeeCapSats || r.AbsoluteFeeCapSats > program.MaxAbsoluteFeeCapSats ||
		r.FeerateCapSatPerV < program.MinFeerateCapSatPerV || r.FeerateCapSatPerV > program.MaxFeerateCapSatPerV {
		return fmt.Errorf("invalid fee policy")
	}
	return nil
}

// BuildProgram commits the connector identity, reserve,
// protected change, packet envelope, and both fee limits in both cosigner keys.
// Bitcoin enforces the resulting signatures, not these introspection opcodes.
func BuildProgram(r Rules) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	var prefix []byte
	for range 8 {
		script, err := assemble(r, prefix)
		if err != nil {
			return nil, err
		}
		entry, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: SavingsInput, Script: make([]byte, len(script))})
		if err != nil {
			return nil, err
		}
		content, err := entry.Serialize()
		if err != nil {
			return nil, err
		}
		output, err := (extension.Extension{entry}).Serialize()
		if err != nil {
			return nil, err
		}
		if len(output) <= len(content) || !bytes.HasSuffix(output, content) {
			return nil, fmt.Errorf("noncanonical packet envelope")
		}
		next := output[:len(output)-len(content)]
		if bytes.Equal(next, prefix) {
			return script, nil
		}
		prefix = next
	}
	return nil, fmt.Errorf("connector packet envelope did not converge")
}

func PacketScript(script []byte) ([]byte, error) {
	p, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: SavingsInput, Script: script})
	if err != nil {
		return nil, err
	}
	return (extension.Extension{p}).Serialize()
}

func assemble(r Rules, prefix []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder().AddData([]byte(Name)).AddOp(txscript.OP_DROP)
	equal := func(op byte, n int64) { b.AddOp(op).AddInt64(n).AddOp(txscript.OP_EQUALVERIFY) }
	equal(arkade.OP_INSPECTVERSION, 2)
	equal(arkade.OP_INSPECTLOCKTIME, 0)
	equal(arkade.OP_INSPECTNUMINPUTS, 2)
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddOp(txscript.OP_DUP).AddInt64(4).AddOp(txscript.OP_EQUAL).
		AddOp(txscript.OP_SWAP).AddInt64(5).AddOp(txscript.OP_EQUAL).AddOp(txscript.OP_BOOLOR).AddOp(txscript.OP_VERIFY)
	for i := int64(0); i < 2; i++ {
		b.AddInt64(i)
		equal(arkade.OP_INSPECTINPUTSEQUENCE, savings.TransitionSequence)
	}
	checkScript := func(op byte, index int64, script []byte) {
		version := int64(0)
		if script[0] == txscript.OP_1 {
			version = 1
		}
		b.AddInt64(index).AddOp(op).AddInt64(version).AddOp(txscript.OP_EQUALVERIFY).
			AddData(script[2:]).AddOp(txscript.OP_EQUALVERIFY)
	}
	checkScript(arkade.OP_INSPECTINPUTSCRIPTPUBKEY, ConnectorInput, r.ConnectorScript)
	checkScript(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, ConnectorOutput, r.ConnectorScript)
	checkScript(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, AnchorOutput, []byte{0x51, 0x02, 0x4e, 0x73})
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddInt64(5).AddOp(txscript.OP_EQUAL).AddOp(txscript.OP_IF)
	b.AddInt64(SavingsInput).AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).AddOp(txscript.OP_TOALTSTACK).
		AddInt64(SavingsChangeOutput).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).AddOp(txscript.OP_FROMALTSTACK).
		AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(SavingsChangeOutput).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(program.DustSats).
		AddOp(txscript.OP_GREATERTHANOREQUAL).AddOp(txscript.OP_VERIFY).AddOp(txscript.OP_ENDIF)
	b.AddInt64(ConnectorInput)
	equal(arkade.OP_INSPECTINPUTVALUE, ReserveSats)
	b.AddInt64(ConnectorOutput)
	equal(arkade.OP_INSPECTOUTPUTVALUE, ReserveSats)
	b.AddInt64(AnchorOutput)
	equal(arkade.OP_INSPECTOUTPUTVALUE, savings.P2AValueSats)
	b.AddInt64(PacketOutput)
	equal(arkade.OP_INSPECTOUTPUTVALUE, 0)
	b.AddInt64(DestinationOutput).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(294).
		AddOp(txscript.OP_GREATERTHANOREQUAL).AddOp(txscript.OP_VERIFY)
	b.AddInt64(int64(arkade.PacketType)).AddOp(arkade.OP_INSPECTPACKET).AddOp(txscript.OP_VERIFY).
		AddData(prefix).AddOp(txscript.OP_SWAP).AddOp(arkade.OP_CAT).AddOp(txscript.OP_SHA256).
		AddInt64(PacketOutput).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).AddInt64(-1).
		AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_EQUALVERIFY)
	// The reserve cancels out. Savings funds the miner fee and 240-sat anchor.
	b.AddInt64(SavingsInput).AddOp(arkade.OP_INSPECTINPUTVALUE)
	for _, i := range []int64{DestinationOutput, AnchorOutput} {
		b.AddInt64(i).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddOp(txscript.OP_SUB)
	}
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddInt64(5).AddOp(txscript.OP_EQUAL).AddOp(txscript.OP_IF).
		AddInt64(SavingsChangeOutput).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddOp(txscript.OP_SUB).AddOp(txscript.OP_ENDIF)
	b.AddOp(txscript.OP_DUP).AddInt64(0).AddOp(txscript.OP_GREATERTHANOREQUAL).AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DUP).AddInt64(r.AbsoluteFeeCapSats).AddOp(txscript.OP_LESSTHANOREQUAL).AddOp(txscript.OP_VERIFY).
		AddOp(arkade.OP_TXWEIGHT).AddInt64(r.WitnessBytes).AddOp(txscript.OP_ADD).
		AddInt64(3).AddOp(txscript.OP_ADD).AddInt64(4).AddOp(txscript.OP_DIV).
		AddInt64(r.FeerateCapSatPerV).AddOp(txscript.OP_MUL).AddOp(txscript.OP_LESSTHANOREQUAL)
	return b.Script()
}

// Parents must originate in the chain verifier. Hash/content checks here prove
// prevout contents; they do not prove confirmation, unspentness, or freshness.
type Parents map[wire.OutPoint]*wire.MsgTx

func (p Parents) FetchPrevOutput(op wire.OutPoint) *wire.TxOut {
	tx := p[op]
	if tx == nil || tx.TxHash() != op.Hash || uint64(op.Index) >= uint64(len(tx.TxOut)) {
		return nil
	}
	return tx.TxOut[op.Index]
}
func (p Parents) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if p.FetchPrevOutput(op) == nil {
		return nil
	}
	return p[op]
}
func (p Parents) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if out := p.FetchPrevOutput(op); out != nil {
		return out.PkScript
	}
	return nil
}

func Validate(r Rules, tx *wire.MsgTx, parents Parents) error {
	if tx == nil || len(tx.TxIn) != 2 || (len(tx.TxOut) != 4 && len(tx.TxOut) != 5) {
		return fmt.Errorf("connector transaction shape")
	}
	if tx.TxIn[0] == nil || tx.TxIn[1] == nil || tx.TxIn[0].PreviousOutPoint == tx.TxIn[1].PreviousOutPoint {
		return fmt.Errorf("distinct inputs required")
	}
	var total int64
	for _, in := range tx.TxIn {
		out := parents.FetchPrevOutput(in.PreviousOutPoint)
		if out == nil || out.Value <= 0 || out.Value > 21_000_000*100_000_000 || len(in.SignatureScript) != 0 || len(in.Witness) != 0 {
			return fmt.Errorf("unverified or noncanonical input")
		}
		total += out.Value
	}
	if total > 21_000_000*100_000_000 {
		return fmt.Errorf("input value range")
	}
	for _, out := range tx.TxOut {
		if out == nil || out.Value < 0 || out.Value > total {
			return fmt.Errorf("output value range")
		}
		total -= out.Value
	}
	dust, err := RecipientDust(tx.TxOut[DestinationOutput].PkScript)
	if err != nil || tx.TxOut[DestinationOutput].Value < dust {
		return fmt.Errorf("invalid or dust recipient")
	}
	script, err := BuildProgram(r)
	if err != nil {
		return err
	}
	wantPacket, err := PacketScript(script)
	if err != nil {
		return err
	}
	if !bytes.Equal(tx.TxOut[PacketOutput].PkScript, wantPacket) {
		return fmt.Errorf("unexpected connector packet")
	}
	s := parents.FetchPrevOutput(tx.TxIn[SavingsInput].PreviousOutPoint).PkScript
	if !validP2TR(s) || bytes.Equal(s, r.ConnectorScript) {
		return fmt.Errorf("distinct Savings script required")
	}
	engine, err := arkade.NewEngine(script, tx, SavingsInput, nil, txscript.NewTxSigHashes(tx, parents), parents.FetchPrevOutput(tx.TxIn[0].PreviousOutPoint).Value, parents)
	if err != nil {
		return err
	}
	return engine.Execute()
}

// RecipientDust permits the ordinary address formats supported by Bitcoin
// wallets. The program's 294-sat floor is the smallest standard threshold;
// semantic validation applies the exact script-specific threshold here.
func RecipientDust(script []byte) (int64, error) {
	switch txscript.GetScriptClass(script) {
	case txscript.PubKeyHashTy:
		return 546, nil
	case txscript.ScriptHashTy:
		return 540, nil
	case txscript.WitnessV0PubKeyHashTy:
		return 294, nil
	case txscript.WitnessV0ScriptHashTy, txscript.WitnessV1TaprootTy:
		return 330, nil
	default:
		return 0, fmt.Errorf("unsupported Bitcoin payment script")
	}
}
