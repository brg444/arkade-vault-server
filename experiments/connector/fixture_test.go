// All keys and transactions in this package are disposable test fixtures.
// Keeping the experiment in _test.go files excludes it from runtime binaries.
package connector

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const experimentName = "savings-connector-experiment-v0"

type fixture struct {
	phone, hardware, guardian, emulator, attacker                 *btcec.PrivateKey
	policy, savingsScript, connector, destination, attackerScript []byte
	leaf                                                          txscript.TapLeaf
	control                                                       []byte
	authorities                                                   []*btcec.PrivateKey
	parent                                                        *wire.MsgTx
	tx                                                            *wire.MsgTx
	family                                                        *savings.Family
}

func must[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func key(n byte) *btcec.PrivateKey {
	k, _ := btcec.PrivKeyFromBytes([]byte{n})
	return k
}

func taproot(t *testing.T, k *btcec.PrivateKey) []byte {
	t.Helper()
	s, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(k.PubKey()))
	return must(t, s, err)
}

// The program inspects the actual connector prevout, pins the boarding output,
// preserves Savings change and the reserve, and caps the fee. It is executed by
// the pinned interpreter, not by Bitcoin. This fixture has three outputs and no
// Emulator packet or P2A output; it is not a production transition format.
func connectorProgram(t *testing.T, connector, destination []byte) []byte {
	t.Helper()
	b := txscript.NewScriptBuilder().AddData([]byte(experimentName)).AddOp(txscript.OP_DROP).
		AddOp(arkade.OP_INSPECTVERSION).AddInt64(2).AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTLOCKTIME).AddInt64(0).AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(2).AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddInt64(3).AddOp(txscript.OP_EQUALVERIFY)
	checkScript := func(op byte, index int64, script []byte) {
		b.AddInt64(index).AddOp(op).AddInt64(1).AddOp(txscript.OP_EQUALVERIFY).
			AddData(script[2:]).AddOp(txscript.OP_EQUALVERIFY)
	}
	checkScript(arkade.OP_INSPECTINPUTSCRIPTPUBKEY, 1, connector)
	checkScript(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, 0, destination)
	checkScript(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, 2, connector)
	// Compare both witness versions and programs for Savings change. Referring
	// to input zero avoids a circular commitment to this program's tweaked key.
	b.AddInt64(0).AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).AddOp(txscript.OP_TOALTSTACK).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).AddOp(txscript.OP_FROMALTSTACK).
		AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTINPUTVALUE).AddInt64(1000).AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(2).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(1000).AddOp(txscript.OP_EQUALVERIFY)
	for i := int64(0); i < 2; i++ {
		b.AddInt64(i).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(330).
			AddOp(txscript.OP_GREATERTHANOREQUAL).AddOp(txscript.OP_VERIFY)
	}
	b.AddInt64(0).AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddOp(txscript.OP_SUB).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddOp(txscript.OP_SUB).
		AddOp(txscript.OP_DUP).AddInt64(0).AddOp(txscript.OP_GREATERTHANOREQUAL).AddOp(txscript.OP_VERIFY).
		AddInt64(1000).AddOp(txscript.OP_LESSTHANOREQUAL)
	s, err := b.Script()
	return must(t, s, err)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{phone: key(3), hardware: key(4), guardian: key(14), emulator: key(15), attacker: key(16)}
	f.connector, f.destination, f.attackerScript = taproot(t, f.hardware), taproot(t, key(17)), taproot(t, f.attacker)
	f.policy = connectorProgram(t, f.connector, f.destination)
	hash := arkade.ArkadeScriptHash(f.policy)
	f.authorities = []*btcec.PrivateKey{f.phone,
		arkade.ComputeArkadeScriptPrivateKey(f.guardian, hash),
		arkade.ComputeArkadeScriptPrivateKey(f.emulator, hash)}
	s, err := savings.Checksig(f.authorities[0].PubKey(), f.authorities[1].PubKey(), f.authorities[2].PubKey())
	s = must(t, s, err)
	internal, err := savings.ContextInternalKey("connector-fixture", "savings", "")
	f.setTree(t, must(t, internal, err), [][]byte{s}, 0)
	f.setParent()
	return f
}

func (f *fixture) setTree(t *testing.T, internal *btcec.PublicKey, scripts [][]byte, selected int) {
	t.Helper()
	leaves := make([]txscript.TapLeaf, len(scripts))
	for i, script := range scripts {
		leaves[i] = txscript.NewBaseTapLeaf(script)
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tree.RootNode.TapHash()
	s, err := txscript.PayToTaprootScript(txscript.ComputeTaprootOutputKey(internal, root[:]))
	f.savingsScript = must(t, s, err)
	f.leaf = leaves[selected]
	proof := tree.LeafMerkleProofs[tree.LeafProofIndex[f.leaf.TapHash()]]
	control := proof.ToControlBlock(internal)
	c, err := control.ToBytes()
	f.control = must(t, c, err)
}

func (f *fixture) setParent() {
	f.parent = wire.NewMsgTx(2)
	f.parent.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 99}, nil, nil))
	f.parent.AddTxOut(wire.NewTxOut(10000, f.savingsScript))
	f.parent.AddTxOut(wire.NewTxOut(1000, f.connector))
	f.parent.AddTxOut(wire.NewTxOut(1000, f.attackerScript))
	f.parent.AddTxOut(wire.NewTxOut(1000, f.connector))
	f.resetSpend()
}

func (f *fixture) resetSpend() {
	f.tx = wire.NewMsgTx(2)
	for _, index := range []uint32{0, 1} {
		in := wire.NewTxIn(&wire.OutPoint{Hash: f.parent.TxHash(), Index: index}, nil, nil)
		in.Sequence = 0xfffffffd
		f.tx.AddTxIn(in)
	}
	f.tx.AddTxOut(wire.NewTxOut(8000, f.destination))
	f.tx.AddTxOut(wire.NewTxOut(1500, f.savingsScript))
	f.tx.AddTxOut(wire.NewTxOut(1000, f.connector))
}

type prevouts map[wire.OutPoint]*wire.MsgTx

func (p prevouts) FetchPrevOutput(op wire.OutPoint) *wire.TxOut {
	tx := p[op]
	if tx == nil || tx.TxHash() != op.Hash || int(op.Index) >= len(tx.TxOut) {
		return nil
	}
	return tx.TxOut[op.Index]
}
func (p prevouts) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if p.FetchPrevOutput(op) == nil {
		return nil
	}
	return p[op]
}
func (p prevouts) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if out := p.FetchPrevOutput(op); out != nil {
		return out.PkScript
	}
	return nil
}
func (f *fixture) prevouts() prevouts {
	p := prevouts{}
	for i := range f.parent.TxOut {
		p[wire.OutPoint{Hash: f.parent.TxHash(), Index: uint32(i)}] = f.parent
	}
	return p
}

func verifiedInputs(tx *wire.MsgTx, p prevouts) error {
	seen := map[wire.OutPoint]bool{}
	for _, in := range tx.TxIn {
		if seen[in.PreviousOutPoint] {
			return fmt.Errorf("duplicate input")
		}
		seen[in.PreviousOutPoint] = true
		if p.FetchPrevOutput(in.PreviousOutPoint) == nil {
			return fmt.Errorf("unverified prevout")
		}
	}
	return nil
}

func runProgram(tx *wire.MsgTx, script []byte, p prevouts) error {
	if len(tx.TxIn) == 0 {
		return fmt.Errorf("missing Savings input")
	}
	if err := verifiedInputs(tx, p); err != nil {
		return err
	}
	// The interpreter consumes the PSBT's unsigned transaction. Bitcoin
	// witnesses are checked independently, against the original transaction.
	tx = tx.Copy()
	for _, in := range tx.TxIn {
		in.Witness = nil
	}
	engine, err := arkade.NewEngine(script, tx, 0, nil, txscript.NewTxSigHashes(tx, p), p.FetchPrevOutput(tx.TxIn[0].PreviousOutPoint).Value, p)
	if err != nil {
		return err
	}
	return engine.Execute()
}

func verifyApproval(f *fixture) error {
	if err := runProgram(f.tx, f.policy, f.prevouts()); err != nil {
		return err
	}
	witness := f.tx.TxIn[1].Witness
	if len(witness) != 1 || len(witness[0]) != 64 {
		return fmt.Errorf("connector requires DEFAULT key-path signature")
	}
	return verifyInput(f.tx, f.prevouts(), 1)
}

func verifyInput(tx *wire.MsgTx, p prevouts, index int) error {
	if err := verifiedInputs(tx, p); err != nil {
		return err
	}
	out := p.FetchPrevOutput(tx.TxIn[index].PreviousOutPoint)
	engine, err := txscript.NewEngine(out.PkScript, tx, index, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, p), out.Value, p)
	if err != nil {
		return err
	}
	return engine.Execute()
}

func (f *fixture) signSavings(t *testing.T, keys ...*btcec.PrivateKey) {
	t.Helper()
	p := f.prevouts()
	hashes := txscript.NewTxSigHashes(f.tx, p)
	out := p.FetchPrevOutput(f.tx.TxIn[0].PreviousOutPoint)
	witness := wire.TxWitness{}
	for i := len(keys) - 1; i >= 0; i-- {
		sig, err := txscript.RawTxInTapscriptSignature(f.tx, hashes, 0, out.Value, out.PkScript, f.leaf, txscript.SigHashDefault, keys[i])
		witness = append(witness, must(t, sig, err))
	}
	f.tx.TxIn[0].Witness = append(witness, f.leaf.Script, f.control)
}

func (f *fixture) signConnector(t *testing.T, k *btcec.PrivateKey, hashType txscript.SigHashType) {
	if txscript.IsPayToWitnessPubKeyHash(f.connector) {
		subscript := append([]byte{0x76, 0xa9, 0x14}, f.connector[2:]...)
		subscript = append(subscript, 0x88, 0xac)
		witness, err := txscript.WitnessSignature(f.tx, txscript.NewTxSigHashes(f.tx, f.prevouts()), 1, 1000, subscript, hashType, k, true)
		f.tx.TxIn[1].Witness = must(t, witness, err)
		return
	}

	t.Helper()
	p := f.prevouts()
	out := p.FetchPrevOutput(f.tx.TxIn[1].PreviousOutPoint)
	sig, err := txscript.RawTxInTaprootSignature(f.tx, txscript.NewTxSigHashes(f.tx, p), 1, out.Value, out.PkScript, nil, hashType, k)
	f.tx.TxIn[1].Witness = wire.TxWitness{must(t, sig, err)}
}

// This checks imported PSBT claims against the fixture's independently supplied
// parent transactions. Confirmation and unspentness are separate Core tests.
func verifyPSBT(ptx *psbt.Packet, p prevouts) error {
	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return fmt.Errorf("input metadata count")
	}
	if err := verifiedInputs(ptx.UnsignedTx, p); err != nil {
		return err
	}
	for i, in := range ptx.UnsignedTx.TxIn {
		actual, claim := p.FetchPrevOutput(in.PreviousOutPoint), ptx.Inputs[i].WitnessUtxo
		if claim == nil || claim.Value != actual.Value || !bytes.Equal(claim.PkScript, actual.PkScript) {
			return fmt.Errorf("input %d prevout metadata mismatch", i)
		}
		if ptx.Inputs[i].SighashType != txscript.SigHashDefault {
			return fmt.Errorf("input %d sighash", i)
		}
	}
	return nil
}

// Build the existing full Savings tree through production constructors. The
// selected leaf is either its admin path or a genuine recovery-initiation path.
func existingFixture(t *testing.T, selected string) *fixture {
	t.Helper()
	return existingFixtureFor(t, selected, "mainnet")
}

func existingFixtureFor(t *testing.T, selected, network string) *fixture {
	t.Helper()
	f := newFixture(t)
	direct, err := hex.DecodeString("02c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	direct = must(t, direct, err)
	policy, err := program.DefaultSpendingPolicyFor(network)
	in := savings.FamilyInput{VaultID: "connector-fixture", Network: network, Phone: f.phone.PubKey(), Hardware: f.hardware.PubKey(), Recovery: key(5).PubKey(),
		PhoneDirectP256: direct, VaultCosignerBase: f.guardian.PubKey(), ArkadeCosignerBase: f.emulator.PubKey(),
		ProtectionTier: program.ProtectionTierAdvanced, SpendingPolicy: must(t, policy, err), ServerFreeClawback: true}
	fam, err := savings.BuildFamily(in)
	fam = must(t, fam, err)
	f.family = fam
	admin, err := savings.Checksig(f.phone.PubKey(), f.hardware.PubKey())
	scripts := [][]byte{must(t, admin, err)}
	f.authorities = []*btcec.PrivateKey{f.phone, f.hardware}
	index := 0
	for i, role := range []string{"phone", "hardware", "recovery"} {
		claimant := map[string]*btcec.PrivateKey{"phone": f.phone, "hardware": f.hardware, "recovery": key(5)}[role]
		auth := fam.InitiateAuth[savings.FamilyKey(role)]
		g := arkade.ComputeArkadeScriptPrivateKey(f.guardian, arkade.ArkadeScriptHash(auth))
		e := arkade.ComputeArkadeScriptPrivateKey(f.emulator, arkade.ArkadeScriptHash(auth))
		s, err := savings.Checksig(claimant.PubKey(), g.PubKey(), e.PubKey())
		scripts = append(scripts, must(t, s, err))
		if selected == role {
			index = i + 1
			f.authorities = []*btcec.PrivateKey{claimant, g, e}
			f.policy = auth
		}
	}
	internal, err := savings.ContextInternalKey(in.VaultID, "savings", "")
	f.setTree(t, must(t, internal, err), scripts, index)
	if !bytes.Equal(f.savingsScript, fam.Savings.PkScript) {
		t.Fatal("fixture differs from production Savings tree")
	}
	f.setParent()
	return f
}

func pendingFixture(t *testing.T, role string) (*fixture, uint32) {
	t.Helper()
	f := existingFixture(t, "admin")
	return pendingFamilyFixture(t, f, role, "connector-fixture", savings.Template)
}

func pendingFamilyFixture(t *testing.T, f *fixture, role, vaultID, template string) (*fixture, uint32) {
	t.Helper()
	keys := map[string]*btcec.PrivateKey{"phone": f.phone, "hardware": f.hardware, "recovery": key(5)}
	delay := map[string]uint32{"phone": program.PhoneRecoveryCSVBlocks, "hardware": program.HardwareRecoveryCSVBlocks, "recovery": program.RecoveryCSVBlocks}[role]
	claim := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{keys[role].PubKey()}},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: delay}}
	s, err := claim.Script()
	scripts := [][]byte{must(t, s, err)}
	pair := f.family.PendingTweaks[savings.FamilyKey(role)]
	var remaining []*btcec.PublicKey
	roles := []string{"phone", "hardware"}
	if _, ok := f.family.Pending["savings-recovery"]; ok {
		roles = append(roles, "recovery")
	}
	for _, guardian := range roles {
		if guardian == role {
			continue
		}
		pub := keys[guardian].PubKey()
		remaining = append(remaining, pub)
		clawback, err := savings.Checksig(pub, pair.Vault, pair.Arkade)
		scripts = append(scripts, must(t, clawback, err))
	}
	free, err := savings.Checksig(remaining...)
	scripts = append(scripts, must(t, free, err), []byte{txscript.OP_RETURN})
	internal, err := savings.ContextInternalKeyTemplate(vaultID, "savings", role, template)
	f.setTree(t, must(t, internal, err), scripts, 0)
	if !bytes.Equal(f.savingsScript, f.family.Pending[savings.FamilyKey(role)].PkScript) {
		t.Fatal("pending fixture differs from production")
	}
	f.authorities = []*btcec.PrivateKey{keys[role]}
	f.setParent()
	return f, delay
}

func txHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b.Bytes())
}

func decodeTx(t *testing.T, raw string) *wire.MsgTx {
	t.Helper()
	b, err := hex.DecodeString(raw)
	b = must(t, b, err)
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	return tx
}
