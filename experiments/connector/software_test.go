package connector

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/program"
	candidate "github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func TestSoftwareSignatureBoundary(t *testing.T) {
	for _, kind := range []candidate.Kind{candidate.Taproot, candidate.NativeSegwit} {
		for _, hashType := range []txscript.SigHashType{txscript.SigHashAll, txscript.SigHashNone, txscript.SigHashSingle, txscript.SigHashAll | txscript.SigHashAnyOneCanPay} {
			t.Run(fmt.Sprintf("%s_%x", kind, hashType), func(t *testing.T) {
				f, fam, origin := softwareFixture(t, kind)
				req := protocolRequest(f, fam.Rules)
				req.Origin = origin
				d, err := candidate.Prepare(req)
				d = must(t, d, err)
				p, err := d.PSBT()
				p = must(t, p, err)
				f.tx = p.UnsignedTx.Copy()
				f.signSavings(t, f.authorities...)
				h, err := d.ForHardware(f.tx.TxIn[0].Witness)
				h = must(t, h, err)
				f.signConnector(t, f.hardware, hashType)
				raw, err := hex.DecodeString(txHex(t, f.tx))
				raw = must(t, raw, err)
				_, err = h.AcceptTransaction(raw)
				if (err == nil) != (hashType == txscript.SigHashAll) {
					t.Fatalf("unexpected sighash result: %v", err)
				}
				if hashType != txscript.SigHashAll {
					return
				}
				f.tx.TxIn[1].Witness[0][10] ^= 1
				raw, err = hex.DecodeString(txHex(t, f.tx))
				if _, err := h.AcceptTransaction(must(t, raw, err)); err == nil {
					t.Fatal("invalid signature accepted")
				}
				f.signConnector(t, key(71), txscript.SigHashAll)
				raw, err = hex.DecodeString(txHex(t, f.tx))
				if _, err := h.AcceptTransaction(must(t, raw, err)); err == nil {
					t.Fatal("unregistered connector key accepted")
				}
			})
		}
	}
}

// Deliberately public fixture seed. Never use it outside isolated tests.
func softwareKey(t *testing.T, network string, kind candidate.Kind) (*btcec.PrivateKey, candidate.KeyOrigin) {
	t.Helper()
	coin := uint32(0x80000000)
	if network == "mutinynet" {
		coin++
	}
	return derivedSoftwareKey(t, bytes.Repeat([]byte{0x42}, 32), kind, []uint32{kind.Purpose(), coin, 0x80000000, 0, 0})
}

func electrumKey(t *testing.T) (*btcec.PrivateKey, candidate.KeyOrigin) {
	// Public Electrum upstream test fixture, never a user wallet.
	seed := pbkdf2.Key([]byte("bitter grass shiver impose acquire brush forget axis eager alone wine silver"), []byte("electrum"), 2048, 64, sha512.New)
	return derivedSoftwareKey(t, seed, candidate.NativeSegwit, []uint32{0x80000000, 0, 0})
}

func derivedSoftwareKey(t *testing.T, seed []byte, kind candidate.Kind, path []uint32) (*btcec.PrivateKey, candidate.KeyOrigin) {
	t.Helper()
	root, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	root = must(t, root, err)
	pub, err := root.ECPubKey()
	pub = must(t, pub, err)
	origin := candidate.KeyOrigin{Type: kind, Fingerprint: binary.BigEndian.Uint32(btcutil.Hash160(pub.SerializeCompressed())[:4]), Path: path}
	child := root
	for _, index := range origin.Path {
		child, err = child.Derive(index)
		child = must(t, child, err)
	}
	priv, err := child.ECPrivKey()
	priv = must(t, priv, err)
	origin.PublicKey = priv.PubKey().SerializeCompressed()
	return priv, origin
}

func softwareFixture(t *testing.T, kind candidate.Kind) (*fixture, *candidate.Family, candidate.KeyOrigin) {
	t.Helper()
	f, _ := protocolFixture(t)
	priv, origin := softwareKey(t, "mainnet", kind)
	in := familyInput(t, "mainnet", program.ProtectionTierStandard)
	in.Hardware = priv.PubKey()
	fam, err := candidate.BuildFamily(in, kind)
	fam = must(t, fam, err)
	f.hardware, f.connector = priv, fam.Rules.ConnectorScript
	f.savingsScript, f.leaf, f.control, f.policy = fam.Recovery.Savings.PkScript, txscript.NewBaseTapLeaf(fam.Leaf), fam.Control, fam.Program
	hash := arkade.ArkadeScriptHash(fam.Program)
	f.authorities = []*btcec.PrivateKey{f.phone, arkade.ComputeArkadeScriptPrivateKey(f.guardian, hash), arkade.ComputeArkadeScriptPrivateKey(f.emulator, hash)}
	f.setParent()
	return f, fam, origin
}

func TestSoftwareWalletCore(t *testing.T) {
	c := startCore(t, "-datacarriersize=100000")
	for _, kind := range []candidate.Kind{candidate.Taproot, candidate.NativeSegwit} {
		t.Run(string(kind), func(t *testing.T) {
			f, fam, origin := softwareFixture(t, kind)
			wif, err := btcutil.NewWIF(f.hardware, &chaincfg.RegressionNetParams, true)
			wif = must(t, wif, err)
			function := "tr"
			if kind == candidate.NativeSegwit {
				function = "wpkh"
			}
			descriptor := fmt.Sprintf("%s(%s)", function, wif.String())
			info := rpc[struct{ Checksum string }](t, c, "getdescriptorinfo", descriptor)
			imported := rpc[[]struct{ Success bool }](t, c, "importdescriptors", []any{map[string]any{"desc": descriptor + "#" + info.Checksum, "timestamp": "now"}})
			if len(imported) != 1 || !imported[0].Success {
				t.Fatal("connector descriptor import failed")
			}
			for _, full := range []bool{false, true} {
				c.fund(t, f)
				req := protocolRequest(f, fam.Rules)
				req.Origin = origin
				if full {
					req.AmountSats = 8760
				}
				d, err := candidate.Prepare(req)
				d = must(t, d, err)
				p, err := d.PSBT()
				p = must(t, p, err)
				// Exercise both named cosigner interpreters, not just Bitcoin signatures.
				for _, signer := range []*btcec.PublicKey{f.guardian.PubKey(), f.emulator.PubKey()} {
					if err := executePacket(p, f, signer); err != nil {
						t.Fatal(err)
					}
				}
				f.tx = p.UnsignedTx.Copy()
				f.signSavings(t, f.authorities...)
				h, err := d.ForHardware(f.tx.TxIn[0].Witness)
				h = must(t, h, err)
				request, err := h.PSBT()
				request = must(t, request, err)
				encoded, err := request.B64Encode()
				encoded = must(t, encoded, err)
				result := rpc[struct {
					PSBT     string
					Complete bool
					Hex      string
				}](t, c, "walletprocesspsbt", encoded, true, "ALL", true)
				if !result.Complete {
					t.Fatal("Core could not sign the connector beside finalized Savings")
				}
				response, err := psbt.NewFromRawBytes(bytes.NewBufferString(result.PSBT), true)
				final, err := h.Accept(must(t, response, err))
				final = must(t, final, err)
				raw, err := hex.DecodeString(result.Hex)
				raw = must(t, raw, err)
				fromRaw, err := h.AcceptTransaction(raw)
				if err != nil || txHex(t, fromRaw) != txHex(t, final) {
					t.Fatalf("raw transaction import: %v", err)
				}
				c.accepted(t, final, true)
				c.mine(t, final)
				// Moving any recipient output after approval invalidates the connector.
				final.TxOut[0].Value--
				mutated, err := hex.DecodeString(txHex(t, final))
				if _, err := h.AcceptTransaction(must(t, mutated, err)); err == nil {
					t.Fatal("changed amount accepted")
				}
			}
		})
	}
}
