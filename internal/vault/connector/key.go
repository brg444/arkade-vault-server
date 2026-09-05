package connector

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

type Kind string

const (
	Taproot      Kind = "p2tr"
	NativeSegwit Kind = "p2wpkh"
)

func (k Kind) Purpose() uint32 {
	if k == NativeSegwit {
		return 0x80000054
	}
	return 0x80000056
}

func (k Kind) Script(key *btcec.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("connector key required")
	}
	switch k {
	case Taproot:
		return txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(key))
	case NativeSegwit:
		return txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(btcutil.Hash160(key.SerializeCompressed())).Script()
	default:
		return nil, fmt.Errorf("unsupported connector type")
	}
}

func (o KeyOrigin) Kind() (Kind, error) {
	if o.Type != Taproot && o.Type != NativeSegwit {
		return "", fmt.Errorf("connector type required")
	}
	p := o.Path
	if len(p) < 1 || len(p) > 255 {
		return "", fmt.Errorf("invalid BIP32 origin depth")
	}
	// BIP84/BIP86 have standard network and address-path semantics. Electrum
	// native seeds use m/0'/change/index instead, which is also a valid origin.
	if p[0] == NativeSegwit.Purpose() || p[0] == Taproot.Purpose() {
		if len(p) != 5 || p[0] != o.Type.Purpose() || (p[1] != 0x80000000 && p[1] != 0x80000001) || p[2] < 0x80000000 || p[3] > 1 || p[4] >= 0x80000000 {
			return "", fmt.Errorf("BIP84 or BIP86 origin mismatch")
		}
	}
	return o.Type, nil
}
