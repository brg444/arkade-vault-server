package application

import (
	"bytes"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type vtxoPolicyTree struct {
	CosignerPub     *btcec.PublicKey
	DelegatePub     *btcec.PublicKey
	ArkdPub         *btcec.PublicKey
	TapKey          *btcec.PublicKey
	PkScript        []byte
	SpendLeaf       []byte
	DelegateLeaf    []byte
	SpendControl    []byte
	DelegateControl []byte
	RevealedScripts []string
	ArkAddress      string
	OnchainAddress  string
}

type vtxoBoardTree struct {
	BoardingPub     *btcec.PublicKey
	CosignerPub     *btcec.PublicKey
	OperatorPub     *btcec.PublicKey
	PkScript        []byte
	Collaborative   []byte
	ControlBlock    []byte
	RevealedScripts []string
	OnchainAddress  string
}

func (s *Service) operatorSignerPub() []byte {
	if s == nil || isNilInterface(s.ArkResolver) {
		return nil
	}
	return s.ArkResolver.OperatorSignerPub()
}

func (s *Service) vtxoKeyContext(vaultID string) (vtxoKeyContext, error) {
	operator := s.operatorSignerPub()
	cfg := s.runtimeConfig()
	context, err := newVtxoKeyContext(vaultID, cfg.Network, operator)
	context.lightProfile = s.snapshot(vaultID).Light != nil
	return context, err
}

func (s *Service) buildVtxoPolicyTree(vaultID string, snap enrolledSnapshot) (*vtxoPolicyTree, error) {
	if snap.Light != nil {
		return s.buildLightPolicyTree(*snap.Light)
	}
	if snap.PhoneBIP340 == nil || snap.ExternalOwnerWallet == nil {
		return nil, fmt.Errorf("enrolled keys required")
	}
	keyContext, err := s.vtxoKeyContext(vaultID)
	if err != nil {
		return nil, err
	}
	cosigner, err := s.keys.vtxoPublic(keyContext)
	if err != nil {
		return nil, err
	}
	operator := s.operatorSignerPub()
	arkd, err := btcec.ParsePubKey(operator)
	if err != nil {
		return nil, fmt.Errorf("Operator signer pubkey")
	}
	pins, err := program.PinsFor(s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	delegate, err := btcec.ParsePubKey(mustDecodeCompressed(pins.DelegatePub))
	if err != nil {
		return nil, fmt.Errorf("pinned public delegate")
	}
	params := policy.VaultPolicyV1Params{
		UserPub:              schnorr.SerializePubKey(snap.PhoneBIP340),
		VtxoVaultCosignerPub: schnorr.SerializePubKey(cosigner),
		ArkdServerPub:        schnorr.SerializePubKey(arkd),
		DelegatePub:          schnorr.SerializePubKey(delegate),
		ExitDevicePub:        schnorr.SerializePubKey(snap.PhoneBIP340),
		ExitHardwarePub:      schnorr.SerializePubKey(snap.ExternalOwnerWallet),
		Network:              s.runtimeConfig().Network,
	}
	if snap.RecoveryKey != nil {
		params.ExitRecoveryPub = schnorr.SerializePubKey(snap.RecoveryKey)
	}
	encoded, err := policy.BuildVaultPolicyV1Tree(params)
	if err != nil {
		return nil, err
	}
	tapKey, err := schnorr.ParsePubKey(encoded.TapKey)
	if err != nil {
		return nil, err
	}
	arkAddr := &arklib.Address{Version: 0, HRP: s.vtxoAddrHRP(), Signer: arkd, VtxoTapKey: tapKey}
	addr, err := arkAddr.EncodeV0()
	if err != nil {
		return nil, err
	}
	net, err := vtxoNetworkParams(s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	onchain, err := btcutil.NewAddressTaproot(encoded.TapKey, net)
	if err != nil {
		return nil, err
	}
	return &vtxoPolicyTree{
		CosignerPub:     cosigner,
		DelegatePub:     delegate,
		ArkdPub:         arkd,
		TapKey:          tapKey,
		PkScript:        encoded.PkScript,
		SpendLeaf:       encoded.SpendScript,
		DelegateLeaf:    encoded.DelegateScript,
		SpendControl:    encoded.SpendControlBlock,
		DelegateControl: encoded.DelegateControlBlock,
		RevealedScripts: encoded.RevealedScripts,
		ArkAddress:      addr,
		OnchainAddress:  onchain.EncodeAddress(),
	}, nil
}

func mustDecodeCompressed(hex33 string) []byte {
	raw, err := hex.DecodeString(hex33)
	if err != nil || len(raw) != 33 {
		return nil
	}
	return raw
}

func vtxoNetworkParams(name string) (*chaincfg.Params, error) {
	switch name {
	case program.NetworkMutinynet:
		return &arklib.MutinyNetSigNetParams, nil
	case program.NetworkMainnet:
		return &chaincfg.MainNetParams, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", name)
	}
}

func defaultVtxoPkScript(user, arkd *btcec.PublicKey, exitDelay uint32) []byte {
	if user == nil || arkd == nil {
		return nil
	}
	exit := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay}
	def := arkscript.NewDefaultVtxoScript(user, arkd, exit)
	tap, _, err := def.TapTree()
	if err != nil {
		return nil
	}
	pk, err := arkscript.P2TRScript(tap)
	if err != nil {
		return nil
	}
	return pk
}

func (s *Service) buildVtxoBoardTree(vaultID string, snap enrolledSnapshot, boarding *btcec.PublicKey) (*vtxoBoardTree, error) {
	network := s.runtimeConfig().Network
	pins, err := program.PinsFor(network)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1: %w", err)
	}
	if vaultID == "" || snap.PhoneBIP340 == nil || boarding == nil {
		return nil, fmt.Errorf("vault-board-v1 enrolled phone and boarding keys required")
	}
	operator, err := btcec.ParsePubKey(s.operatorSignerPub())
	if err != nil {
		return nil, fmt.Errorf("Operator signer pubkey")
	}
	keyContext, err := newVaultBoardKeyContext(vaultID, network, operator.SerializeCompressed())
	if err != nil {
		return nil, err
	}
	cosigner, err := s.keys.vaultBoardPublic(keyContext)
	if err != nil {
		return nil, err
	}
	if err := requireDistinctVaultBoardRoles(boarding, cosigner, snap.PhoneBIP340, operator); err != nil {
		return nil, err
	}
	exit := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{snap.PhoneBIP340}},
		Locktime: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: pins.BoardExitDelay,
		},
	}
	cooperative := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{boarding, cosigner, operator}}
	// Match the official TypeScript SDK's BoardingProgramScript encoding:
	// collaborative leaf first, recovery leaf second. Taproot's two-leaf root
	// is independent of this list order, but the intent proof carries the
	// serialized revealed-tree field and both sides must use one canonical form.
	board := &arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{cooperative, exit}}
	tapKey, tapTree, err := board.TapTree()
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 tree: %w", err)
	}
	pkScript, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 script: %w", err)
	}
	leaf, err := cooperative.Script()
	if err != nil {
		return nil, err
	}
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leaf).TapHash())
	if err != nil {
		return nil, err
	}
	revealed, err := board.Encode()
	if err != nil {
		return nil, err
	}
	net, err := vtxoNetworkParams(network)
	if err != nil {
		return nil, err
	}
	address, err := btcutil.NewAddressTaproot(pkScript[2:], net)
	if err != nil {
		return nil, err
	}
	return &vtxoBoardTree{
		BoardingPub: boarding, CosignerPub: cosigner, OperatorPub: operator,
		PkScript: pkScript, Collaborative: leaf, ControlBlock: proof.ControlBlock,
		RevealedScripts: revealed, OnchainAddress: address.EncodeAddress(),
	}, nil
}

func requireDistinctVaultBoardRoles(boarding, cosigner, phone, operator *btcec.PublicKey) error {
	roles := []struct {
		name string
		pub  *btcec.PublicKey
	}{
		{name: "boarding", pub: boarding},
		{name: "VaultBoardCosigner", pub: cosigner},
		{name: "phone recovery", pub: phone},
		{name: "Operator", pub: operator},
	}
	for i := range roles {
		if roles[i].pub == nil {
			return fmt.Errorf("vault-board-v1 %s key required", roles[i].name)
		}
		for j := 0; j < i; j++ {
			// All four roles sign Taproot script paths, so compare their x-only
			// identities rather than compressed-key parity.
			if bytes.Equal(schnorr.SerializePubKey(roles[i].pub), schnorr.SerializePubKey(roles[j].pub)) {
				return fmt.Errorf("vault-board-v1 %s and %s keys must be distinct", roles[j].name, roles[i].name)
			}
		}
	}
	return nil
}

func (s *Service) refuseDefaultVtxoChange(snap enrolledSnapshot, dest []byte) error {
	operator := s.operatorSignerPub()
	if snap.PhoneBIP340 == nil || len(operator) != 33 {
		return nil
	}
	arkd, err := btcec.ParsePubKey(operator)
	if err != nil {
		return nil
	}
	pins, err := program.PinsFor(s.runtimeConfig().Network)
	if err != nil {
		return err
	}
	if bytes.Equal(dest, defaultVtxoPkScript(snap.PhoneBIP340, arkd, pins.ArkdMinExitDelay)) {
		return fmt.Errorf("DefaultVtxo change refused")
	}
	return nil
}
