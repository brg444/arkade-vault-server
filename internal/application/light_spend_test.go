package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestLightReservationKeepsPolicyChangeAndScopedKeys(t *testing.T) {
	svc, token, start, enroll, owner := lightEnrollmentFixture(t, true)
	if _, err := svc.FinishLightEnrollment(context.Background(), token, enroll); err != nil {
		t.Fatal(err)
	}
	snap := svc.snapshot(start.VaultID)
	tree, err := svc.buildVtxoPolicyTree(start.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubArkResolver{signer: svc.operatorSignerPub(), checkpoint: []byte{0xc0, 0x01}, vtxos: []ports.ResolvedVtxo{{Txid: strings.Repeat("15", 32), Vout: 1, ValueSats: 80_000, Script: tree.PkScript}}}
	svc.ArkResolver = resolver
	target, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	operator, err := btcec.ParsePubKey(resolver.signer)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := (&arklib.Address{Version: 0, HRP: arklib.BitcoinMutinyNet.Addr, Signer: operator, VtxoTapKey: target.PubKey()}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{svc: svc, hot: owner}
	request := signedReserveRequest(t, e, VtxoReserveRequest{OperationID: strings.Repeat("41", 16), VaultID: start.VaultID, Purpose: policy.VtxoPurposeSpend, DestAddress: dest, AmountSats: 30_000})
	missing := request
	missing.PhoneSignature = ""
	if _, err := svc.ReserveVtxo(context.Background(), missing); err == nil {
		t.Fatal("unsigned reservation accepted")
	}
	over := request
	over.AmountSats = 50_001
	over = signedReserveRequest(t, e, over)
	if _, err := svc.ReserveVtxo(context.Background(), over); err == nil {
		t.Fatal("Light per-payment cap bypassed")
	}
	first, err := svc.ReserveVtxo(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ChangeScript != hex.EncodeToString(tree.PkScript) || first.ChangeSats == 0 {
		t.Fatalf("change escaped Light: %+v", first)
	}
	replay, err := svc.ReserveVtxo(context.Background(), request)
	if err != nil || replay.BundleDigest != first.BundleDigest {
		t.Fatalf("lost-response replay changed reservation: %v", err)
	}
	changed := request
	changed.AmountSats = 10_000
	changed = signedReserveRequest(t, e, changed)
	if _, err := svc.ReserveVtxo(context.Background(), changed); err == nil {
		t.Fatal("same reservation id accepted different payment")
	}
	ctx, err := svc.vtxoKeyContext(start.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	lightPub, err := svc.keys.vtxoPublic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx.lightProfile = false
	legacyPub, err := svc.keys.vtxoPublic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(lightPub.SerializeCompressed(), legacyPub.SerializeCompressed()) {
		t.Fatal("Light reused legacy signing domain")
	}
	if err := svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	after, err := svc.ReserveVtxo(context.Background(), request)
	if err != nil || after.BundleDigest != first.BundleDigest {
		t.Fatalf("restart reservation replay: %v", err)
	}
}

func TestLightSignedSpendAndLostResponse(t *testing.T) {
	f := newLightEnrollmentFixture(t, true)
	if _, err := f.env.svc.FinishLightEnrollment(context.Background(), f.token, f.request); err != nil {
		t.Fatal(err)
	}
	signer := f.env.svc.operatorSignerPub()
	operator, err := btcec.ParsePubKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubArkResolver{signer: signer}
	f.env.svc.ArkResolver = resolver
	assertVtxoSpendLostResponse(t, f.env, resolver, operator, f.start.VaultID)
}
