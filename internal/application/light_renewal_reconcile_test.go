package application

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestLightRenewalIndexerRejectsSubstitutedSettlement(t *testing.T) {
	p := lightRenewalPlan{Txid: strings.Repeat("01", 32), ValueSats: 80000, ReceiverSats: 79900}
	f := verifiedLightRenewalFinal{CommitmentTxid: strings.Repeat("02", 32), ReceiverTxid: strings.Repeat("03", 32)}
	zero := uint32(0)
	swept := false
	commitments := []string{f.CommitmentTxid}
	old := indexerVtxo{Outpoint: indexerOutpoint{p.Txid, &zero}, Amount: json.RawMessage(`"80000"`), Script: "51", CreatedAt: json.RawMessage(`"100"`), ExpiresAt: json.RawMessage(`"200"`), IsSwept: &swept, CommitmentTxids: &commitments, IsSpent: true, SettledBy: f.CommitmentTxid}
	next := old
	next.Outpoint.Txid = f.ReceiverTxid
	next.Amount = json.RawMessage(`"79900"`)
	next.ExpiresAt = json.RawMessage(`"300"`)
	next.IsSpent = false
	for name, mutate := range map[string]func([]indexerVtxo) []indexerVtxo{
		"valid":               func(v []indexerVtxo) []indexerVtxo { return v },
		"missing replacement": func(v []indexerVtxo) []indexerVtxo { return v[:1] },
		"wrong settlement":    func(v []indexerVtxo) []indexerVtxo { v[0].SettledBy = strings.Repeat("04", 32); return v },
		"unspent old":         func(v []indexerVtxo) []indexerVtxo { v[0].IsSpent = false; return v },
		"changed principal":   func(v []indexerVtxo) []indexerVtxo { v[1].Amount = json.RawMessage(`"79899"`); return v },
		"changed script":      func(v []indexerVtxo) []indexerVtxo { v[1].Script = "52"; return v },
		"same expiry":         func(v []indexerVtxo) []indexerVtxo { v[1].ExpiresAt = v[0].ExpiresAt; return v },
		"missing commitment":  func(v []indexerVtxo) []indexerVtxo { empty := []string{}; v[1].CommitmentTxids = &empty; return v },
		"duplicate":           func(v []indexerVtxo) []indexerVtxo { return append(v, v[1]) },
		"unrelated":           func(v []indexerVtxo) []indexerVtxo { v[1].Outpoint.Txid = strings.Repeat("05", 32); return v },
	} {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(indexerVtxoPage{Vtxos: mutate([]indexerVtxo{old, next}), Page: &indexerPage{Current: 1, Next: 1, Total: 1}})
			if err != nil {
				t.Fatal(err)
			}
			r := &arkResolver{origin: "https://mutinynet.arkade.sh", hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) { return jsonResponse(200, string(body)), nil })}
			ok, err := r.lightRenewalSettled(context.Background(), p, f, []byte{0x51})
			if name == "valid" {
				if err != nil || !ok {
					t.Fatalf("valid replacement: %v", err)
				}
			} else if ok {
				t.Fatal("substituted settlement accepted")
			}
		})
	}
}
