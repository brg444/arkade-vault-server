package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// This optional integration test starts its own disposable, peerless regtest
// node. It never connects to an existing RPC service or uses an existing wallet.
type core struct {
	url           string
	client        *http.Client
	miningAddress string
}

func (c *core) request(method string, args ...any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": "connector", "method": method, "params": args})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("connector-regtest", "disposable-local-test")
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var result struct {
		Result json.RawMessage
		Error  *struct {
			Code    int
			Message string
		}
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("%s: %d %s", method, result.Error.Code, result.Error.Message)
	}
	return result.Result, nil
}

func rpc[T any](t *testing.T, c *core, method string, args ...any) T {
	t.Helper()
	raw, err := c.request(method, args...)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func startCore(t *testing.T, extraArgs ...string) *core {
	t.Helper()
	binary := os.Getenv("CONNECTOR_BITCOIND")
	if binary == "" {
		t.Skip("set CONNECTOR_BITCOIND to run isolated Bitcoin Core regtest qualification")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log, err := os.Create(filepath.Join(dir, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-regtest", "-server", "-networkactive=0", "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0", "-listenonion=0",
		"-datadir="+dir, "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", fmt.Sprintf("-rpcport=%d", port),
		"-rpcuser=connector-regtest", "-rpcpassword=disposable-local-test", "-fallbackfee=0.00002000")
	cmd.Args = append(cmd.Args, extraArgs...)
	if len(extraArgs) != 0 {
		t.Logf("explicit regtest policy options: %v", extraArgs)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	c := &core{url: fmt.Sprintf("http://127.0.0.1:%d", port), client: &http.Client{Timeout: 30 * time.Second}}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_, _ = c.request("stop")
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		_ = log.Close()
		if t.Failed() {
			if data, err := os.ReadFile(filepath.Join(dir, "node.log")); err == nil {
				if len(data) > 4000 {
					data = data[len(data)-4000:]
				}
				t.Log(string(data))
			}
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := c.request("getblockchaininfo"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("regtest RPC startup timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	info := rpc[struct{ Chain string }](t, c, "getblockchaininfo")
	if info.Chain != "regtest" {
		t.Fatal("refusing non-regtest node")
	}
	version := rpc[struct{ Subversion string }](t, c, "getnetworkinfo")
	t.Logf("Bitcoin Core %s; isolated datadir; peers disabled", version.Subversion)
	rpc[json.RawMessage](t, c, "createwallet", "connector-fixtures")
	c.url += "/wallet/connector-fixtures"
	c.miningAddress = rpc[string](t, c, "getnewaddress", "", "bech32m")
	rpc[[]string](t, c, "generatetoaddress", 101, c.miningAddress)
	return c
}

func (c *core) fund(t *testing.T, f *fixture) {
	t.Helper()
	parent := f.parent.Copy()
	parent.TxIn = nil
	funded := rpc[struct{ Hex string }](t, c, "fundrawtransaction", txHex(t, parent), map[string]any{"changePosition": len(parent.TxOut)})
	signed := rpc[struct {
		Hex      string
		Complete bool
	}](t, c, "signrawtransactionwithwallet", funded.Hex)
	if !signed.Complete {
		t.Fatal("fixture funding incomplete")
	}
	rpc[string](t, c, "sendrawtransaction", signed.Hex)
	rpc[[]string](t, c, "generatetoaddress", 1, c.miningAddress)
	f.parent = decodeTx(t, signed.Hex)
	f.resetSpend()
}

func (c *core) accepted(t *testing.T, tx *wire.MsgTx, want bool) {
	t.Helper()
	result := rpc[[]struct {
		Allowed      bool
		RejectReason string `json:"reject-reason"`
	}](t, c, "testmempoolaccept", []string{txHex(t, tx)})
	if len(result) != 1 || result[0].Allowed != want {
		t.Fatalf("mempool result %+v; want allowed=%v", result, want)
	}
	if !want {
		t.Logf("Core rejection: %s", result[0].RejectReason)
	}
}

func (c *core) mine(t *testing.T, tx *wire.MsgTx) {
	t.Helper()
	id := rpc[string](t, c, "sendrawtransaction", txHex(t, tx))
	rpc[[]string](t, c, "generatetoaddress", 1, c.miningAddress)
	out := rpc[*struct{ Confirmations int }](t, c, "gettxout", id, 0)
	if out == nil || out.Confirmations != 1 {
		t.Fatal("transaction did not confirm")
	}
	t.Logf("Core mined %s", id)
}

func TestBitcoinCoreRegtest(t *testing.T) {
	c := startCore(t)
	t.Run("valid_payment_then_mutation_and_replacement", func(t *testing.T) {
		f := newFixture(t)
		c.fund(t, f)
		if err := runProgram(f.tx, f.policy, f.prevouts()); err != nil {
			t.Fatal(err)
		}
		f.signSavings(t, f.authorities...)
		f.signConnector(t, f.hardware, txscript.SigHashDefault)
		c.accepted(t, f.tx, true)
		original := f.tx.Copy()
		// Re-sign Savings only: Core must still reject the changed hardware-approved amount.
		f.tx.TxOut[0].Value--
		f.signSavings(t, f.authorities...)
		c.accepted(t, f.tx, false)
		rpc[string](t, c, "sendrawtransaction", txHex(t, original))
		f.tx.TxOut[0].Value = 7600 // 900-sat replacement fee, with fresh hardware approval.
		f.signSavings(t, f.authorities...)
		f.signConnector(t, f.hardware, txscript.SigHashDefault)
		if err := runProgram(f.tx, f.policy, f.prevouts()); err != nil {
			t.Fatal(err)
		}
		c.accepted(t, f.tx, true)
		c.mine(t, f.tx)
		c.accepted(t, original, false)
	})
	for _, mode := range []string{"omit", "replace"} {
		t.Run("candidate_bypass_"+mode, func(t *testing.T) {
			f := newFixture(t)
			c.fund(t, f)
			f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.attackerScript)}
			if mode == "omit" {
				f.tx.TxIn = f.tx.TxIn[:1]
			} else {
				f.tx.TxIn[1].PreviousOutPoint.Index = 2
				f.tx.TxOut[0].Value += 1000
				f.signConnector(t, f.attacker, txscript.SigHashDefault)
			}
			if err := runProgram(f.tx, f.policy, f.prevouts()); err == nil {
				t.Fatal("program accepted bypass")
			}
			f.signSavings(t, f.authorities...)
			c.accepted(t, f.tx, true)
			c.mine(t, f.tx)
		})
	}
	for _, role := range []string{"admin", "phone", "recovery"} {
		t.Run("existing_tree_"+role, func(t *testing.T) {
			f := existingFixture(t, role)
			c.fund(t, f)
			f.tx.TxIn = f.tx.TxIn[:1]
			f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.attackerScript)}
			if role == "admin" {
				f.signSavings(t, f.phone, f.attacker)
				c.accepted(t, f.tx, false)
			} else if err := runProgram(f.tx, f.policy, f.prevouts()); err == nil {
				t.Fatal("existing program accepted direct theft")
			}
			f.signSavings(t, f.authorities...)
			c.accepted(t, f.tx, true)
			c.mine(t, f.tx)
		})
	}
	t.Run("external_connector_spend_and_refill", func(t *testing.T) {
		f := newFixture(t)
		c.fund(t, f)
		f.signSavings(t, f.authorities...)
		f.signConnector(t, f.hardware, txscript.SigHashDefault)
		c.accepted(t, f.tx, true)
		external := wire.NewMsgTx(2)
		external.AddTxIn(wire.NewTxIn(&f.tx.TxIn[1].PreviousOutPoint, nil, nil))
		external.AddTxOut(wire.NewTxOut(600, f.attackerScript))
		p := f.prevouts()
		sig, err := txscript.RawTxInTaprootSignature(external, txscript.NewTxSigHashes(external, p), 0, 1000, f.connector, nil, txscript.SigHashDefault, f.hardware)
		external.TxIn[0].Witness = wire.TxWitness{must(t, sig, err)}
		c.accepted(t, external, true)
		c.mine(t, external)
		c.accepted(t, f.tx, false)
		out := rpc[json.RawMessage](t, c, "gettxout", f.parent.TxHash().String(), 0)
		if string(out) == "null" {
			t.Fatal("external connector spend consumed Savings")
		}
		f.tx.TxIn[1].PreviousOutPoint.Index = 3
		if err := runProgram(f.tx, f.policy, p); err != nil {
			t.Fatal(err)
		}
		f.signSavings(t, f.authorities...)
		f.signConnector(t, f.hardware, txscript.SigHashDefault)
		c.accepted(t, f.tx, true)
		c.mine(t, f.tx)
	})
	for _, role := range []string{"phone", "hardware", "recovery"} {
		t.Run("pending_claim_delay_"+role, func(t *testing.T) {
			f, delay := pendingFixture(t, role)
			c.fund(t, f)
			f.tx.TxIn = f.tx.TxIn[:1]
			f.tx.TxIn[0].Sequence = delay
			f.tx.TxOut = []*wire.TxOut{wire.NewTxOut(9500, f.destination)}
			f.signSavings(t, f.authorities...)
			// No connector, Guardian, or Emulator signature is needed to claim an
			// existing pending output, but Core must enforce its real block age.
			c.accepted(t, f.tx, false)
			rpc[[]string](t, c, "generatetoaddress", delay-2, c.miningAddress)
			c.accepted(t, f.tx, false)
			rpc[[]string](t, c, "generatetoaddress", 1, c.miningAddress)
			c.accepted(t, f.tx, true)
			c.mine(t, f.tx)
		})
	}
}
