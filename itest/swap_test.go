// Integration tests against a real local pearld. Skipped unless PEARLD_BIN is set.
//
//	PEARLD_BIN=/path/to/pearld go test ./itest/            (simnet: real node, dummy PoW certs, fast)
//	PD_NET=regtest PEARLD_BIN=... go test ./itest/ -timeout 3h  (regtest: real V4 proofs, ~30 s/block)
//	PD_RPC_HOST=127.0.0.1:port PD_RPC_USER=.. PD_RPC_PASS=.. PD_NET=regtest  (attach to a running node
//	  whose --miningaddr is the "miner" key in $PEARL_DIVER_HOME/keys)
//	AGENTWORK_PATH=/path/to/agentwork   also verifies emitted receipts with agentwork's Python codec
package itest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pearl-research-labs/pearl/node/btcec"

	"github.com/xbtMelchizedek/pearl-diver/agb1"
	"github.com/xbtMelchizedek/pearl-diver/htlc"
	"github.com/xbtMelchizedek/pearl-diver/localkeys"
	"github.com/xbtMelchizedek/pearl-diver/pearl"
	"github.com/xbtMelchizedek/pearl-diver/simtclk"
	"github.com/xbtMelchizedek/pearl-diver/swap"
	"github.com/xbtMelchizedek/pearl-diver/timelock"
)

var (
	cl     *pearl.Client
	miner  *btcec.PrivateKey
	netNm  string
	vclock int64 // virtual wall clock (ms), advanced one target block per mined block
)

const blockMs = timelock.PearlTargetBlockMs

func TestMain(m *testing.M) {
	bin := os.Getenv("PEARLD_BIN")
	if bin == "" && os.Getenv("PD_RPC_HOST") == "" {
		fmt.Println("itest: PEARLD_BIN not set; skipping integration tests")
		os.Exit(0)
	}
	netNm = os.Getenv("PD_NET")
	if netNm == "" {
		netNm = "simnet"
	}
	params, err := pearl.NetByName(netNm)
	must(err)
	miner, err = localkeys.Secp("miner")
	must(err)
	_, addr, err := htlc.P2TRKeyPath(miner.PubKey(), params)
	must(err)
	var node *pearl.Node
	var nodeDir string
	cfg := pearl.Config{Host: os.Getenv("PD_RPC_HOST"), User: os.Getenv("PD_RPC_USER"), Pass: os.Getenv("PD_RPC_PASS"), Net: params}
	if cfg.Host == "" {
		dir, err := os.MkdirTemp("", "pearl-diver-"+netNm+"-")
		must(err)
		nodeDir = dir
		node, err = pearl.StartNode(bin, params, addr, dir)
		must(err)
		cfg = node.Config
		fmt.Println("itest: started pearld", netNm, "in", dir)
	}
	cl, err = pearl.Dial(cfg)
	must(err)
	tip, err := cl.Tip()
	must(err)
	need := uint32(params.CoinbaseMaturity) + 6
	if tip < need {
		if netNm == "regtest" && os.Getenv("PD_ALLOW_SLOW_MATURITY") == "" {
			fmt.Printf("itest: regtest tip %d < %d; pre-mine first (or set PD_ALLOW_SLOW_MATURITY=1)\n", tip, need)
			os.Exit(1)
		}
		t0 := time.Now()
		must(cl.MineTo(need))
		fmt.Printf("itest: mined to %d in %s\n", need, time.Since(t0).Round(time.Millisecond))
	}
	vclock = 1_800_000_000_000
	code := m.Run()
	cl.Close()
	if node != nil {
		node.Stop()
		if code == 0 && os.Getenv("PD_KEEP") == "" {
			_ = os.RemoveAll(nodeDir)
		}
	}
	os.Exit(code)
}

// strictMempool: our own nodes run --rejectnonstd; attached nodes may not.
func strictMempool() bool { return os.Getenv("PD_RPC_HOST") == "" || os.Getenv("PD_STRICT") != "" }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mine(t *testing.T, n uint32) {
	t.Helper()
	if err := cl.Mine(n); err != nil {
		t.Fatal(err)
	}
	vclock += int64(n) * blockMs
}

// ephemeral party: keys live only in memory for the test.
func party(t *testing.T) swap.Party {
	t.Helper()
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return swap.Party{Agb: agb1.Signer{Key: ed25519.NewKeyFromSeed(seed)}, Prl: k}
}

func coord() *swap.Coord {
	return &swap.Coord{
		Pearl: pearl.Rail{C: cl}, Flop: simtclk.New(func() int64 { return vclock }),
		Clock:  func() int64 { return vclock },
		Assume: timelock.Assumptions{FastBlockMs: blockMs / 2, SlowBlockMs: blockMs * 2},
		// small numbers so regtest runs stay short; production values belong in the CLI config
		MinResponderBlocks: 2, ClaimSafetyBlocks: 1,
	}
}

// fund the responder from the miner (local chain faucet) and confirm.
func fund(t *testing.T, p swap.Party, amt int64) {
	t.Helper()
	pk, _, _ := htlc.P2TRKeyPath(p.Prl.PubKey(), cl.Net)
	op, err := cl.Pay(miner, pk, amt+5*pearl.DefaultFee)
	if err != nil {
		t.Fatal(err)
	}
	mine(t, 1)
	if _, c, err := cl.Output(op); err != nil || c < 1 {
		t.Fatalf("faucet not confirmed: %v", err)
	}
}

const (
	prlAmt  = int64(250_000_000)      // 2.5 PRL (local chain)
	flopAmt = "1000000000000000000"   // 1 FLOP in base units (simulated)
	window  = int64(12) * blockMs * 2 // FLOP refund 24 target-blocks out
	margin  = int64(4) * blockMs      // 4 target blocks of slack
)

type setup struct {
	c         *swap.Coord
	init, rsp swap.Party
	secret    []byte
	terms     swap.Terms
}

func newSwap(t *testing.T) setup {
	t.Helper()
	c := coord()
	init, rsp := party(t), party(t)
	fund(t, rsp, prlAmt)
	sec, h := swap.NewSecret()
	off := swap.Offer(init, netNm, h, flopAmt, prlAmt, vclock, window, margin, 1)
	terms, err := c.Accept(off, rsp)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return setup{c, init, rsp, sec, terms}
}

func TestHappyPathAndReceipts(t *testing.T) {
	s := newSwap(t)
	ref, err := s.c.InitiatorLock(s.terms)
	if err != nil {
		t.Fatal(err)
	}
	startH, _ := cl.Tip()
	op, err := s.c.ResponderLock(s.terms, s.rsp, ref)
	if err != nil {
		t.Fatal(err)
	}
	// initiator must not claim before MinConf
	if _, err := s.c.InitiatorClaim(s.terms, s.init, op, s.secret); err == nil {
		t.Fatal("claimed an unconfirmed lock")
	}
	mine(t, 1)
	claimID, err := s.c.InitiatorClaim(s.terms, s.init, op, s.secret)
	if err != nil {
		t.Fatalf("initiator claim: %v", err)
	}
	prlTs := vclock
	// responder sees the preimage in the MEMPOOL, before any block
	got, err := s.c.ResponderCounterClaim(s.terms, op, ref, startH)
	if err != nil || got != "0x"+hex.EncodeToString(s.secret) {
		t.Fatalf("counter-claim from mempool: %q %v", got, err)
	}
	flopTs := vclock
	mine(t, 1)
	if s.c.Flop.Status(ref) != "claimed" {
		t.Fatal("FLOP leg not claimed")
	}
	if _, _, err := cl.Output(op); err == nil {
		t.Fatal("HTLC still unspent after claim")
	}
	// initiator received PRL
	ipk, _, _ := htlc.P2TRKeyPath(s.init.Prl.PubKey(), cl.Net)
	us, _ := cl.UTXOs(ipk, 1)
	if len(us) != 1 || us[0].Out.Value != prlAmt-pearl.DefaultFee {
		t.Fatalf("initiator PRL balance wrong: %+v", us)
	}
	msgs, err := swap.Receipts(s.terms, s.init, s.rsp, ref, op, claimID, flopTs, prlTs)
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, msgs)
}

func writeAndVerify(t *testing.T, msgs []agb1.Msg) {
	t.Helper()
	var lines []string
	for _, m := range msgs {
		lines = append(lines, m.Line)
	}
	_ = os.MkdirAll("../out", 0o755)
	f := filepath.Join("..", "out", "receipts-"+netNm+".agb1")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	aw := os.Getenv("AGENTWORK_PATH")
	if aw == "" {
		t.Log("AGENTWORK_PATH not set; receipts written but not verified by agentwork")
		return
	}
	out, err := exec.Command("python3", "../tests/verify_receipts.py", aw, f).CombinedOutput()
	if err != nil {
		t.Fatalf("agentwork rejected the receipts: %v\n%s", err, out)
	}
	t.Logf("agentwork: %s", strings.TrimSpace(string(out)))
}

func TestWrongPreimageRejectedByPearld(t *testing.T) {
	s := newSwap(t)
	ref, _ := s.c.InitiatorLock(s.terms)
	op, err := s.c.ResponderLock(s.terms, s.rsp, ref)
	if err != nil {
		t.Fatal(err)
	}
	mine(t, 1)
	bad := sha256.Sum256([]byte("wrong"))
	if _, err := s.c.InitiatorClaim(s.terms, s.init, op, bad[:]); err == nil {
		t.Fatal("pearld accepted a claim with the wrong preimage")
	} else {
		t.Logf("pearld rejected wrong preimage: %v", err)
	}
	if err := s.c.Flop.Claim(ref, "0x"+hex.EncodeToString(bad[:])); err == nil {
		t.Fatal("FLOP sim accepted the wrong preimage")
	}
	if got, err := s.c.ResponderCounterClaim(s.terms, op, ref, 0); err != nil || got != "" {
		t.Fatal("watcher saw a preimage that was never published")
	}
}

func TestRefundBeforeTimelockFailsAfterSucceeds(t *testing.T) {
	s := newSwap(t)
	ref, _ := s.c.InitiatorLock(s.terms)
	op, err := s.c.ResponderLock(s.terms, s.rsp, ref)
	if err != nil {
		t.Fatal(err)
	}
	mine(t, 1)
	tip, _ := cl.Tip()
	if tip >= s.terms.PrlLocktime {
		t.Fatal("test setup: locktime already reached")
	}
	if _, err := s.c.ResponderRefund(s.terms, s.rsp, op); err == nil {
		// Only possible on a node relaying non-standard txs (regtest/simnet default).
		// Consensus must still keep it out of blocks until the locktime.
		t.Logf("mempool admitted a non-final refund (node relays non-standard txs); checking consensus")
		mine(t, 1)
		if _, _, err := cl.Output(op); err != nil {
			t.Fatalf("non-final refund was MINED at tip %d < locktime %d", tip+1, s.terms.PrlLocktime)
		}
		tip++
	} else {
		t.Logf("early refund rejected at tip %d (locktime %d): %v", tip, s.terms.PrlLocktime, err)
	}
	// one block short: tip = locktime-1 is still too early
	mine(t, s.terms.PrlLocktime-1-tip)
	if _, err := s.c.ResponderRefund(s.terms, s.rsp, op); err == nil && strictMempool() {
		t.Fatal("refund accepted at tip = locktime-1")
	}
	mine(t, 1) // tip = locktime: tx with nLockTime=locktime is final in the next block
	id, err := s.c.ResponderRefund(s.terms, s.rsp, op)
	if err != nil && strictMempool() {
		t.Fatalf("refund at tip = locktime: %v", err)
	}
	mine(t, 1)
	if _, _, err := cl.Output(op); err == nil {
		t.Fatal("refund not mined once final")
	}
	if got, err := s.c.ResponderCounterClaim(s.terms, op, ref, 0); err != nil || got != "" {
		t.Fatal("a refund was parsed as a claim")
	}
	t.Logf("refund %s confirmed", id)
}

func TestResponderDisappears(t *testing.T) {
	s := newSwap(t)
	ref, err := s.c.InitiatorLock(s.terms)
	if err != nil {
		t.Fatal(err)
	}
	// responder never locks PRL. Initiator cannot refund early...
	if err := s.c.InitiatorRefund(ref); err == nil {
		t.Fatal("FLOP refund before T_A accepted")
	}
	// ...and never reveals the secret, so nothing can be claimed from it.
	vclock = s.terms.FlopRefundAfterMs
	if err := s.c.InitiatorRefund(ref); err != nil {
		t.Fatalf("FLOP refund at T_A: %v", err)
	}
	if s.c.Flop.Status(ref) != "refunded" {
		t.Fatal("status")
	}
}

func TestInitiatorDisappearsAfterResponderLocks(t *testing.T) {
	s := newSwap(t)
	ref, _ := s.c.InitiatorLock(s.terms)
	op, err := s.c.ResponderLock(s.terms, s.rsp, ref)
	if err != nil {
		t.Fatal(err)
	}
	mine(t, 1)
	// initiator goes silent: no claim, no reveal. Responder waits for H_B and refunds PRL.
	if err := cl.MineTo(s.terms.PrlLocktime); err != nil {
		t.Fatal(err)
	}
	if _, err := s.c.ResponderRefund(s.terms, s.rsp, op); err != nil {
		t.Fatalf("responder refund at H_B: %v", err)
	}
	mine(t, 1)
	rpk, _, _ := htlc.P2TRKeyPath(s.rsp.Prl.PubKey(), cl.Net)
	us, _ := cl.UTXOs(rpk, 1)
	var total int64
	for _, u := range us {
		total += u.Out.Value
	}
	if total < prlAmt-pearl.DefaultFee {
		t.Fatalf("responder did not get PRL back: %d", total)
	}
	// the initiator's FLOP comes back at T_A, which the ordering rule put after H_B + margin
	if err := s.c.InitiatorRefund(ref); err == nil {
		t.Fatal("FLOP refund before T_A")
	}
	vclock = s.terms.FlopRefundAfterMs
	if err := s.c.InitiatorRefund(ref); err != nil {
		t.Fatal(err)
	}
}

func TestLateInitiatorCannotClaimAfterLocktime(t *testing.T) {
	// The coordinator refuses to claim when H_B is too close; a claim racing the refund is
	// the free-option / griefing window the README describes.
	s := newSwap(t)
	ref, _ := s.c.InitiatorLock(s.terms)
	op, err := s.c.ResponderLock(s.terms, s.rsp, ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.MineTo(s.terms.PrlLocktime - 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.c.InitiatorClaim(s.terms, s.init, op, s.secret); err == nil {
		t.Fatal("coordinator allowed a claim inside the safety window")
	}
	mine(t, 1)
	if _, err := s.c.ResponderRefund(s.terms, s.rsp, op); err != nil {
		t.Fatal(err)
	}
	mine(t, 1)
}

func TestResponderRefusesTamperedOrUnsafeTerms(t *testing.T) {
	c := coord()
	init, rsp := party(t), party(t)
	_, h := swap.NewSecret()
	off := swap.Offer(init, netNm, h, flopAmt, prlAmt, vclock, window, margin, 1)
	terms, err := c.Accept(off, rsp)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := c.InitiatorLock(terms)
	// 1) initiator locked under terms the responder did not agree to
	bad := terms
	bad.FlopAmt = "1"
	if _, err := c.ResponderLock(bad, rsp, ref); err == nil {
		t.Fatal("responder locked against mismatched FLOP terms")
	}
	// 2) responder's height too close to T_A: ordering rule must refuse
	unsafe := terms
	unsafe.PrlLocktime = terms.PrlLocktime + 20
	if err := c.CheckTiming(unsafe, false); err == nil {
		t.Fatal("unsafe ordering accepted")
	}
	// 3) a too-short FLOP window cannot produce any safe height
	short := swap.Offer(init, netNm, h, flopAmt, prlAmt, vclock, 3*blockMs, 2*blockMs, 1)
	if _, err := c.Accept(short, rsp); err == nil {
		t.Fatal("accepted a FLOP window with no safe Pearl height")
	}
}
