// Command pearldiver drives Pearl Diver swaps on a LOCAL Pearl node (regtest/simnet) with a
// simulated tclk FLOP escrow. It refuses mainnet/testnet. Private keys stay in
// $PEARL_DIVER_HOME/keys (mode 600) and are never printed.
//
//	pearldiver demo   --pearld PATH [--net simnet|regtest]      full happy path on a fresh node
//	pearldiver keygen --name NAME                                show DID + Pearl x-only key
//	pearldiver offer  --state S --initiator NAME --flop-amt N --prl-amt N [--window-ms --margin-ms]
//	pearldiver accept --state S --responder NAME
//	pearldiver lock-flop  --state S
//	pearldiver lock-prl   --state S --responder NAME
//	pearldiver claim-prl  --state S --initiator NAME
//	pearldiver watch      --state S                               counter-claim FLOP if preimage is public
//	pearldiver refund-prl --state S --responder NAME
//	pearldiver refund-flop --state S
//	pearldiver receipts   --state S --initiator NAME --responder NAME [--out FILE]
//	pearldiver status     --state S
//	pearldiver mine --n N | faucet --name NAME --prl-amt N | miner-address --net NET   (local chain helpers)
//	pearldiver height-for --deadline-ms MS --tip H [--now-ms MS] [--mode not-after|not-before]
//
// Node connection for the step commands: PD_RPC_HOST, PD_RPC_USER, PD_RPC_PASS, PD_NET.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pearl-research-labs/pearl/node/btcec/schnorr"
	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/wire"

	"github.com/xbtMelchizedek/pearl-diver/agb1"
	"github.com/xbtMelchizedek/pearl-diver/htlc"
	"github.com/xbtMelchizedek/pearl-diver/localkeys"
	"github.com/xbtMelchizedek/pearl-diver/pearl"
	"github.com/xbtMelchizedek/pearl-diver/simtclk"
	"github.com/xbtMelchizedek/pearl-diver/swap"
	"github.com/xbtMelchizedek/pearl-diver/timelock"
)

type state struct {
	Terms       swap.Terms `json:"terms"`
	FlopRef     string     `json:"flopRef,omitempty"`
	PrlLock     string     `json:"prlLock,omitempty"` // txid:vout
	StartHeight uint32     `json:"startHeight,omitempty"`
	PrlClaim    string     `json:"prlClaim,omitempty"`
	PrlClaimTs  int64      `json:"prlClaimTs,omitempty"`
	FlopClaimTs int64      `json:"flopClaimTs,omitempty"`
	PrlRefund   string     `json:"prlRefund,omitempty"`
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "pearldiver:", err)
	os.Exit(1)
}

func party(name string) swap.Party {
	ek, err := localkeys.Ed25519(name)
	if err != nil {
		die(err)
	}
	pk, err := localkeys.Secp(name)
	if err != nil {
		die(err)
	}
	return swap.Party{Agb: agb1.Signer{Key: ek}, Prl: pk}
}

func home() string {
	d, err := localkeys.Dir()
	if err != nil {
		die(err)
	}
	return filepath.Dir(d)
}

func now() int64 { return time.Now().UnixMilli() }

func coordFor(c *pearl.Client) *swap.Coord {
	r, err := simtclk.Open(filepath.Join(home(), "simtclk.json"), now)
	if err != nil {
		die(err)
	}
	return &swap.Coord{Pearl: pearl.Rail{C: c}, Flop: r, Clock: now, Assume: timelock.PearlDefault,
		MinResponderBlocks: 3, ClaimSafetyBlocks: 2}
}

func dialEnv() *pearl.Client {
	n := os.Getenv("PD_NET")
	if n == "" {
		n = "regtest"
	}
	params, err := pearl.NetByName(n)
	if err != nil {
		die(err)
	}
	c, err := pearl.Dial(pearl.Config{Host: os.Getenv("PD_RPC_HOST"), User: os.Getenv("PD_RPC_USER"), Pass: os.Getenv("PD_RPC_PASS"), Net: params})
	if err != nil {
		die(err)
	}
	return c
}

func load(p string) state {
	var s state
	b, err := os.ReadFile(p)
	if err != nil {
		die(err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		die(err)
	}
	return s
}

func save(p string, s state) {
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		die(err)
	}
}

func parseOP(s string) wire.OutPoint {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		die(errors.New("bad outpoint " + s))
	}
	h, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		die(err)
	}
	var i uint32
	fmt.Sscan(parts[1], &i)
	return wire.OutPoint{Hash: *h, Index: i}
}

// secrets are stored like keys: mode 600, outside git, never printed.
func secretPath(hash string) string {
	d, _ := localkeys.Dir()
	return filepath.Join(d, "preimage-"+strings.TrimPrefix(hash, "0x")[:16]+".key")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pearldiver <demo|keygen|offer|accept|lock-flop|lock-prl|claim-prl|watch|refund-prl|refund-flop|receipts|status|height-for> ...")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	st := fs.String("state", "swap.json", "swap state file")
	name := fs.String("name", "", "key name")
	ini := fs.String("initiator", "", "initiator key name")
	rsp := fs.String("responder", "", "responder key name")
	flopAmt := fs.String("flop-amt", "1000000000000000000", "FLOP base units (simulated)")
	prlAmt := fs.Int64("prl-amt", 100_000_000, "PRL grains")
	windowMs := fs.Int64("window-ms", 24*timelock.PearlTargetBlockMs*2, "FLOP refund delay from now")
	marginMs := fs.Int64("margin-ms", 6*timelock.PearlTargetBlockMs, "ordering safety margin")
	out := fs.String("out", "", "output file")
	bin := fs.String("pearld", os.Getenv("PEARLD_BIN"), "pearld binary (demo)")
	netName := fs.String("net", "simnet", "demo network: simnet|regtest")
	deadline := fs.Int64("deadline-ms", 0, "deadline (height-for)")
	tip := fs.Uint("tip", 0, "tip height (height-for)")
	nowMs := fs.Int64("now-ms", 0, "now (height-for; default wall clock)")
	nBlocks := fs.Uint("n", 1, "blocks to mine")
	mode := fs.String("mode", "not-after", "not-after (responder leg) | not-before (initiator leg)")
	_ = fs.Parse(args)

	switch cmd {
	case "keygen":
		p := party(*name)
		fmt.Printf("name: %s\ndid: %s\nprl_xonly: %s\n", *name, p.Agb.DID(), hex.EncodeToString(schnorr.SerializePubKey(p.Prl.PubKey())))
	case "height-for":
		n := *nowMs
		if n == 0 {
			n = now()
		}
		var h uint32
		var err error
		if *mode == "not-before" {
			h, err = timelock.HeightNotBefore(n, uint32(*tip), *deadline, timelock.PearlDefault)
		} else {
			h, err = timelock.HeightNotAfter(n, uint32(*tip), *deadline, timelock.PearlDefault)
		}
		if err != nil {
			die(err)
		}
		w, _ := timelock.HeightWindow(n, uint32(*tip), h, timelock.PearlDefault)
		fmt.Printf("height: %d\nrefund_window_ms: [%d, %d]\nassumed_block_ms: fast %d slow %d\n", h, w.Earliest, w.Latest, timelock.PearlDefault.FastBlockMs, timelock.PearlDefault.SlowBlockMs)
	case "offer":
		sec, h := swap.NewSecret()
		if err := os.WriteFile(secretPath(h), []byte(hex.EncodeToString(sec)+"\n"), 0o600); err != nil {
			die(err)
		}
		n := os.Getenv("PD_NET")
		if n == "" {
			n = "regtest"
		}
		t := swap.Offer(party(*ini), n, h, *flopAmt, *prlAmt, now(), *windowMs, *marginMs, 1)
		save(*st, state{Terms: t})
		fmt.Printf("offer written to %s (hash %s; preimage stored mode 600 in the key dir)\n", *st, h)
	case "accept":
		c := dialEnv()
		s := load(*st)
		t, err := coordFor(c).Accept(s.Terms, party(*rsp))
		if err != nil {
			die(err)
		}
		s.Terms = t
		save(*st, s)
		fmt.Printf("accepted: swap %s, Pearl CLTV height %d, FLOP refund after %d ms\n", t.ID(), t.PrlLocktime, t.FlopRefundAfterMs)
	case "lock-flop":
		c := dialEnv()
		s := load(*st)
		ref, err := coordFor(c).InitiatorLock(s.Terms)
		if err != nil {
			die(err)
		}
		s.FlopRef = ref
		save(*st, s)
		fmt.Println("FLOP (simulated) locked:", ref)
	case "lock-prl":
		c := dialEnv()
		s := load(*st)
		s.StartHeight, _ = c.Tip()
		op, err := coordFor(c).ResponderLock(s.Terms, party(*rsp), s.FlopRef)
		if err != nil {
			die(err)
		}
		s.PrlLock = op.String()
		save(*st, s)
		fmt.Println("PRL locked in prl-htlc:", op)
	case "claim-prl":
		c := dialEnv()
		s := load(*st)
		raw, err := os.ReadFile(secretPath(s.Terms.Hash))
		if err != nil {
			die(err)
		}
		sec, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
		id, err := coordFor(c).InitiatorClaim(s.Terms, party(*ini), parseOP(s.PrlLock), sec)
		if err != nil {
			die(err)
		}
		s.PrlClaim, s.PrlClaimTs = id.String(), now()
		save(*st, s)
		fmt.Println("PRL claimed (preimage now public on Pearl):", id)
	case "watch":
		c := dialEnv()
		s := load(*st)
		got, err := coordFor(c).ResponderCounterClaim(s.Terms, parseOP(s.PrlLock), s.FlopRef, s.StartHeight)
		if err != nil {
			die(err)
		}
		if got == "" {
			fmt.Println("no preimage on Pearl yet")
			return
		}
		s.FlopClaimTs = now()
		save(*st, s)
		fmt.Println("preimage seen on Pearl; FLOP (simulated) claimed")
	case "refund-prl":
		c := dialEnv()
		s := load(*st)
		id, err := coordFor(c).ResponderRefund(s.Terms, party(*rsp), parseOP(s.PrlLock))
		if err != nil {
			die(err)
		}
		s.PrlRefund = id.String()
		save(*st, s)
		fmt.Println("PRL refunded:", id)
	case "refund-flop":
		c := dialEnv()
		s := load(*st)
		if err := coordFor(c).InitiatorRefund(s.FlopRef); err != nil {
			die(err)
		}
		fmt.Println("FLOP (simulated) refunded")
	case "receipts":
		s := load(*st)
		h, err := chainhash.NewHashFromStr(s.PrlClaim)
		if err != nil {
			die(errors.New("swap not completed (no PRL claim)"))
		}
		msgs, err := swap.Receipts(s.Terms, party(*ini), party(*rsp), s.FlopRef, parseOP(s.PrlLock), h, s.FlopClaimTs, s.PrlClaimTs)
		if err != nil {
			die(err)
		}
		writeLines(*out, msgs)
	case "mine": // local chain only (Dial refuses other networks)
		c := dialEnv()
		if err := c.Mine(uint32(*nBlocks)); err != nil {
			die(err)
		}
		t, _ := c.Tip()
		fmt.Println("tip:", t)
	case "faucet": // pays from the node's "miner" key to NAME's key-path address, local chain only
		c := dialEnv()
		m, err := localkeys.Secp("miner")
		if err != nil {
			die(err)
		}
		pk, _, _ := htlc.P2TRKeyPath(party(*name).Prl.PubKey(), c.Net)
		op, err := c.Pay(m, pk, *prlAmt)
		if err != nil {
			die(err)
		}
		fmt.Println("faucet paid:", op)
	case "miner-address":
		m, err := localkeys.Secp("miner")
		if err != nil {
			die(err)
		}
		params, err := pearl.NetByName(*netName)
		if err != nil {
			die(err)
		}
		_, a, _ := htlc.P2TRKeyPath(m.PubKey(), params)
		fmt.Println(a)
	case "status":
		s := load(*st)
		b, _ := json.MarshalIndent(s, "", "  ")
		fmt.Println(string(b))
		fmt.Println("swap id:", s.Terms.ID())
	case "demo":
		demo(*bin, *netName, *out)
	default:
		die(errors.New("unknown command " + cmd))
	}
}

func writeLines(out string, msgs []agb1.Msg) {
	var b strings.Builder
	for _, m := range msgs {
		b.WriteString(m.Line + "\n")
	}
	if out == "" {
		fmt.Print(b.String())
		return
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		die(err)
	}
	fmt.Printf("%d signed agb1 messages written to %s (not posted anywhere)\n", len(msgs), out)
}

func demo(bin, netName, out string) {
	if bin == "" {
		die(errors.New("--pearld or PEARLD_BIN required"))
	}
	params, err := pearl.NetByName(netName)
	if err != nil {
		die(err)
	}
	miner, err := localkeys.Secp("miner")
	if err != nil {
		die(err)
	}
	_, addr, _ := htlc.P2TRKeyPath(miner.PubKey(), params)
	dir, _ := os.MkdirTemp("", "pearl-diver-demo-")
	defer os.RemoveAll(dir)
	t0 := time.Now()
	n, err := pearl.StartNode(bin, params, addr, dir)
	if err != nil {
		die(err)
	}
	defer n.Stop()
	c, err := pearl.Dial(n.Config)
	if err != nil {
		die(err)
	}
	defer c.Close()
	step := func(f string, a ...any) { fmt.Printf("[%6.1fs] %s\n", time.Since(t0).Seconds(), fmt.Sprintf(f, a...)) }
	step("pearld %s up (local only, random RPC creds, no P2P)", netName)
	if err := c.MineTo(uint32(params.CoinbaseMaturity) + 3); err != nil {
		die(err)
	}
	tip, _ := c.Tip()
	step("mined to height %d (coinbase maturity)", tip)
	alice, bob := party("demo-alice"), party("demo-bob")
	co := coordFor(c)
	co.Flop = simtclk.New(now)
	bpk, _, _ := htlc.P2TRKeyPath(bob.Prl.PubKey(), params)
	if _, err := c.Pay(miner, bpk, 3*100_000_000); err != nil {
		die(err)
	}
	_ = c.Mine(1)
	step("faucet: 3 PRL (local chain) to bob")
	sec, h := swap.NewSecret()
	t := swap.Offer(alice, netName, h, "1000000000000000000", 100_000_000, now(), 24*timelock.PearlTargetBlockMs*2, 6*timelock.PearlTargetBlockMs, 1)
	step("alice offers 1 FLOP (sim) for 1 PRL, hash %s…", h[:18])
	if t, err = co.Accept(t, bob); err != nil {
		die(err)
	}
	tip, _ = c.Tip()
	step("bob accepts: Pearl CLTV height %d (tip %d), FLOP refund after %s", t.PrlLocktime, tip, time.UnixMilli(t.FlopRefundAfterMs).Format("15:04:05 MST"))
	ref, err := co.InitiatorLock(t)
	if err != nil {
		die(err)
	}
	step("alice locks FLOP in simulated tclk escrow %s…", ref[:18])
	start, _ := c.Tip()
	op, err := co.ResponderLock(t, bob, ref)
	if err != nil {
		die(err)
	}
	_ = c.Mine(1)
	hh, _ := t.HTLC()
	a, _ := hh.Address(params)
	step("bob verified the FLOP lock and locked 1 PRL in prl-htlc %s (%s)", op, a)
	id, err := co.InitiatorClaim(t, alice, op, sec)
	if err != nil {
		die(err)
	}
	prlTs := now()
	step("alice verified the HTLC and claimed it: %s (preimage now public)", id)
	got, err := co.ResponderCounterClaim(t, op, ref, start)
	if err != nil || got == "" {
		die(fmt.Errorf("counter-claim failed: %v", err))
	}
	flopTs := now()
	_ = c.Mine(1)
	step("bob read the preimage from Pearl and claimed the FLOP escrow (status %s)", co.Flop.Status(ref))
	msgs, err := swap.Receipts(t, alice, bob, ref, op, id, flopTs, prlTs)
	if err != nil {
		die(err)
	}
	if out == "" {
		out = "out/demo-receipts-" + netName + ".agb1"
	}
	_ = os.MkdirAll(filepath.Dir(out), 0o755)
	writeLines(out, msgs)
	step("done: swap %s", t.ID())
}
