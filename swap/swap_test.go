package swap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/pearl-research-labs/pearl/node/btcec"

	"github.com/xbtMelchizedek/pearl-diver/agb1"
)

func p(label string) Party {
	s := sha256.Sum256([]byte("pd-swap-test|" + label))
	k, _ := btcec.PrivKeyFromBytes(s[:])
	return Party{Agb: agb1.Signer{Key: ed25519.NewKeyFromSeed(s[:])}, Prl: k}
}

func TestTermsIDCommitsToEveryField(t *testing.T) {
	a, b := p("a"), p("b")
	base := Offer(a, "regtest", "0x11"+strings.Repeat("00", 31), "1", 2, 1000, 500, 100, 1)
	base.Responder, base.PrlLocktime = b.Pub(), 150
	id := base.ID()
	muts := []func(*Terms){
		func(x *Terms) { x.Net = "simnet" }, func(x *Terms) { x.FlopAmt = "2" }, func(x *Terms) { x.PrlAmt = 3 },
		func(x *Terms) { x.PrlLocktime = 151 }, func(x *Terms) { x.MarginMs++ }, func(x *Terms) { x.FlopRefundAfterMs++ },
		func(x *Terms) { x.Responder = a.Pub() }, func(x *Terms) { x.MinConf = 2 }, func(x *Terms) { x.Hash = "0x22" + strings.Repeat("00", 31) },
	}
	for i, m := range muts {
		c := base
		m(&c)
		if c.ID() == id {
			t.Fatalf("mutation %d did not change the swap id", i)
		}
	}
	if base.ID() != id {
		t.Fatal("ID not deterministic")
	}
}

func TestHTLCRebuiltFromTerms(t *testing.T) {
	a, b := p("a"), p("b")
	_, h := NewSecret()
	tm := Offer(a, "regtest", h, "1", 2, 1000, 500, 100, 1)
	tm.Responder, tm.PrlLocktime = b.Pub(), 150
	h1, err := tm.HTLC()
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := tm.HTLC()
	if string(h1.PkScript) != string(h2.PkScript) {
		t.Fatal("rebuild not deterministic")
	}
	tm.PrlLocktime = 151
	h3, _ := tm.HTLC()
	if string(h1.PkScript) == string(h3.PkScript) {
		t.Fatal("locktime not bound into the output")
	}
}
