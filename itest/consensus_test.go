package itest

import (
	"os"
	"testing"

	"github.com/xbtMelchizedek/pearl-diver/htlc"
	"github.com/xbtMelchizedek/pearl-diver/pearl"
)

// On a node with the permissive regtest/simnet default policy, a non-final refund can sit in
// the mempool. This checks CONSENSUS still keeps it out of blocks until tip >= locktime.
func TestConsensusKeepsEarlyRefundOutOfBlocks(t *testing.T) {
	bin := os.Getenv("PEARLD_BIN")
	if bin == "" || netNm != "simnet" {
		t.Skip("needs PEARLD_BIN and simnet (spins up a second node)")
	}
	dir := t.TempDir()
	_, addr, _ := htlc.P2TRKeyPath(miner.PubKey(), cl.Net)
	n, err := pearl.StartNodeWith(bin, cl.Net, addr, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop()
	c2, err := pearl.Dial(n.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	saved := cl
	cl = c2
	defer func() { cl = saved }()
	if err := cl.MineTo(106); err != nil {
		t.Fatal(err)
	}
	s := newSwap(t)
	ref, _ := s.c.InitiatorLock(s.terms)
	op, err := s.c.ResponderLock(s.terms, s.rsp, ref)
	if err != nil {
		t.Fatal(err)
	}
	mine(t, 1)
	if _, err := s.c.ResponderRefund(s.terms, s.rsp, op); err != nil {
		t.Fatalf("permissive mempool should admit the non-final refund here: %v", err)
	}
	tip, _ := cl.Tip()
	for tip < s.terms.PrlLocktime {
		if _, _, err := cl.Output(op); err != nil {
			t.Fatalf("non-final refund mined in block %d (locktime %d)", tip, s.terms.PrlLocktime)
		}
		mine(t, 1)
		tip++
	}
	mine(t, 1)
	if _, _, err := cl.Output(op); err == nil {
		t.Fatal("refund still not mined after it became final")
	}
	t.Logf("non-final refund stayed in mempool until tip reached %d, then mined", s.terms.PrlLocktime)
}
