package htlc

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/pearl-research-labs/pearl/node/btcec"
	"github.com/pearl-research-labs/pearl/node/btcec/schnorr"
	"github.com/pearl-research-labs/pearl/node/chaincfg"
	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/wire"
)

// Deterministic, public, test-only keys. Never use for value.
func testKey(label string) *btcec.PrivateKey {
	h := sha256.Sum256([]byte("pearl-diver-test-key|" + label))
	k, _ := btcec.PrivKeyFromBytes(h[:])
	return k
}

type fixture struct {
	h        *HTLC
	pre      []byte
	claimer  *btcec.PrivateKey
	refunder *btcec.PrivateKey
	spend    Spend
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pre := sha256.Sum256([]byte("preimage"))
	claimer, refunder := testKey("alice"), testKey("bob")
	h, err := Build(Params{
		Hash:     sha256.Sum256(pre[:]),
		Claimer:  schnorr.SerializePubKey(claimer.PubKey()),
		Refunder: schnorr.SerializePubKey(refunder.PubKey()),
		Locktime: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	dest, _, _ := P2TRKeyPath(claimer.PubKey(), &chaincfg.RegressionNetParams)
	return fixture{h, pre[:], claimer, refunder, Spend{
		Prev: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}, PrevVal: 100_000, DestPk: dest, Fee: 1_000,
	}}
}

func TestAddressIsRegtestBech32m(t *testing.T) {
	f := newFixture(t)
	a, err := f.h.Address(&chaincfg.RegressionNetParams)
	if err != nil || !strings.HasPrefix(a, "rprl1p") {
		t.Fatalf("address %q err %v", a, err)
	}
}

func TestClaimWithPreimage(t *testing.T) {
	f := newFixture(t)
	tx, err := f.h.ClaimTx(f.spend, f.pre, f.claimer)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.Verify(tx, f.spend.PrevVal); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	got, ok := f.h.ExtractPreimage(tx.TxIn[0].DecodeWitness())
	if !ok || string(got) != string(f.pre) {
		t.Fatal("preimage not extractable from claim witness")
	}
}

func TestClaimWrongPreimageFails(t *testing.T) {
	f := newFixture(t)
	bad := sha256.Sum256([]byte("not it"))
	tx, _ := f.h.ClaimTx(f.spend, bad[:], f.claimer)
	if err := f.h.Verify(tx, f.spend.PrevVal); err == nil {
		t.Fatal("wrong preimage accepted")
	}
	if _, ok := f.h.ExtractPreimage(tx.TxIn[0].DecodeWitness()); ok {
		t.Fatal("extracted a wrong preimage")
	}
}

func TestClaimWrongSizePreimageFails(t *testing.T) {
	// A 33-byte preimage can never hash to H anyway, but OP_SIZE must reject before hashing.
	f := newFixture(t)
	tx, _ := f.h.ClaimTx(f.spend, append(append([]byte{}, f.pre...), 0), f.claimer)
	if err := f.h.Verify(tx, f.spend.PrevVal); err == nil {
		t.Fatal("33-byte preimage accepted")
	}
}

func TestClaimByRefunderKeyFails(t *testing.T) {
	f := newFixture(t)
	tx, _ := f.h.ClaimTx(f.spend, f.pre, f.refunder)
	if err := f.h.Verify(tx, f.spend.PrevVal); err == nil {
		t.Fatal("claim signed by the wrong key accepted")
	}
}

func TestRefundAfterLocktime(t *testing.T) {
	f := newFixture(t)
	tx, err := f.h.RefundTx(f.spend, f.refunder)
	if err != nil {
		t.Fatal(err)
	}
	if tx.LockTime != 500 || tx.TxIn[0].Sequence == wire.MaxTxInSequenceNum {
		t.Fatal("refund must set nLockTime and a non-final sequence")
	}
	if err := f.h.Verify(tx, f.spend.PrevVal); err != nil {
		t.Fatalf("valid refund rejected: %v", err)
	}
	if _, ok := f.h.ExtractPreimage(tx.TxIn[0].DecodeWitness()); ok {
		t.Fatal("refund witness parsed as claim")
	}
}

func TestRefundWithEarlyLocktimeFails(t *testing.T) {
	// Force nLockTime below the script's CLTV by signing a tx by hand.
	f := newFixture(t)
	s := f.spend
	s.Locktime = 499
	h2 := *f.h
	h2.Params.Locktime = 499 // trick RefundTx into not bumping, but keep the 500 script
	tx2, _ := h2.RefundTx(s, f.refunder)
	if err := f.h.Verify(tx2, f.spend.PrevVal); err == nil {
		t.Fatal("refund with nLockTime < CLTV accepted")
	}
}

func TestRefundByClaimerKeyFails(t *testing.T) {
	f := newFixture(t)
	tx, _ := f.h.RefundTx(f.spend, f.claimer)
	if err := f.h.Verify(tx, f.spend.PrevVal); err == nil {
		t.Fatal("refund signed by the wrong key accepted")
	}
}

func TestBuildRejectsBadParams(t *testing.T) {
	k := schnorr.SerializePubKey(testKey("a").PubKey())
	if _, err := Build(Params{Claimer: k, Refunder: k, Locktime: 10}); err == nil {
		t.Fatal("same claimer/refunder accepted")
	}
	k2 := schnorr.SerializePubKey(testKey("b").PubKey())
	if _, err := Build(Params{Claimer: k, Refunder: k2, Locktime: 500_000_000}); err == nil {
		t.Fatal("timestamp locktime accepted")
	}
	if _, err := Build(Params{Claimer: k[:31], Refunder: k2, Locktime: 10}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestDeterministicScripts(t *testing.T) {
	a, b := newFixture(t), newFixture(t)
	if string(a.h.PkScript) != string(b.h.PkScript) {
		t.Fatal("same params gave different outputs")
	}
}
