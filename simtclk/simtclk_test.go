package simtclk

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func terms(now int64) (LockTerms, string) {
	pre := sha256.Sum256([]byte("s"))
	h := sha256.Sum256(pre[:])
	return LockTerms{Contract: "0x" + hex.EncodeToString(h[:]), Lock: "hash", Statement: "0x" + hex.EncodeToString(h[:]),
		Amount: "1000", Asset: "FLOP", Payer: "did:key:a", Payee: "did:key:b", ClaimByMs: now + 50, RefundAfterMs: now + 100}, "0x" + hex.EncodeToString(pre[:])
}

func TestMemoryRailPredicates(t *testing.T) {
	now := int64(1000)
	r := New(func() int64 { return now })
	tm, pre := terms(now)
	ref, err := r.Lock(tm)
	if err != nil || !r.VerifyLock(tm, ref) {
		t.Fatal("lock/verify failed")
	}
	if _, err := r.Lock(tm); err == nil {
		t.Fatal("double lock accepted")
	}
	tm2 := tm
	tm2.Amount = "999"
	if r.VerifyLock(tm2, ref) {
		t.Fatal("verifyLock ignored a changed term")
	}
	if err := r.Refund(ref); err == nil {
		t.Fatal("refund before refundAfterMs accepted")
	}
	if err := r.Claim(ref, "0x"+hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("wrong preimage accepted")
	}
	if _, ok := r.RevealedSecret(ref); ok {
		t.Fatal("secret revealed before claim")
	}
	if err := r.Claim(ref, pre); err != nil {
		t.Fatal(err)
	}
	if s, ok := r.RevealedSecret(ref); !ok || s != pre {
		t.Fatal("watcher cannot see the secret")
	}
	if err := r.Refund(ref); err == nil {
		t.Fatal("refund after claim accepted")
	}
}

func TestClaimAtDeadlineFailsRefundSucceeds(t *testing.T) {
	now := int64(1000)
	r := New(func() int64 { return now })
	tm, pre := terms(now)
	ref, _ := r.Lock(tm)
	now = tm.RefundAfterMs
	if err := r.Claim(ref, pre); err == nil {
		t.Fatal("claim at refundAfterMs accepted (must be strictly before)")
	}
	if err := r.Refund(ref); err != nil {
		t.Fatal(err)
	}
	if r.Status(ref) != "refunded" {
		t.Fatal("status")
	}
}

func TestLockIntoOpenRefundWindowFails(t *testing.T) {
	now := int64(1000)
	r := New(func() int64 { return now })
	tm, _ := terms(now)
	now = tm.RefundAfterMs
	if _, err := r.Lock(tm); err == nil {
		t.Fatal("lock into open refund window accepted")
	}
}

func TestPersistence(t *testing.T) {
	now := int64(1000)
	p := filepath.Join(t.TempDir(), "rail.json")
	r, _ := Open(p, func() int64 { return now })
	tm, pre := terms(now)
	ref, _ := r.Lock(tm)
	r2, err := Open(p, func() int64 { return now })
	if err != nil || !r2.VerifyLock(tm, ref) {
		t.Fatal("state not persisted")
	}
	if err := r2.Claim(ref, pre); err != nil {
		t.Fatal(err)
	}
	r3, _ := Open(p, func() int64 { return now })
	if s, ok := r3.RevealedSecret(ref); !ok || s != pre {
		t.Fatal("reveal not persisted")
	}
}

func TestVerifySecretRejectsWrongLength(t *testing.T) {
	h := sha256.Sum256([]byte("x"))
	if VerifySecret("0x"+hex.EncodeToString(h[:]), "0x78") {
		t.Fatal("1-byte preimage accepted")
	}
}
