// Package simtclk is a SIMULATED FLOP-side escrow: a Go port of tclk's MemoryRail
// (flop-labs/tclk src/rail.ts, the "executable spec" every real rail must enforce) plus
// optional JSON persistence so separate CLI processes can share it, and a reveal log so a
// counterparty can "watch" for the preimage the way it would watch a flop-htlc claim.
//
// It holds no value and talks to no network. It is NOT the FLOP chain or tclk-flop.
//
// Predicates (same as MemoryRail):
//   - one lock per contract; lock refused once now >= refundAfterMs
//   - claim only from "locked", strictly before refundAfterMs, with a 32-byte preimage
//     whose sha256 equals the statement
//   - refund only from "locked", at/after refundAfterMs
//   - verifyLock true iff the held terms equal the given terms exactly (fail-closed)
package simtclk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// RailID is what a receipt names for this leg: tclk's canonical id for the process-local
// reference implementation. It never means value moved.
const RailID = "memory"

// LockTerms mirrors tclk's LockTerms.
type LockTerms struct {
	Contract      string `json:"contract"`
	Lock          string `json:"lock"` // only "hash" is supported here
	Statement     string `json:"statement"`
	Amount        string `json:"amount"`
	Asset         string `json:"asset"`
	Payer         string `json:"payer"`
	Payee         string `json:"payee"`
	ClaimByMs     int64  `json:"claimByMs"`
	RefundAfterMs int64  `json:"refundAfterMs"`
}

type lockRec struct {
	Terms  LockTerms `json:"terms"`
	Status string    `json:"status"` // locked | claimed | refunded
	Secret string    `json:"secret,omitempty"`
}

// Rail is the simulated escrow.
type Rail struct {
	mu    sync.Mutex
	clock func() int64
	path  string // "" = memory only
	locks map[string]*lockRec
}

// New returns an in-memory rail.
func New(clock func() int64) *Rail { return &Rail{clock: clock, locks: map[string]*lockRec{}} }

// Open returns a rail persisted at path (created if missing).
func Open(path string, clock func() int64) (*Rail, error) {
	r := New(clock)
	r.path = path
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &r.locks); err != nil {
		return nil, fmt.Errorf("simtclk: %s: %w", path, err)
	}
	return r, nil
}

func (r *Rail) save() error {
	if r.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(r.locks, "", "  ")
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// VerifySecret: 32-byte preimage, sha256 == statement (both 0x-hex). Fail-closed.
func VerifySecret(statement, secret string) bool {
	p, err := hex.DecodeString(strings.TrimPrefix(secret, "0x"))
	if err != nil || len(p) != 32 {
		return false
	}
	h := sha256.Sum256(p)
	return "0x"+hex.EncodeToString(h[:]) == strings.ToLower(statement)
}

func (r *Rail) Lock(t LockTerms) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.Lock != "hash" {
		return "", errors.New("simtclk: only hash locks are simulated")
	}
	if _, ok := r.locks[t.Contract]; ok {
		return "", fmt.Errorf("tclk: rail already holds a lock for %s", t.Contract)
	}
	if r.clock() >= t.RefundAfterMs {
		return "", errors.New("tclk: refusing to lock into an already-open refund window")
	}
	r.locks[t.Contract] = &lockRec{Terms: t, Status: "locked"}
	return t.Contract, r.save()
}

func (r *Rail) VerifyLock(t LockTerms, ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.locks[ref]
	return ok && h.Status == "locked" && h.Terms == t
}

func (r *Rail) requireLocked(ref, op string) (*lockRec, error) {
	h, ok := r.locks[ref]
	if !ok {
		return nil, fmt.Errorf("tclk: %s on an unknown lock %s", op, ref)
	}
	if h.Status != "locked" {
		return nil, fmt.Errorf("tclk: %s on a %s lock", op, h.Status)
	}
	return h, nil
}

func (r *Rail) Claim(ref, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, err := r.requireLocked(ref, "claim")
	if err != nil {
		return err
	}
	if r.clock() >= h.Terms.RefundAfterMs {
		return errors.New("tclk: claim after refundAfterMs")
	}
	if !VerifySecret(h.Terms.Statement, secret) {
		return errors.New("tclk: secret does not open the statement")
	}
	h.Status, h.Secret = "claimed", strings.ToLower(secret)
	return r.save()
}

func (r *Rail) Refund(ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, err := r.requireLocked(ref, "refund")
	if err != nil {
		return err
	}
	if r.clock() < h.Terms.RefundAfterMs {
		return errors.New("tclk: refund before refundAfterMs")
	}
	h.Status = "refunded"
	return r.save()
}

// Status returns the rail's view of a lock ("" if unknown).
func (r *Rail) Status(ref string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.locks[ref]; ok {
		return h.Status
	}
	return ""
}

// RevealedSecret is what a watcher sees after a claim (on FLOP: the claim extrinsic).
func (r *Rail) RevealedSecret(ref string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.locks[ref]; ok && h.Status == "claimed" {
		return h.Secret, true
	}
	return "", false
}
