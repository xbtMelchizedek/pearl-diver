// Package swap coordinates a Pearl Diver atomic swap:
//
//	FLOP (initiator pays, simulated tclk hash escrow)  <->  PRL (responder pays, prl-htlc on Pearl)
//
// Both legs lock under the same sha256 H. The initiator holds the preimage s.
//
//  1. offer    initiator: H, amounts, FLOP deadline T_A (ms), margin
//  2. accept   responder: picks Pearl CLTV height so that the ordering rule holds
//  3. lock     initiator locks FLOP to the responder (refund after T_A)
//  4. lock     responder verifies 3, re-checks ordering, locks PRL to the initiator (CLTV H_B)
//  5. claim    initiator verifies 4 (script rebuilt from terms, amount, confirmations) and
//     claims PRL, which publishes s in the witness
//  6. watch    responder extracts s from the Pearl spend and claims FLOP before T_A
//  7. refund   if anyone stops: PRL back to responder at H_B, FLOP back to initiator at T_A
//
// Ordering rule: initiator.Earliest > responder.Latest + margin (package timelock).
package swap

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/pearl-research-labs/pearl/node/btcec"
	"github.com/pearl-research-labs/pearl/node/btcec/schnorr"
	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/wire"

	"github.com/xbtMelchizedek/pearl-diver/agb1"
	"github.com/xbtMelchizedek/pearl-diver/htlc"
	"github.com/xbtMelchizedek/pearl-diver/pearl"
	"github.com/xbtMelchizedek/pearl-diver/simtclk"
	"github.com/xbtMelchizedek/pearl-diver/timelock"
)

const Version = "pearl-diver/1"

// Party is one side, with its private keys (never serialized).
type Party struct {
	Agb agb1.Signer
	Prl *btcec.PrivateKey
}

// Pub is the public half that goes into Terms.
type Pub struct {
	DID      string `json:"did"`
	PrlXOnly string `json:"prlXOnly"`
}

func (p Party) Pub() Pub {
	return Pub{DID: p.Agb.DID(), PrlXOnly: hex.EncodeToString(schnorr.SerializePubKey(p.Prl.PubKey()))}
}

// Terms are what both sides agree to. ID() commits to all of them.
type Terms struct {
	Version           string `json:"version"`
	Net               string `json:"net"`
	Hash              string `json:"hash"` // 0x sha256(preimage)
	Initiator         Pub    `json:"initiator"`
	Responder         Pub    `json:"responder"`
	FlopAsset         string `json:"flopAsset"`
	FlopAmt           string `json:"flopAmt"` // base units (18 decimals), simulated
	PrlAmt            int64  `json:"prlAmt"`  // grains (1e8 per PRL), local chain only
	FlopClaimByMs     int64  `json:"flopClaimByMs"`
	FlopRefundAfterMs int64  `json:"flopRefundAfterMs"`
	PrlLocktime       uint32 `json:"prlLocktime"`
	MarginMs          int64  `json:"marginMs"`
	MinConf           int64  `json:"minConf"`
	CreatedMs         int64  `json:"createdMs"`
}

// ID is 0x + sha256 of the canonical terms.
func (t Terms) ID() string {
	c, err := agb1.Canonical(map[string]any{
		"version": t.Version, "net": t.Net, "hash": t.Hash,
		"initiator": map[string]any{"did": t.Initiator.DID, "prlXOnly": t.Initiator.PrlXOnly},
		"responder": map[string]any{"did": t.Responder.DID, "prlXOnly": t.Responder.PrlXOnly},
		"flopAsset": t.FlopAsset, "flopAmt": t.FlopAmt, "prlAmt": t.PrlAmt,
		"flopClaimByMs": t.FlopClaimByMs, "flopRefundAfterMs": t.FlopRefundAfterMs,
		"prlLocktime": int64(t.PrlLocktime), "marginMs": t.MarginMs, "minConf": t.MinConf, "createdMs": t.CreatedMs,
	})
	if err != nil {
		panic(err)
	}
	s := sha256.Sum256([]byte("pearl-diver/terms|" + c))
	return "0x" + hex.EncodeToString(s[:])
}

func (t Terms) hash32() ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(t.Hash, "0x"))
	if err != nil || len(b) != 32 {
		return h, errors.New("swap: bad hash")
	}
	copy(h[:], b)
	return h, nil
}

// HTLC rebuilds the Pearl output from the terms (never from a counterparty's bytes).
func (t Terms) HTLC() (*htlc.HTLC, error) {
	h, err := t.hash32()
	if err != nil {
		return nil, err
	}
	c, err1 := hex.DecodeString(t.Initiator.PrlXOnly)
	r, err2 := hex.DecodeString(t.Responder.PrlXOnly)
	if err1 != nil || err2 != nil {
		return nil, errors.New("swap: bad x-only key")
	}
	return htlc.Build(htlc.Params{Hash: h, Claimer: c, Refunder: r, Locktime: t.PrlLocktime})
}

// FlopTerms is the FLOP-leg projection (tclk LockTerms).
func (t Terms) FlopTerms() simtclk.LockTerms {
	return simtclk.LockTerms{Contract: t.ID(), Lock: "hash", Statement: t.Hash, Amount: t.FlopAmt, Asset: t.FlopAsset,
		Payer: t.Initiator.DID, Payee: t.Responder.DID, ClaimByMs: t.FlopClaimByMs, RefundAfterMs: t.FlopRefundAfterMs}
}

// NewSecret returns a fresh 32-byte preimage and its 0x hash.
func NewSecret() ([]byte, string) {
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	h := sha256.Sum256(s)
	return s, "0x" + hex.EncodeToString(h[:])
}

// Coord runs swap steps against a Pearl rail and the simulated FLOP rail.
type Coord struct {
	Pearl  pearl.Rail
	Flop   *simtclk.Rail
	Clock  func() int64
	Assume timelock.Assumptions
	// MinResponderBlocks: the initiator needs at least this many blocks between the
	// responder's lock and H_B to claim safely.
	MinResponderBlocks uint32
	// ClaimSafetyBlocks: the initiator refuses to claim when tip+this >= H_B (the
	// responder could race a refund against a late claim).
	ClaimSafetyBlocks uint32
}

// Offer builds the initiator's half of the terms.
func Offer(init Party, net, hash, flopAmt string, prlAmt, nowMs, flopWindowMs, marginMs, minConf int64) Terms {
	return Terms{Version: Version, Net: net, Hash: hash, Initiator: init.Pub(), FlopAsset: "FLOP", FlopAmt: flopAmt,
		PrlAmt: prlAmt, FlopClaimByMs: nowMs + flopWindowMs - marginMs, FlopRefundAfterMs: nowMs + flopWindowMs,
		MarginMs: marginMs, MinConf: minConf, CreatedMs: nowMs}
}

// Accept fills in the responder and picks the Pearl CLTV height:
// the highest height whose refund is sure (under Assume) to open before T_A - margin.
func (c *Coord) Accept(t Terms, resp Party) (Terms, error) {
	tip, err := c.Pearl.C.Tip()
	if err != nil {
		return t, err
	}
	now := c.Clock()
	h, err := timelock.HeightNotAfter(now, tip, t.FlopRefundAfterMs-t.MarginMs-1, c.Assume)
	if err != nil {
		return t, err
	}
	t.Responder = resp.Pub()
	t.PrlLocktime = h
	return t, c.CheckTiming(t, false)
}

// CheckTiming re-checks the ordering rule and the responder window at the current tip/time.
func (c *Coord) CheckTiming(t Terms, initiatorClaiming bool) error {
	tip, err := c.Pearl.C.Tip()
	if err != nil {
		return err
	}
	now := c.Clock()
	respW, err := timelock.HeightWindow(now, tip, t.PrlLocktime, c.Assume)
	if err != nil {
		return err
	}
	if err := timelock.CheckOrdering(timelock.MsWindow(t.FlopRefundAfterMs), respW, t.MarginMs); err != nil {
		return err
	}
	need := c.MinResponderBlocks
	if initiatorClaiming {
		need = c.ClaimSafetyBlocks
	}
	if t.PrlLocktime <= tip+need {
		return fmt.Errorf("swap: Pearl locktime %d too close to tip %d (need > %d blocks)", t.PrlLocktime, tip, need)
	}
	return nil
}

// InitiatorLock locks the FLOP leg (simulated).
func (c *Coord) InitiatorLock(t Terms) (string, error) { return c.Flop.Lock(t.FlopTerms()) }

// ResponderLock verifies the FLOP lock, re-checks timing, and locks PRL.
func (c *Coord) ResponderLock(t Terms, resp Party, flopRef string) (wire.OutPoint, error) {
	if t.Responder != resp.Pub() {
		return wire.OutPoint{}, errors.New("swap: terms do not name this responder")
	}
	if !c.Flop.VerifyLock(t.FlopTerms(), flopRef) {
		return wire.OutPoint{}, errors.New("swap: FLOP lock missing or terms differ; not locking PRL")
	}
	if err := c.CheckTiming(t, false); err != nil {
		return wire.OutPoint{}, err
	}
	h, err := t.HTLC()
	if err != nil {
		return wire.OutPoint{}, err
	}
	return c.Pearl.Lock(h, resp.Prl, t.PrlAmt)
}

// InitiatorClaim verifies the PRL lock and claims it, revealing the preimage.
func (c *Coord) InitiatorClaim(t Terms, init Party, op wire.OutPoint, preimage []byte) (*chainhash.Hash, error) {
	if t.Initiator != init.Pub() {
		return nil, errors.New("swap: terms do not name this initiator")
	}
	h, err := t.HTLC()
	if err != nil {
		return nil, err
	}
	if err := c.Pearl.VerifyLock(h, op, t.PrlAmt, t.MinConf); err != nil {
		return nil, err
	}
	if err := c.CheckTiming(t, true); err != nil {
		return nil, err
	}
	return c.Pearl.Claim(h, op, t.PrlAmt, preimage, init.Prl)
}

// ResponderCounterClaim watches Pearl for the preimage and claims FLOP with it.
// Returns ("", nil) if the preimage is not public yet.
func (c *Coord) ResponderCounterClaim(t Terms, op wire.OutPoint, flopRef string, fromHeight uint32) (string, error) {
	h, err := t.HTLC()
	if err != nil {
		return "", err
	}
	pre, _, ok, err := c.Pearl.WatchPreimage(h, op, fromHeight)
	if err != nil || !ok {
		return "", err
	}
	s := "0x" + hex.EncodeToString(pre)
	return s, c.Flop.Claim(flopRef, s)
}

// InitiatorRefund takes the FLOP leg back (only at/after T_A).
func (c *Coord) InitiatorRefund(flopRef string) error { return c.Flop.Refund(flopRef) }

// ResponderRefund takes the PRL leg back (pearld enforces tip >= H_B).
func (c *Coord) ResponderRefund(t Terms, resp Party, op wire.OutPoint) (*chainhash.Hash, error) {
	h, err := t.HTLC()
	if err != nil {
		return nil, err
	}
	return c.Pearl.Refund(h, op, t.PrlAmt, resp.Prl)
}
