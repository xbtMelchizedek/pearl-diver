// Package timelock converts between wall-clock deadlines (tclk uses Unix ms) and block
// heights (Pearl CLTV), and enforces the HTLC leg-ordering rule.
//
// A block-height deadline does not map to one wall-clock instant: blocks come faster or
// slower than target. So each leg's refund opens inside a window [Earliest, Latest]:
//
//	ms deadline T        -> [T, T]
//	height H at tip h    -> [now + (H-h)*FastBlockMs, now + (H-h)*SlowBlockMs]
//
// Ordering rule (initiator locks first, holds the secret, reveals it last):
//
//	initiator.Earliest > responder.Latest + Margin
//
// i.e. even if the responder's chain is slow and the initiator's chain is fast, the
// responder still has Margin of wall-clock time after the last moment the initiator can
// claim (and reveal) to use the secret on the initiator's leg before that leg can be
// refunded. Margin must cover: noticing the reveal, fee bumping, and getting the
// counter-claim confirmed under congestion.
package timelock

import (
	"errors"
	"fmt"
)

// Pearl's TargetTimePerBlock is 3m14s (chaincfg, all networks).
const PearlTargetBlockMs int64 = 194_000

// Assumptions bound how far block production may drift from target.
type Assumptions struct {
	FastBlockMs int64 // shortest plausible average block interval (e.g. target/2)
	SlowBlockMs int64 // longest plausible average block interval (e.g. target*2)
}

// PearlDefault: blocks between 2x faster and 2x slower than target on average.
// Pearl is a young PoW chain; operators should widen this, not narrow it.
var PearlDefault = Assumptions{FastBlockMs: PearlTargetBlockMs / 2, SlowBlockMs: PearlTargetBlockMs * 2}

func (a Assumptions) check() error {
	if a.FastBlockMs <= 0 || a.SlowBlockMs < a.FastBlockMs {
		return errors.New("timelock: need 0 < FastBlockMs <= SlowBlockMs")
	}
	return nil
}

// Window is the wall-clock interval (Unix ms) in which a leg's refund path opens.
type Window struct{ Earliest, Latest int64 }

// MsWindow is the window of a wall-clock (tclk refundAfterMs) deadline.
func MsWindow(refundAfterMs int64) Window { return Window{refundAfterMs, refundAfterMs} }

// HeightWindow is the window in which CLTV height h becomes spendable, seen from tip at nowMs.
// A refund tx with nLockTime=h is final in block h+1, i.e. once the tip reaches h.
func HeightWindow(nowMs int64, tip, h uint32, a Assumptions) (Window, error) {
	if err := a.check(); err != nil {
		return Window{}, err
	}
	if h <= tip {
		return Window{nowMs, nowMs}, nil // already open
	}
	n := int64(h - tip)
	return Window{nowMs + n*a.FastBlockMs, nowMs + n*a.SlowBlockMs}, nil
}

// HeightNotAfter returns the highest CLTV height whose refund window is guaranteed (under a)
// to open no later than deadlineMs. Use it for the RESPONDER leg when it is on Pearl: the
// responder's refund must be over before the initiator's deadline minus margin.
// Errors if no height in the future satisfies it.
func HeightNotAfter(nowMs int64, tip uint32, deadlineMs int64, a Assumptions) (uint32, error) {
	if err := a.check(); err != nil {
		return 0, err
	}
	n := (deadlineMs - nowMs) / a.SlowBlockMs // floor
	if n < 1 {
		return 0, fmt.Errorf("timelock: deadline %d ms is less than one slow block away", deadlineMs-nowMs)
	}
	return tip + uint32(n), nil
}

// HeightNotBefore returns the lowest CLTV height whose refund window is guaranteed (under a)
// to open no earlier than deadlineMs. Use it for the INITIATOR leg when it is on Pearl.
func HeightNotBefore(nowMs int64, tip uint32, deadlineMs int64, a Assumptions) (uint32, error) {
	if err := a.check(); err != nil {
		return 0, err
	}
	d := deadlineMs - nowMs
	if d <= 0 {
		return tip + 1, nil
	}
	n := (d + a.FastBlockMs - 1) / a.FastBlockMs // ceil
	return tip + uint32(n), nil
}

// CheckOrdering enforces initiator.Earliest > responder.Latest + margin.
func CheckOrdering(initiator, responder Window, marginMs int64) error {
	if marginMs <= 0 {
		return errors.New("timelock: margin must be positive")
	}
	if initiator.Earliest <= responder.Latest+marginMs {
		return fmt.Errorf("timelock: unsafe ordering: initiator refund may open at %d, responder's may open as late as %d (+%d margin)",
			initiator.Earliest, responder.Latest, marginMs)
	}
	return nil
}
