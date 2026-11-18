package pearl

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/pearl-research-labs/pearl/node/btcec"
	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/wire"

	"github.com/xbtMelchizedek/pearl-diver/htlc"
)

// RailID is the extension id receipts use until tclk's closed registry has `prl-htlc`.
const RailID = "x-prl-htlc"

// Rail is the prl-htlc settlement rail on a local Pearl node.
type Rail struct{ C *Client }

// Lock funds the HTLC from payer's key-path address. Returns the HTLC outpoint.
func (r Rail) Lock(h *htlc.HTLC, payer *btcec.PrivateKey, amt int64) (wire.OutPoint, error) {
	return r.C.Pay(payer, h.PkScript, amt)
}

// VerifyLock: the outpoint is unspent, pays exactly h's script and amt, with >= minConf.
// The verifier rebuilds h from the agreed terms itself; it never trusts a sent script.
func (r Rail) VerifyLock(h *htlc.HTLC, op wire.OutPoint, amt int64, minConf int64) error {
	o, conf, err := r.C.Output(op)
	if err != nil {
		return err
	}
	if !bytes.Equal(o.PkScript, h.PkScript) {
		return errors.New("prl-htlc: output script does not match the agreed HTLC")
	}
	if o.Value != amt {
		return fmt.Errorf("prl-htlc: amount %d != agreed %d", o.Value, amt)
	}
	if conf < minConf {
		return fmt.Errorf("prl-htlc: %d confirmations < %d", conf, minConf)
	}
	return nil
}

// Claim spends the claim leaf with the preimage (this publishes the preimage).
func (r Rail) Claim(h *htlc.HTLC, op wire.OutPoint, amt int64, preimage []byte, claimer *btcec.PrivateKey) (*chainhash.Hash, error) {
	dest, _, err := htlc.P2TRKeyPath(claimer.PubKey(), r.C.Net)
	if err != nil {
		return nil, err
	}
	tx, err := h.ClaimTx(htlc.Spend{Prev: op, PrevVal: amt, DestPk: dest, Fee: DefaultFee}, preimage, claimer)
	if err != nil {
		return nil, err
	}
	return r.C.Send(tx)
}

// Refund spends the CLTV leaf back to the refunder. pearld rejects it until tip >= locktime.
func (r Rail) Refund(h *htlc.HTLC, op wire.OutPoint, amt int64, refunder *btcec.PrivateKey) (*chainhash.Hash, error) {
	dest, _, err := htlc.P2TRKeyPath(refunder.PubKey(), r.C.Net)
	if err != nil {
		return nil, err
	}
	tx, err := h.RefundTx(htlc.Spend{Prev: op, PrevVal: amt, DestPk: dest, Fee: DefaultFee, Locktime: h.Params.Locktime}, refunder)
	if err != nil {
		return nil, err
	}
	return r.C.Send(tx)
}

// WatchPreimage returns the preimage if the HTLC was claimed (mempool or chain since
// fromHeight). ok=false if unspent or refunded.
func (r Rail) WatchPreimage(h *htlc.HTLC, op wire.OutPoint, fromHeight uint32) (pre []byte, spender *chainhash.Hash, ok bool, err error) {
	tx, err := r.C.FindSpend(op, fromHeight)
	if err != nil || tx == nil {
		return nil, nil, false, err
	}
	id := tx.TxHash()
	for _, in := range tx.TxIn {
		if in.PreviousOutPoint == op {
			if p, ok := h.ExtractPreimage(in.DecodeWitness()); ok {
				return p, &id, true, nil
			}
		}
	}
	return nil, &id, false, nil // spent another way (refund)
}
