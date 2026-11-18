// Package pearl is the Pearl side of Pearl Diver: a thin client over pearld's JSON-RPC
// (local regtest/simnet only) and the prl-htlc rail built on package htlc.
package pearl

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pearl-research-labs/pearl/node/btcec"
	"github.com/pearl-research-labs/pearl/node/chaincfg"
	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/rpcclient"
	"github.com/pearl-research-labs/pearl/node/wire"

	"github.com/xbtMelchizedek/pearl-diver/htlc"
)

// DefaultFee in grains (1 PRL = 1e8 grains). Generous for an empty local mempool.
const DefaultFee int64 = 20_000

// Config points at a LOCAL pearld. Mainnet and public testnet are refused.
type Config struct {
	Host, User, Pass string
	Net              *chaincfg.Params
}

// Client wraps pearld RPC.
type Client struct {
	rpc *rpcclient.Client
	Net *chaincfg.Params
}

// LocalOnly refuses anything but regtest/simnet.
func LocalOnly(net *chaincfg.Params) error {
	if net.Name != chaincfg.RegressionNetParams.Name && net.Name != chaincfg.SimNetParams.Name {
		return fmt.Errorf("pearl-diver: network %q refused; local regtest/simnet only", net.Name)
	}
	return nil
}

// Dial connects (HTTP POST, no TLS: localhost only).
func Dial(c Config) (*Client, error) {
	if err := LocalOnly(c.Net); err != nil {
		return nil, err
	}
	r, err := rpcclient.New(&rpcclient.ConnConfig{Host: c.Host, User: c.User, Pass: c.Pass,
		HTTPPostMode: true, DisableTLS: true}, nil)
	if err != nil {
		return nil, err
	}
	return &Client{rpc: r, Net: c.Net}, nil
}

func (c *Client) Close() { c.rpc.Shutdown() }

// Tip returns the current height.
func (c *Client) Tip() (uint32, error) {
	h, err := c.rpc.GetBlockCount()
	return uint32(h), err
}

// Mine generates n blocks (pearld --generate support: regtest real V4 proofs, simnet dummy).
func (c *Client) Mine(n uint32) error {
	for i := uint32(0); i < n; i++ {
		if _, err := c.rpc.Generate(1); err != nil {
			return err
		}
	}
	return nil
}

// MineTo mines until the tip is at least h.
func (c *Client) MineTo(h uint32) error {
	tip, err := c.Tip()
	if err != nil {
		return err
	}
	if tip >= h {
		return nil
	}
	return c.Mine(h - tip)
}

// Send broadcasts a transaction to the local node.
func (c *Client) Send(tx *wire.MsgTx) (*chainhash.Hash, error) {
	return c.rpc.SendRawTransaction(tx, false)
}

// UTXO is a spendable output.
type UTXO struct {
	OutPoint wire.OutPoint
	Out      *wire.TxOut
	Conf     int64
	Coinbase bool
}

// UTXOs scans the chain for unspent outputs paying pk with at least minConf (coinbase
// outputs also need maturity). Fine for a local chain; not an indexer.
func (c *Client) UTXOs(pk []byte, minConf int64) ([]UTXO, error) {
	tip, err := c.Tip()
	if err != nil {
		return nil, err
	}
	var out []UTXO
	for h := int64(1); h <= int64(tip); h++ {
		bh, err := c.rpc.GetBlockHash(h)
		if err != nil {
			return nil, err
		}
		blk, err := c.rpc.GetBlock(bh)
		if err != nil {
			return nil, err
		}
		for ti, tx := range blk.Transactions {
			txid := tx.TxHash()
			for vi, o := range tx.TxOut {
				if !bytes.Equal(o.PkScript, pk) {
					continue
				}
				res, err := c.rpc.GetTxOut(&txid, uint32(vi), false)
				if err != nil || res == nil {
					continue // spent
				}
				if res.Confirmations < minConf || (ti == 0 && res.Confirmations < int64(c.Net.CoinbaseMaturity)+1) {
					continue
				}
				out = append(out, UTXO{wire.OutPoint{Hash: txid, Index: uint32(vi)}, o, res.Confirmations, ti == 0})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Out.Value > out[j].Out.Value })
	return out, nil
}

// Pay sends amt grains from key's BIP-86 key-path address to dest, change back to key.
// Returns the outpoint of the payment (vout 0).
func (c *Client) Pay(key *btcec.PrivateKey, dest []byte, amt int64) (wire.OutPoint, error) {
	src, _, err := htlc.P2TRKeyPath(key.PubKey(), c.Net)
	if err != nil {
		return wire.OutPoint{}, err
	}
	utxos, err := c.UTXOs(src, 1)
	if err != nil {
		return wire.OutPoint{}, err
	}
	for _, u := range utxos {
		if u.Out.Value < amt+DefaultFee {
			continue
		}
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(wire.NewTxIn(&u.OutPoint, nil, nil))
		tx.AddTxOut(wire.NewTxOut(amt, dest))
		if change := u.Out.Value - amt - DefaultFee; change > 0 {
			tx.AddTxOut(wire.NewTxOut(change, src))
		}
		if err := htlc.KeyPathSpend(tx, 0, map[wire.OutPoint]*wire.TxOut{u.OutPoint: u.Out}, key); err != nil {
			return wire.OutPoint{}, err
		}
		id, err := c.Send(tx)
		if err != nil {
			return wire.OutPoint{}, err
		}
		return wire.OutPoint{Hash: *id, Index: 0}, nil
	}
	return wire.OutPoint{}, errors.New("pearl: no spendable output large enough (mine more blocks?)")
}

// Output returns an UNSPENT output and its confirmations (0 = mempool).
func (c *Client) Output(op wire.OutPoint) (*wire.TxOut, int64, error) {
	res, err := c.rpc.GetTxOut(&op.Hash, op.Index, true)
	if err != nil {
		return nil, 0, err
	}
	if res == nil {
		return nil, 0, errors.New("pearl: output spent or unknown")
	}
	raw, err := c.rpc.GetRawTransaction(&op.Hash)
	if err != nil {
		return nil, 0, err
	}
	txo := raw.MsgTx().TxOut
	if int(op.Index) >= len(txo) {
		return nil, 0, errors.New("pearl: bad vout")
	}
	return txo[op.Index], res.Confirmations, nil
}

// FindSpend looks for a tx spending op in the mempool and then in blocks [from, tip].
func (c *Client) FindSpend(op wire.OutPoint, from uint32) (*wire.MsgTx, error) {
	check := func(tx *wire.MsgTx) bool {
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint == op {
				return true
			}
		}
		return false
	}
	if pool, err := c.rpc.GetRawMempool(); err == nil {
		for _, h := range pool {
			if t, err := c.rpc.GetRawTransaction(h); err == nil && check(t.MsgTx()) {
				return t.MsgTx(), nil
			}
		}
	}
	tip, err := c.Tip()
	if err != nil {
		return nil, err
	}
	if from == 0 {
		from = 1
	}
	for h := from; h <= tip; h++ {
		bh, err := c.rpc.GetBlockHash(int64(h))
		if err != nil {
			return nil, err
		}
		blk, err := c.rpc.GetBlock(bh)
		if err != nil {
			return nil, err
		}
		for _, tx := range blk.Transactions {
			if check(tx) {
				return tx, nil
			}
		}
	}
	return nil, nil
}

// WaitConfirm mines (if mine) or polls until txid has a confirmation.
func (c *Client) WaitConfirm(txid *chainhash.Hash, mine bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if r, err := c.rpc.GetRawTransactionVerbose(txid); err == nil && r.Confirmations > 0 {
			return nil
		}
		if mine {
			if err := c.Mine(1); err != nil {
				return err
			}
		} else {
			time.Sleep(time.Second)
		}
	}
	return fmt.Errorf("pearl: %s not confirmed in %s", txid, timeout)
}
