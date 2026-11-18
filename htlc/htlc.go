// Package htlc builds and spends the prl-htlc Taproot output used by Pearl Diver.
//
// Output: P2TR with an unspendable NUMS internal key (BIP-341 "H") and two tapleaves:
//
//	claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <claimer_xonly> OP_CHECKSIG
//	refund: <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refunder_xonly> OP_CHECKSIG
//
// The OP_SIZE check pins the preimage to 32 bytes, the same rule as tclk's hash lock
// (hashLockFromPreimage rejects anything else). Without it a claimer could reveal a
// preimage that one chain accepts and the other chain's escrow rejects.
//
// Everything here uses Pearl's own txscript / btcec packages (a btcd fork), so the
// scripts, sighashes and control blocks are exactly what pearld validates.
package htlc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pearl-research-labs/pearl/node/btcec"
	"github.com/pearl-research-labs/pearl/node/btcec/schnorr"
	"github.com/pearl-research-labs/pearl/node/btcutil"
	"github.com/pearl-research-labs/pearl/node/chaincfg"
	"github.com/pearl-research-labs/pearl/node/txscript"
	"github.com/pearl-research-labs/pearl/node/wire"
)

// NUMSHex is the BIP-341 nothing-up-my-sleeve x-only point H (no known discrete log).
const NUMSHex = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

// PreimageLen is the only accepted preimage length.
const PreimageLen = 32

// RefundSequence makes nLockTime enforceable (anything below 0xffffffff works).
const RefundSequence = wire.MaxTxInSequenceNum - 1

// Params fully determine one HTLC output.
type Params struct {
	Hash     [32]byte // sha256(preimage)
	Claimer  []byte   // 32-byte x-only key that may claim with the preimage
	Refunder []byte   // 32-byte x-only key that may refund after Locktime
	Locktime uint32   // absolute block height (must be < 500000000)
}

// HTLC is a built output.
type HTLC struct {
	Params      Params
	ClaimLeaf   txscript.TapLeaf
	RefundLeaf  txscript.TapLeaf
	Tree        *txscript.IndexedTapScriptTree
	InternalKey *btcec.PublicKey
	OutputKey   *btcec.PublicKey
	PkScript    []byte
}

func numsKey() *btcec.PublicKey {
	b, _ := hex.DecodeString(NUMSHex)
	k, err := schnorr.ParsePubKey(b)
	if err != nil {
		panic(err)
	}
	return k
}

// ClaimScript returns the claim leaf script.
func ClaimScript(hash [32]byte, claimer []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).AddInt64(PreimageLen).AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_SHA256).AddData(hash[:]).AddOp(txscript.OP_EQUALVERIFY).
		AddData(claimer).AddOp(txscript.OP_CHECKSIG).Script()
}

// RefundScript returns the refund leaf script.
func RefundScript(locktime uint32, refunder []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddInt64(int64(locktime)).AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).AddOp(txscript.OP_DROP).
		AddData(refunder).AddOp(txscript.OP_CHECKSIG).Script()
}

// Build constructs the output. It validates keys and the locktime.
func Build(p Params) (*HTLC, error) {
	if len(p.Claimer) != 32 || len(p.Refunder) != 32 {
		return nil, errors.New("htlc: keys must be 32-byte x-only")
	}
	if _, err := schnorr.ParsePubKey(p.Claimer); err != nil {
		return nil, fmt.Errorf("htlc: claimer key: %w", err)
	}
	if _, err := schnorr.ParsePubKey(p.Refunder); err != nil {
		return nil, fmt.Errorf("htlc: refunder key: %w", err)
	}
	if bytes.Equal(p.Claimer, p.Refunder) {
		return nil, errors.New("htlc: claimer and refunder must differ")
	}
	if p.Locktime == 0 || p.Locktime >= txscript.LockTimeThreshold {
		return nil, errors.New("htlc: locktime must be a block height in (0, 500000000)")
	}
	cs, err := ClaimScript(p.Hash, p.Claimer)
	if err != nil {
		return nil, err
	}
	rs, err := RefundScript(p.Locktime, p.Refunder)
	if err != nil {
		return nil, err
	}
	h := &HTLC{Params: p, ClaimLeaf: txscript.NewBaseTapLeaf(cs), RefundLeaf: txscript.NewBaseTapLeaf(rs)}
	h.Tree = txscript.AssembleTaprootScriptTree(h.ClaimLeaf, h.RefundLeaf)
	h.InternalKey = numsKey()
	root := h.Tree.RootNode.TapHash()
	h.OutputKey = txscript.ComputeTaprootOutputKey(h.InternalKey, root[:])
	h.PkScript, err = txscript.PayToTaprootScript(h.OutputKey)
	return h, err
}

// Address returns the bech32m address on the given network.
func (h *HTLC) Address(net *chaincfg.Params) (string, error) {
	a, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(h.OutputKey), net)
	if err != nil {
		return "", err
	}
	return a.EncodeAddress(), nil
}

func (h *HTLC) controlBlock(leaf txscript.TapLeaf) ([]byte, error) {
	idx, ok := h.Tree.LeafProofIndex[leaf.TapHash()]
	if !ok {
		return nil, errors.New("htlc: leaf not in tree")
	}
	cb := h.Tree.LeafMerkleProofs[idx].ToControlBlock(h.InternalKey)
	return cb.ToBytes()
}

// Spend describes a one-input, one-output spend of the HTLC.
type Spend struct {
	Prev     wire.OutPoint
	PrevVal  int64
	DestPk   []byte // destination pkScript
	Fee      int64
	Locktime uint32 // tx nLockTime (refund needs >= Params.Locktime)
}

func (h *HTLC) unsignedTx(s Spend, seq uint32) (*wire.MsgTx, *txscript.TxSigHashes, error) {
	if s.PrevVal-s.Fee <= 0 {
		return nil, nil, errors.New("htlc: fee exceeds value")
	}
	tx := wire.NewMsgTx(2)
	in := wire.NewTxIn(&s.Prev, nil, nil)
	in.Sequence = seq
	tx.AddTxIn(in)
	tx.AddTxOut(wire.NewTxOut(s.PrevVal-s.Fee, s.DestPk))
	tx.LockTime = s.Locktime
	fetch := txscript.NewCannedPrevOutputFetcher(h.PkScript, s.PrevVal)
	return tx, txscript.NewTxSigHashes(tx, fetch), nil
}

// ClaimTx builds and signs the claim spend. It does NOT check the preimage, so tests can
// build an invalid claim and watch the chain reject it.
func (h *HTLC) ClaimTx(s Spend, preimage []byte, claimerKey *btcec.PrivateKey) (*wire.MsgTx, error) {
	tx, sh, err := h.unsignedTx(s, wire.MaxTxInSequenceNum)
	if err != nil {
		return nil, err
	}
	sig, err := txscript.RawTxInTapscriptSignature(tx, sh, 0, s.PrevVal, h.PkScript, h.ClaimLeaf, txscript.SigHashDefault, claimerKey)
	if err != nil {
		return nil, err
	}
	cb, err := h.controlBlock(h.ClaimLeaf)
	if err != nil {
		return nil, err
	}
	tx.TxIn[0].SetWitness(wire.TxWitness{sig, preimage, h.ClaimLeaf.Script, cb})
	return tx, nil
}

// RefundTx builds and signs the refund spend; nLockTime is forced to >= Params.Locktime.
func (h *HTLC) RefundTx(s Spend, refunderKey *btcec.PrivateKey) (*wire.MsgTx, error) {
	if s.Locktime < h.Params.Locktime {
		s.Locktime = h.Params.Locktime
	}
	tx, sh, err := h.unsignedTx(s, RefundSequence)
	if err != nil {
		return nil, err
	}
	sig, err := txscript.RawTxInTapscriptSignature(tx, sh, 0, s.PrevVal, h.PkScript, h.RefundLeaf, txscript.SigHashDefault, refunderKey)
	if err != nil {
		return nil, err
	}
	cb, err := h.controlBlock(h.RefundLeaf)
	if err != nil {
		return nil, err
	}
	tx.TxIn[0].SetWitness(wire.TxWitness{sig, h.RefundLeaf.Script, cb})
	return tx, nil
}

// ExtractPreimage returns the preimage from a witness that spends the claim leaf of h
// and hashes to h.Params.Hash. It returns ok=false for refunds and for anything else.
func (h *HTLC) ExtractPreimage(w wire.TxWitness) ([]byte, bool) {
	if len(w) != 4 || !bytes.Equal(w[2], h.ClaimLeaf.Script) {
		return nil, false
	}
	pre := w[1]
	if len(pre) != PreimageLen {
		return nil, false
	}
	if sha256.Sum256(pre) != h.Params.Hash {
		return nil, false
	}
	return append([]byte(nil), pre...), true
}

// Verify runs Pearl's script engine on a spend of this output (standard tapscript flags).
func (h *HTLC) Verify(tx *wire.MsgTx, prevVal int64) error {
	fetch := txscript.NewCannedPrevOutputFetcher(h.PkScript, prevVal)
	vm, err := txscript.NewEngine(h.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetch), prevVal, fetch)
	if err != nil {
		return err
	}
	return vm.Execute()
}

// KeyPathSpend signs a key-path spend of a plain P2TR output (BIP-86 style, no script
// root) owned by key. Used to move regtest coinbase coins into HTLCs.
func KeyPathSpend(tx *wire.MsgTx, idx int, prevOuts map[wire.OutPoint]*wire.TxOut, key *btcec.PrivateKey) error {
	fetch := txscript.NewMultiPrevOutFetcher(prevOuts)
	sh := txscript.NewTxSigHashes(tx, fetch)
	prev := prevOuts[tx.TxIn[idx].PreviousOutPoint]
	if prev == nil {
		return errors.New("htlc: missing prevout")
	}
	sig, err := txscript.RawTxInTaprootSignature(tx, sh, idx, prev.Value, prev.PkScript, nil, txscript.SigHashDefault, key)
	if err != nil {
		return err
	}
	tx.TxIn[idx].SetWitness(wire.TxWitness{sig})
	return nil
}

// P2TRKeyPath returns the BIP-86 P2TR pkScript and address for a key (no script tree).
func P2TRKeyPath(pub *btcec.PublicKey, net *chaincfg.Params) ([]byte, string, error) {
	out := txscript.ComputeTaprootKeyNoScript(pub)
	pk, err := txscript.PayToTaprootScript(out)
	if err != nil {
		return nil, "", err
	}
	a, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(out), net)
	if err != nil {
		return nil, "", err
	}
	return pk, a.EncodeAddress(), nil
}
