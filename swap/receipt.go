package swap

import (
	"fmt"

	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/wire"

	"github.com/xbtMelchizedek/pearl-diver/agb1"
	"github.com/xbtMelchizedek/pearl-diver/pearl"
	"github.com/xbtMelchizedek/pearl-diver/simtclk"
)

// Receipts returns the signed agb1 thread for a COMPLETED swap (both legs claimed):
//
//	ask(I) -> offer(R) -> accept(I) -> claim(R: PRL locked) + claim(I: FLOP locked)
//	-> receipt(I pays R, FLOP, rail "memory") + receipt(R pays I, PRL, rail "x-prl-htlc")
//
// Each receipt's ref is the payee's claim, as agentwork reputation requires. railRef values
// carry the network name, so a regtest receipt can never be read as a mainnet settlement.
// Nothing is posted anywhere; the caller decides what to do with the lines.
func Receipts(t Terms, init, resp Party, flopRef string, prlLock wire.OutPoint, prlClaim *chainhash.Hash, flopClaimTs, prlClaimTs int64) ([]agb1.Msg, error) {
	room := "app/pearl-diver/" + t.Net
	k := []string{"pearl-diver", t.Net}
	id := t.ID()
	var out []agb1.Msg
	add := func(s agb1.Signer, typ string, body map[string]any, ref string, ts int64) (agb1.Msg, error) {
		m, err := s.Build(typ, room, body, agb1.Opts{Ref: ref, K: k, TsMs: ts})
		if err == nil {
			out = append(out, m)
		}
		return m, err
	}
	ts := t.CreatedMs
	ask, err := add(init.Agb, "ask", map[string]any{
		"task":   fmt.Sprintf("atomic swap %s: %s FLOP base units (simulated tclk escrow) for %d PRL grains (%s), same sha256 lock %s", id, t.FlopAmt, t.PrlAmt, t.Net, t.Hash),
		"budget": map[string]any{"asset": "FLOP", "max": t.FlopAmt},
	}, "", ts)
	if err != nil {
		return nil, err
	}
	offer, err := add(resp.Agb, "offer", map[string]any{
		"price": map[string]any{"asset": "FLOP", "amt": t.FlopAmt},
		"rails": []string{simtclk.RailID, pearl.RailID},
		"note":  fmt.Sprintf("pays %d PRL grains via %s, CLTV height %d", t.PrlAmt, pearl.RailID, t.PrlLocktime),
	}, ask.CID, ts+1)
	if err != nil {
		return nil, err
	}
	accept, err := add(init.Agb, "accept", map[string]any{"payee": resp.Agb.DID(), "contract": id}, offer.CID, ts+2)
	if err != nil {
		return nil, err
	}
	rClaim, err := add(resp.Agb, "claim", map[string]any{
		"deliverable": fmt.Sprintf("%s:%s:%s:%d", pearl.RailID, t.Net, prlLock.Hash, prlLock.Index),
		"note":        "PRL locked to the initiator under the agreed hash",
	}, accept.CID, ts+3)
	if err != nil {
		return nil, err
	}
	iClaim, err := add(init.Agb, "claim", map[string]any{
		"deliverable": fmt.Sprintf("%s:%s", simtclk.RailID, flopRef),
		"note":        "FLOP locked to the responder under the agreed hash (simulated rail)",
	}, accept.CID, ts+4)
	if err != nil {
		return nil, err
	}
	if _, err = add(init.Agb, "receipt", map[string]any{
		"outcome": "settled", "payee": resp.Agb.DID(),
		"amount": map[string]any{"asset": "FLOP", "amt": t.FlopAmt},
		"rail":   simtclk.RailID, "railRef": "sim:" + flopRef, "contract": id,
	}, rClaim.CID, flopClaimTs); err != nil {
		return nil, err
	}
	if _, err = add(resp.Agb, "receipt", map[string]any{
		"outcome": "settled", "payee": init.Agb.DID(),
		"amount": map[string]any{"asset": "PRL", "amt": fmt.Sprint(t.PrlAmt)},
		"rail":   pearl.RailID, "railRef": t.Net + ":" + prlClaim.String(), "contract": id,
		"deliverable": fmt.Sprintf("%s:%d", prlLock.Hash, prlLock.Index),
	}, iClaim.CID, prlClaimTs); err != nil {
		return nil, err
	}
	return out, nil
}
