# Pearl Diver

Hash-locked atomic swaps between **Pearl (PRL)** and **FLOP**, with no bridge and no custodian,
plus a signed [agentwork](https://github.com/xbtMelchizedek/agentwork) receipt for every
completed swap.

> **Status: Milestone 1, local only.** The Pearl leg runs on a real `pearld` built from source,
> on **regtest** (real V4 proofs, CPU mining) or **simnet** (same node, dummy proofs, fast). The
> FLOP leg is a **simulation** of tclk's hash-lock escrow. Nothing here has touched mainnet,
> a public testnet, or anything of value. The code is unaudited. Don't use it with real funds.

## What works and what is simulated

| Piece | Status |
|---|---|
| `prl-htlc` Taproot output (hashlock + CLTV leaves, NUMS internal key) | **Real.** Built with Pearl's own `txscript`/`btcec`, accepted and enforced by `pearld` |
| Claim reveals preimage, counterparty extracts it from the witness (mempool or block) | **Real** on regtest/simnet |
| Refund rejected before CLTV, accepted at it | **Real** (mempool policy *and* consensus, see tests) |
| Wrong preimage, wrong key, 33-byte preimage | **Rejected** by `pearld` / Pearl's script engine |
| FLOP leg (`simtclk`) | **Simulated.** Go port of tclk's `MemoryRail` predicates, cross-checked against tclk's real `MemoryRail` (commit 7d402db) by `simtclk/conformance_test.go`. No FLOP chain, no `tclk-flop`, no testnet |
| Deadline (ms) ↔ block height conversion, leg-ordering rule | **Real** (package `timelock`) |
| agb1 receipts | **Real** signatures, verified by agentwork's own Python codec in the tests. Signed with throwaway local keys; not posted anywhere |

## How a swap runs

Alice (initiator) has FLOP and wants PRL. Bob (responder) has PRL and wants FLOP.

```
1 offer    Alice: s ← random 32 bytes, H = sha256(s); amounts; FLOP refund time T_A (ms); margin
2 accept   Bob:   H_B = highest Pearl height whose refund surely opens before T_A − margin
3 lock     Alice: FLOP into hash escrow (payee Bob, statement H, refundAfterMs T_A)       [simulated]
4 lock     Bob:   verifies 3 exactly, re-checks timing, funds prl-htlc (claim: Alice+s, refund: Bob@H_B)
5 claim    Alice: rebuilds the HTLC from the terms, checks script/amount/confirmations, spends the
                  claim leaf; the witness publishes s
6 watch    Bob:   sees the spend (mempool first), extracts s, claims the FLOP escrow before T_A
7 refund   if someone stops: PRL back to Bob at H_B, FLOP back to Alice at T_A
```

### The output

```
internal key: BIP-341 NUMS point H (no key-path spend)
leaf 0 claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <alice_xonly> OP_CHECKSIG
leaf 1 refund: <H_B> OP_CHECKLOCKTIMEVERIFY OP_DROP <bob_xonly> OP_CHECKSIG
```

`OP_SIZE 32` pins the preimage to 32 bytes, the same rule tclk's `hashLockFromPreimage` uses.
Without it, a claimer could reveal a preimage that one chain's lock accepts and the other's
rejects. The verifier always **rebuilds** the script from the agreed terms. It never trusts a
script or address the counterparty sends.

### Ordering rule

A Pearl height doesn't map to one moment in time, because blocks come early or late. So each
leg's refund opens inside a window:

```
ms deadline T            → [T, T]
height H at tip h, now   → [now + (H−h)·fast, now + (H−h)·slow]      fast = 97 s, slow = 388 s by default
```

The rule is **`initiator.earliest > responder.latest + margin`**. Even if Pearl is slow, Bob
still has `margin` after the last moment Alice can reveal `s` to use it on the FLOP leg.
`timelock.HeightNotAfter` picks H_B; `CheckTiming` re-checks it at lock time and claim time.
The defaults (blocks 2× faster or slower than Pearl's 3m14s target) are a starting point. Pearl is
a young PoW chain that just had a hard fork, so widen them for real use.

## Threat model and honest limits

- **Free option.** After step 4, Alice can wait and claim only if the price moved her way,
  then let everything refund otherwise. HTLC swaps can't fix this on their own. Ways to soften
  it: short windows, Alice locking first (done here), or a premium or deposit that Bob keeps if
  Alice walks. Not implemented.
- **Timelock griefing.** Either side can lock the other's funds until the timeout at the cost of
  their own. Bob's capital is stuck until H_B, Alice's until T_A. Reputation (agb1 receipts) is
  the only deterrent here.
- **Late-claim race.** If Alice claims close to H_B, her claim and Bob's refund can both be
  valid. The coordinator refuses to claim within `ClaimSafetyBlocks` of H_B, and the margin
  covers Bob's counter-claim. Both are parameters, not guarantees.
- **Liveness.** Bob must be online and watching between Alice's claim and T_A. A watchtower
  could do this but isn't built.
- **Reorgs and finality.** `MinConf` is 1 in tests. Pearl is young PoW, so real use needs many
  more confirmations on the Pearl lock and on the claim.
- **Fees.** The fee is fixed at 20,000 grains. No RBF or CPFP bumping yet. Under congestion a
  claim or refund could miss its window.
- **Privacy.** Both legs use the same H, so the two chains can be linked.
- **tclk adaptor signatures aren't Taproot-valid.** tclk's point-lock/adaptor path isn't BIP-340,
  so the scriptless PTLC variant (which would hide H and fix the linkability) can't be used on
  Pearl yet. This rail is hash-lock only.
- **The FLOP leg is a simulation.** `simtclk` enforces the same predicates as tclk's
  `MemoryRail`, but a real `flop-htlc` escrow has its own block deadlines, fees and finality.
  None of that is modeled. FLOP testnet is scheduled for Nov 24, 2026 (claimed by Arthur Hayes,
  not verified), and FLOP has no token yet.
- **Rail id.** `prl-htlc` isn't in tclk's closed rail registry. Receipts use the extension id
  `x-prl-htlc` until a registry proposal is accepted (draft: `drafts/tclk_prl_htlc_proposal.md`).
- **Unaudited.** The scripts are tested against `pearld`, not reviewed by anyone else.

## Receipts

Each completed swap emits a 7-message agb1 thread (ask → offer → accept → two claims → two
receipts). Each receipt references the payee's claim, as agentwork reputation requires:

- receipt from Alice to Bob: `asset FLOP`, `rail memory`, `railRef sim:<escrow id>`
- receipt from Bob to Alice: `asset PRL`, `rail x-prl-htlc`, `railRef <net>:<claim txid>`

`railRef` always names the network (`regtest:`/`simnet:`/`sim:`), so a test receipt can't be
taken for a real settlement. agentwork reputation v0 only counts assets in its `decimals`
table (FLOP today) and needs a third-party attestation, so these receipts verify but carry no
score until an attester (e.g. Elders' Seal) checks them.

## Build and run

Requirements: Go ≥ 1.26, Rust, a C compiler, make, and a C++ compiler for Pearl's XMSS library.

```bash
scripts/build_pearld.sh                          # clones pearl @ fp8-scheme (#507), builds pearld + prlctl
export PEARLD_BIN=$PWD/third_party/pearl/bin/pearld
go test ./...                                    # unit tests (no node needed)
go test -v ./itest/                              # integration tests on a fresh simnet node
PD_NET=regtest go test -v ./itest/ -timeout 3h   # regtest (real V4 proofs, ~30 s per block)
go run ./cmd/pearldiver demo --net simnet        # full happy path + receipts in out/
```

Keys are created on first use in `$PEARL_DIVER_HOME/keys` (default `~/.pearl-diver/keys`) with
mode 600, and are never printed. Nodes started by the tests and the demo bind to 127.0.0.1, use
random RPC credentials, and run without P2P or DNS seeds. The client refuses any network other
than regtest or simnet.

The CLI also has step commands (`offer`, `accept`, `lock-flop`, `lock-prl`, `claim-prl`,
`watch`, `refund-prl`, `refund-flop`, `receipts`, `height-for`) for running the two sides as
separate processes. `scripts/cli_smoke.sh` runs a full swap through them on a throwaway simnet
node. See `cmd/pearldiver/main.go`.

## Layout

```
htlc/      prl-htlc script, address, claim/refund signing, preimage extraction
timelock/  ms ↔ height windows, ordering rule
simtclk/   simulated tclk hash escrow (MemoryRail port) + conformance test vs tclk
pearl/     pearld RPC client, prl-htlc rail, throwaway local node launcher
swap/      coordinator (offer/accept/lock/claim/watch/refund) and agb1 receipts
agb1/      agb1 canonical JSON, did:key, Ed25519 signing
itest/     integration tests against a real pearld
cmd/pearldiver/  CLI
```

## License

MIT. Pearl (ISC) and tclk (Apache-2.0) are build or test dependencies only. Neither is vendored
into this repo.
