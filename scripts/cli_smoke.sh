#!/usr/bin/env bash
# Two-sided swap through the CLI step commands on a throwaway local simnet node.
# Usage: PEARLD_BIN=/path/to/pearld scripts/cli_smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o bin/pearldiver ./cmd/pearldiver
PD=bin/pearldiver
D=$(mktemp -d)
export PEARL_DIVER_HOME=${PEARL_DIVER_HOME:-$D/home}   # throwaway keys unless you pass your own
trap 'kill $NODE 2>/dev/null || true; wait $NODE 2>/dev/null || true; rm -rf "$D"' EXIT
U=$(python3 -c 'import secrets;print(secrets.token_hex(8))'); P=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
printf 'rpcuser=%s\nrpcpass=%s\n' "$U" "$P" > "$D/pearld.conf"; chmod 600 "$D/pearld.conf"
"$PEARLD_BIN" --simnet --configfile="$D/pearld.conf" --datadir="$D/data" --logdir="$D/log" --rpclisten=127.0.0.1:$PORT \
  --notls --nolisten --nodnsseed --txindex --rejectnonstd --miningaddr="$($PD miner-address --net simnet)" >"$D/out.log" 2>&1 &
NODE=$!
export PD_RPC_HOST=127.0.0.1:$PORT PD_RPC_USER=$U PD_RPC_PASS=$P PD_NET=simnet
for i in $(seq 1 50); do $PD mine --n 0 >/dev/null 2>&1 && break; sleep 0.3; done
$PD mine --n 103
$PD keygen --name smoke-alice >/dev/null; $PD keygen --name smoke-bob >/dev/null
$PD faucet --name smoke-bob --prl-amt 300000000; $PD mine --n 1
S="$D/swap.json"
$PD offer  --state "$S" --initiator smoke-alice --prl-amt 100000000
$PD accept --state "$S" --responder smoke-bob
$PD lock-flop --state "$S"
$PD lock-prl  --state "$S" --responder smoke-bob; $PD mine --n 1
$PD watch     --state "$S"                       # nothing yet
$PD claim-prl --state "$S" --initiator smoke-alice
$PD watch     --state "$S"                       # sees the preimage, claims FLOP (sim)
$PD mine --n 1
$PD receipts  --state "$S" --initiator smoke-alice --responder smoke-bob --out "$D/receipts.agb1"
if [ -n "${AGENTWORK_PATH:-}" ]; then python3 tests/verify_receipts.py "$AGENTWORK_PATH" "$D/receipts.agb1"; fi
echo "cli smoke: OK"
