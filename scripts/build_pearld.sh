#!/usr/bin/env bash
# Build pearld + prlctl from source (pearl-research-labs/pearl, branch fp8-scheme, which has
# #507 "mine V4 blocks in regtest generate"). Output: third_party/pearl/bin/.
# Needs: go, cargo, make, gcc, and a C++ compiler for XMSS (set CXX, e.g. CXX=g++ or a zig c++ wrapper).
set -euo pipefail
cd "$(dirname "$0")/.."
REF=${PEARL_REF:-d797c3070a17}   # fp8-scheme tip used for Milestone 1 (2026-11-17)
mkdir -p third_party
[ -d third_party/pearl ] || git clone --branch fp8-scheme https://github.com/pearl-research-labs/pearl.git third_party/pearl
cd third_party/pearl
git fetch -q origin fp8-scheme && git checkout -q "$REF"
export CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*zk_pow_ffi.*"
(cd zk-pow && cargo run --release --no-default-features --bin build_cache src/v4/api/v4_cache.bin src/v2/circuit/v2_cache.bin src/v1/v1_cache.bin)
(cd zk-pow/bindings/go && cargo build --release)
(cd xmss && make CC="${CC:-gcc}" CXX="${CXX:-g++}" lib)
mkdir -p bin
go build -tags xmss,zkpow -o bin/pearld ./node
go build -tags xmss,zkpow -o bin/prlctl ./node/cmd/prlctl
./bin/pearld --version
