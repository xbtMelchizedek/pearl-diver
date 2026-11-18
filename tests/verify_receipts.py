"""Verify Pearl Diver receipts with agentwork's own codec (and its reputation rules).

usage: python3 tests/verify_receipts.py <agentwork-repo> <file.agb1>
"""
import sys

sys.path.insert(0, sys.argv[1])
from agentwork import codec  # noqa: E402

msgs = [codec.decode(line) for line in open(sys.argv[2]) if line.strip()]
by = {m["cid"]: m for m in msgs}
receipts = [m for m in msgs if m["t"] == "receipt"]
assert len(receipts) == 2, f"want 2 receipts, got {len(receipts)}"
for r in receipts:
    claim = by[r["ref"]]
    assert claim["t"] == "claim" and claim["from"] == r["b"]["payee"], "receipt must ref the payee's claim"
    assert r["b"]["outcome"] == "settled"
    accept = by[claim["ref"]]
    assert accept["t"] == "accept" and accept["b"]["contract"] == r["b"]["contract"]
rails = sorted(r["b"]["rail"] for r in receipts)
assert rails == ["memory", "x-prl-htlc"], rails
print(f"ok: {len(msgs)} messages decode and verify; receipts on rails {rails}; contract {receipts[0]['b']['contract'][:18]}...")
