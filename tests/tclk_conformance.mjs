// Runs the shared scenarios (tests/rail_scenarios.json) against tclk's REAL MemoryRail
// and prints one boolean per step. simtclk's Go test runs the same file and compares.
// Usage: node tests/tclk_conformance.mjs <path-to-tclk-dist/index.js>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

const tclk = await import(pathToFileURL(process.argv[2]).href);
const scen = JSON.parse(readFileSync(new URL("./rail_scenarios.json", import.meta.url)));
const pre = "0x" + createHash("sha256").update("pearl-diver-conformance").digest("hex");
const stmt = "0x" + createHash("sha256").update(Buffer.from(pre.slice(2), "hex")).digest("hex");
const secrets = { good: pre, bad: "0x" + "00".repeat(32), short: "0x" + pre.slice(2, 40), upper: pre.toUpperCase().replace("0X", "0x") };
const out = {};
for (const s of scen) {
  let now = 0;
  const rail = new tclk.MemoryRail("memory", () => now);
  const terms = { contract: stmt, lock: "hash", statement: stmt, amount: "1000", asset: "FLOP",
    payer: "did:key:payer", payee: "did:key:payee", claimByMs: 500, refundAfterMs: 1000 };
  const res = [];
  for (const st of s.steps) {
    now = st.at;
    try {
      if (st.op === "lock") { await rail.lock(terms); res.push(true); }
      else if (st.op === "verify") { res.push(await rail.verifyLock(st.mut ? { ...terms, amount: "999" } : terms, stmt)); }
      else if (st.op === "claim") { await rail.claim(stmt, secrets[st.secret]); res.push(true); }
      else if (st.op === "refund") { await rail.refund(stmt); res.push(true); }
    } catch { res.push(false); }
  }
  out[s.name] = res;
}
console.log(JSON.stringify(out));
