package simtclk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

type step struct {
	Op     string `json:"op"`
	At     int64  `json:"at"`
	Secret string `json:"secret"`
	Mut    bool   `json:"mut"`
}
type scenario struct {
	Name  string `json:"name"`
	Steps []step `json:"steps"`
}

func runGo(t *testing.T, scen []scenario) map[string][]bool {
	ph := sha256.Sum256([]byte("pearl-diver-conformance"))
	pre := "0x" + hex.EncodeToString(ph[:])
	sh := sha256.Sum256(ph[:])
	stmt := "0x" + hex.EncodeToString(sh[:])
	secrets := map[string]string{"good": pre, "bad": "0x" + strings.Repeat("00", 32), "short": "0x" + pre[2:40],
		"upper": "0x" + strings.ToUpper(pre[2:])}
	out := map[string][]bool{}
	for _, s := range scen {
		var now int64
		r := New(func() int64 { return now })
		tm := LockTerms{Contract: stmt, Lock: "hash", Statement: stmt, Amount: "1000", Asset: "FLOP",
			Payer: "did:key:payer", Payee: "did:key:payee", ClaimByMs: 500, RefundAfterMs: 1000}
		var res []bool
		for _, st := range s.Steps {
			now = st.At
			switch st.Op {
			case "lock":
				_, err := r.Lock(tm)
				res = append(res, err == nil)
			case "verify":
				t2 := tm
				if st.Mut {
					t2.Amount = "999"
				}
				res = append(res, r.VerifyLock(t2, stmt))
			case "claim":
				res = append(res, r.Claim(stmt, secrets[st.Secret]) == nil)
			case "refund":
				res = append(res, r.Refund(stmt) == nil)
			}
		}
		out[s.Name] = res
	}
	return out
}

func loadScenarios(t *testing.T) []scenario {
	b, err := os.ReadFile("../tests/rail_scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	var s []scenario
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// Pinned expectations (also what tclk's MemoryRail returned on 2026-11-17, commit 7d402db).
func TestScenariosPinned(t *testing.T) {
	got := runGo(t, loadScenarios(t))
	want := map[string][]bool{
		"happy":                             {true, true, true, false, false},
		"wrong-preimage":                    {true, false, false, true},
		"uppercase-hex-preimage":            {true, true},
		"refund-timing":                     {true, false, false, true, false},
		"late-lock":                         {false, true, false},
		"verify-mutated":                    {true, false},
		"claim-after-claimby-before-refund": {true, true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

// Cross-checks against tclk's real MemoryRail when TCLK_DIST points at tclk's dist/index.js.
func TestConformanceWithTclkMemoryRail(t *testing.T) {
	dist := os.Getenv("TCLK_DIST")
	if dist == "" {
		t.Skip("set TCLK_DIST=/path/to/tclk/dist/index.js to cross-check against tclk")
	}
	b, err := exec.Command("node", "../tests/tclk_conformance.mjs", dist).Output()
	if err != nil {
		t.Fatal(err)
	}
	var ts map[string][]bool
	if err := json.Unmarshal(b, &ts); err != nil {
		t.Fatal(err)
	}
	if got := runGo(t, loadScenarios(t)); !reflect.DeepEqual(got, ts) {
		t.Fatalf("simtclk diverges from tclk MemoryRail:\n go: %v\n ts: %v", got, ts)
	}
}
