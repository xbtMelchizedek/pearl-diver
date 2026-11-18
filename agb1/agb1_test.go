package agb1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestCanonicalMatchesPythonRules(t *testing.T) {
	got, err := Canonical(map[string]any{"b": "é/\"\n", "a": []any{int64(1), true, nil}, "c": "🙂"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[1,true,null],"b":"\u00e9/\"\n","c":"\ud83d\ude42"}`
	if got != want {
		t.Fatalf("got %s", got)
	}
	if _, err := Canonical(map[string]any{"x": int64(1) << 53}); err == nil {
		t.Fatal("unsafe int accepted")
	}
	if _, err := Canonical(map[string]any{"x": 1.5}); err == nil {
		t.Fatal("float accepted")
	}
}

func TestDIDPrefix(t *testing.T) {
	seed := sha256.Sum256([]byte("x"))
	d := DID(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
	if !strings.HasPrefix(d, "did:key:z6Mk") {
		t.Fatal(d)
	}
}

func TestBuildSignsCid(t *testing.T) {
	seed := sha256.Sum256([]byte("y"))
	s := Signer{ed25519.NewKeyFromSeed(seed[:])}
	m, err := s.Build("note", "app/pearl-diver/regtest", map[string]any{"text": "hi"}, Opts{TsMs: 1, Nonce: "0011223344556677"})
	if err != nil || !strings.HasPrefix(m.Line, "agb1 {") || !strings.HasPrefix(m.CID, "0x") {
		t.Fatal(m, err)
	}
}
