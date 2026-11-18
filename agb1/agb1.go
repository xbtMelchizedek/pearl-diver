// Package agb1 emits signed agentwork (agb1) messages, byte-compatible with
// github.com/xbtMelchizedek/agentwork SPEC §1–4:
//
//	cid = "0x" + hex(sha256("FLOP::agb::v1|" + canonical(envelope minus cid, sig)))
//	sig = base64url_nopad(Ed25519(key, "agb1-sig|" + cid))
//
// canonical = sorted keys, "," ":" separators, ASCII-only (Python json.dumps
// ensure_ascii=True escaping), integers only.
package agb1

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	Prefix    = "agb1 "
	domain    = "FLOP::agb::v1|"
	sigDomain = "agb1-sig|"
	maxSafe   = 1<<53 - 1
)

// Canonical encodes v (map[string]any, []any, string, int, int64, bool, nil).
func Canonical(v any) (string, error) {
	var b strings.Builder
	if err := enc(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func encStr(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e:
			if r > 0xffff {
				a, c := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, a, c)
			} else {
				fmt.Fprintf(b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func enc(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		encStr(b, x)
	case int:
		return enc(b, int64(x))
	case int64:
		if x > maxSafe || x < -maxSafe {
			return errors.New("agb1: integer outside ±2^53-1")
		}
		b.WriteString(strconv.FormatInt(x, 10))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := enc(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return enc(b, a)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // keys are ASCII ([A-Za-z_][A-Za-z0-9_]*), so byte order == code-unit order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encStr(b, k)
			b.WriteByte(':')
			if err := enc(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("agb1: unsupported type %T", v)
	}
	return nil
}

var b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(in []byte) string {
	n := new(big.Int).SetBytes(in)
	var out []byte
	m, z := big.NewInt(58), new(big.Int)
	for n.Cmp(z) > 0 {
		r := new(big.Int)
		n.DivMod(n, m, r)
		out = append(out, b58[r.Int64()])
	}
	for _, c := range in {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// DID returns did:key:z6Mk… for an Ed25519 public key (multicodec 0xed01).
func DID(pub ed25519.PublicKey) string {
	return "did:key:z" + base58(append([]byte{0xed, 0x01}, pub...))
}

// Signer signs messages.
type Signer struct{ Key ed25519.PrivateKey }

func (s Signer) DID() string { return DID(s.Key.Public().(ed25519.PublicKey)) }

// Msg is a built, signed envelope.
type Msg struct {
	Env  map[string]any
	CID  string
	Line string
}

// Opts holds optional envelope fields.
type Opts struct {
	Ref   string
	K     []string
	TsMs  int64
	Nonce string
}

// Build creates and signs an envelope. Nothing is sent anywhere.
func (s Signer) Build(t, room string, body map[string]any, o Opts) (Msg, error) {
	n := o.Nonce
	if n == "" {
		var nb [8]byte
		_, _ = rand.Read(nb[:])
		n = hex.EncodeToString(nb[:])
	}
	env := map[string]any{"t": t, "s": "agb." + t + "/1", "from": s.DID(), "ts": o.TsMs, "n": n, "room": room, "b": body}
	if o.Ref != "" {
		env["ref"] = o.Ref
	}
	if len(o.K) > 0 {
		env["k"] = o.K
	}
	core, err := Canonical(env)
	if err != nil {
		return Msg{}, err
	}
	sum := sha256.Sum256([]byte(domain + core))
	cid := "0x" + hex.EncodeToString(sum[:])
	env["cid"] = cid
	env["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.Key, []byte(sigDomain+cid)))
	line, err := Canonical(env)
	if err != nil {
		return Msg{}, err
	}
	if len(Prefix)+len(line) > 4096 {
		return Msg{}, errors.New("agb1: wire form exceeds 4096 chars")
	}
	return Msg{Env: env, CID: cid, Line: Prefix + line}, nil
}
