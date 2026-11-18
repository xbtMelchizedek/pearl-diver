// Package localkeys stores regtest-only keys outside the repo, in mode-600 files.
//
// Default directory: $PEARL_DIVER_HOME/keys, else ~/.pearl-diver/keys. Key material is
// never printed or logged; only public keys and DIDs are.
package localkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pearl-research-labs/pearl/node/btcec"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// Dir returns the key directory (created 0700 if missing).
func Dir() (string, error) {
	base := os.Getenv("PEARL_DIVER_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".pearl-diver")
	}
	d := filepath.Join(base, "keys")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, os.Chmod(d, 0o700)
}

func path(name, kind string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("keys: bad name %q", name)
	}
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name+"."+kind+".key"), nil
}

func loadOrCreate(name, kind string, size int) ([]byte, error) {
	p, err := path(name, kind)
	if err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(p); err == nil {
		st, _ := os.Stat(p)
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("keys: %s is group/world readable; refusing", p)
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(b) != size {
			return nil, fmt.Errorf("keys: %s is malformed", p)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(b) + "\n"); err != nil {
		return nil, err
	}
	return b, nil
}

// Secp returns (creating if needed) a regtest secp256k1 key named name.
func Secp(name string) (*btcec.PrivateKey, error) {
	b, err := loadOrCreate(name, "secp256k1", 32)
	if err != nil {
		return nil, err
	}
	k, _ := btcec.PrivKeyFromBytes(b)
	return k, nil
}

// Ed25519 returns (creating if needed) an Ed25519 key for signing agb1 receipts.
func Ed25519(name string) (ed25519.PrivateKey, error) {
	seed, err := loadOrCreate(name, "ed25519", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
