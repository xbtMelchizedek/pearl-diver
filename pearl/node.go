package pearl

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pearl-research-labs/pearl/node/chaincfg"
)

// Node is a throwaway local pearld (regtest or simnet) in its own data dir.
// RPC credentials are random per node and never printed.
type Node struct {
	Cmd    *exec.Cmd
	Dir    string
	Config Config
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NetByName maps "regtest"/"simnet" to params; anything else is refused.
func NetByName(name string) (*chaincfg.Params, error) {
	switch name {
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "simnet":
		return &chaincfg.SimNetParams, nil
	}
	return nil, fmt.Errorf("pearl-diver: network %q refused; use regtest or simnet", name)
}

// StartNode launches pearld bound to 127.0.0.1 with no P2P listener and no DNS seeds.
// --rejectnonstd gives mainnet mempool policy (regtest/simnet relay non-standard txs by
// default, which admits not-yet-final timelocked spends to the mempool).
func StartNode(bin string, net *chaincfg.Params, miningAddr, dir string) (*Node, error) {
	return StartNodeWith(bin, net, miningAddr, dir, true)
}

// StartNodeWith lets tests run the network's default (permissive) mempool policy.
func StartNodeWith(bin string, net *chaincfg.Params, miningAddr, dir string, strict bool) (*Node, error) {
	if err := LocalOnly(net); err != nil {
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	cfg := Config{Host: fmt.Sprintf("127.0.0.1:%d", port), User: randHex(8), Pass: randHex(16), Net: net}
	conf := filepath.Join(dir, "pearld.conf")
	if err := os.WriteFile(conf, []byte("rpcuser="+cfg.User+"\nrpcpass="+cfg.Pass+"\n"), 0o600); err != nil {
		return nil, err
	}
	args := []string{"--" + net.Name, "--configfile=" + conf, "--datadir=" + filepath.Join(dir, "data"),
		"--logdir=" + filepath.Join(dir, "log"), "--rpclisten=" + cfg.Host, "--notls", "--nolisten",
		"--nodnsseed", "--txindex", "--miningaddr=" + miningAddr}
	if strict {
		args = append(args, "--rejectnonstd")
	}
	cmd := exec.Command(bin, args...)
	logf, err := os.Create(filepath.Join(dir, "stdout.log"))
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	n := &Node{Cmd: cmd, Dir: dir, Config: cfg}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := Dial(cfg); err == nil {
			if _, err := c.Tip(); err == nil {
				c.Close()
				return n, nil
			}
			c.Close()
		}
		time.Sleep(300 * time.Millisecond)
	}
	n.Stop()
	return nil, errors.New("pearl-diver: pearld did not come up (see " + filepath.Join(dir, "stdout.log") + ")")
}

// Stop kills the node.
func (n *Node) Stop() {
	if n.Cmd != nil && n.Cmd.Process != nil {
		_ = n.Cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = n.Cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = n.Cmd.Process.Kill()
		}
	}
}
