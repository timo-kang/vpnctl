//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This test requires:
// - Linux
// - root (netns + link creation)
// - iproute2 (`ip`)
// - WireGuard tools (`wg`)
//
// It is gated behind -tags=integration and VPNCTL_INTEGRATION=1 to avoid
// accidental local network disruption.
func TestNetns_DirectInjection(t *testing.T) {
	if os.Getenv("VPNCTL_INTEGRATION") != "1" {
		t.Skip("set VPNCTL_INTEGRATION=1 to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("missing ip")
	}
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("missing wg")
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "vpnctl")
	run(t, ".", "go", "build", "-o", bin, "./cmd/vpnctl")

	// Namespaces and bridge (in root ns).
	suffix := fmt.Sprintf("%d", os.Getpid())
	nsCtrl := "vpnctl-ctrl-" + suffix
	nsA := "vpnctl-a-" + suffix
	nsB := "vpnctl-b-" + suffix
	br := "vpnctl-br0-" + suffix
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", nsA).Run()
		_ = exec.Command("ip", "netns", "del", nsB).Run()
		_ = exec.Command("ip", "netns", "del", nsCtrl).Run()
		_ = exec.Command("ip", "link", "del", br).Run()
	})

	run(t, ".", "ip", "netns", "add", nsCtrl)
	run(t, ".", "ip", "netns", "add", nsA)
	run(t, ".", "ip", "netns", "add", nsB)
	run(t, ".", "ip", "link", "add", br, "type", "bridge")
	run(t, ".", "ip", "link", "set", br, "up")

	// Connect each netns to the bridge.
	connect := func(ns, ifNs, ifBr, ipCIDR string) {
		run(t, ".", "ip", "link", "add", ifBr, "type", "veth", "peer", "name", ifNs)
		run(t, ".", "ip", "link", "set", ifNs, "netns", ns)
		run(t, ".", "ip", "link", "set", ifBr, "master", br)
		run(t, ".", "ip", "link", "set", ifBr, "up")
		run(t, ".", "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
		run(t, ".", "ip", "netns", "exec", ns, "ip", "addr", "add", ipCIDR, "dev", ifNs)
		run(t, ".", "ip", "netns", "exec", ns, "ip", "link", "set", ifNs, "up")
	}
	connect(nsCtrl, "eth0", "veth-ctrl-"+suffix, "192.168.100.1/24")
	connect(nsA, "eth0", "veth-a-"+suffix, "192.168.100.2/24")
	connect(nsB, "eth0", "veth-b-"+suffix, "192.168.100.3/24")

	// Generate keys.
	ctrlPriv, ctrlPub := wgKeyPair(t)
	aPriv, aPub := wgKeyPair(t)
	bPriv, bPub := wgKeyPair(t)

	ctrlCfg := fmt.Sprintf(`controller:
  listen: "0.0.0.0:8080"
  data_dir: %q
  vpn_cidr: "10.7.0.0/24"
  wg_apply: true
  wg_interface: "wg0"
  wg_port: 51820
  mtu: 1280
  wg_address: "10.7.0.1/24"
  wg_private_key: %q
  server_public_key: %q
  server_endpoint: "192.168.100.1:51820"
  server_allowed_ips: ["10.7.0.0/24"]
  server_keepalive_sec: 25
`, filepath.Join(tmp, "ctrl-state"), ctrlPriv, ctrlPub)
	ctrlPath := filepath.Join(tmp, "ctrl.yaml")
	mustWrite(t, ctrlPath, ctrlCfg)

	nodeTemplate := func(name, priv, pub, vpnIP string) string {
		return fmt.Sprintf(`node:
  name: %q
  controller: "192.168.100.1:8080"
  wg_interface: "wg0"
  wg_config_path: %q
  wg_private_key: %q
  wg_public_key: %q
  wg_listen_port: 51820
  probe_port: 51900
  vpn_ip: %q
  mtu: 1280
  direct_mode: "auto"
  keepalive_interval_sec: 1
  candidates_interval_sec: 1
  direct_interval_sec: 1
`, name, filepath.Join(tmp, name+"-wg.conf"), priv, pub, vpnIP)
	}
	aPath := filepath.Join(tmp, "a.yaml")
	bPath := filepath.Join(tmp, "b.yaml")
	mustWrite(t, aPath, nodeTemplate("node-a", aPriv, aPub, "10.7.0.2/32"))
	mustWrite(t, bPath, nodeTemplate("node-b", bPriv, bPub, "10.7.0.12/32"))

	// Start controller.
	ctrlCmd := exec.Command("ip", "netns", "exec", nsCtrl, bin, "controller", "init", "--config", ctrlPath)
	ctrlCmd.Stdout = os.Stdout
	ctrlCmd.Stderr = os.Stderr
	if err := ctrlCmd.Start(); err != nil {
		t.Fatalf("start controller: %v", err)
	}
	t.Cleanup(func() { _ = ctrlCmd.Process.Kill() })

	// Start nodes (serve: sync-config -> up -> run loop).
	aCmd := exec.Command("ip", "netns", "exec", nsA, bin, "node", "serve", "--config", aPath, "--retry-delay", "200ms", "--retry-max-delay", "1s")
	aCmd.Stdout = os.Stdout
	aCmd.Stderr = os.Stderr
	if err := aCmd.Start(); err != nil {
		t.Fatalf("start node-a: %v", err)
	}
	t.Cleanup(func() { _ = aCmd.Process.Kill() })

	bCmd := exec.Command("ip", "netns", "exec", nsB, bin, "node", "serve", "--config", bPath, "--retry-delay", "200ms", "--retry-max-delay", "1s")
	bCmd.Stdout = os.Stdout
	bCmd.Stderr = os.Stderr
	if err := bCmd.Start(); err != nil {
		t.Fatalf("start node-b: %v", err)
	}
	t.Cleanup(func() { _ = bCmd.Process.Kill() })

	// Wait until node-a has injected node-b as a direct WG peer.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("ip", "netns", "exec", nsA, "wg", "show", "wg0").CombinedOutput()
		if bytes.Contains(out, []byte(bPub)) {
			// Confirm endpoint is node-b underlay (not controller).
			if bytes.Contains(out, []byte("192.168.100.3:51820")) {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	out, _ := exec.Command("ip", "netns", "exec", nsA, "wg", "show", "wg0").CombinedOutput()
	t.Fatalf("direct peer injection not observed on node-a\n%s", string(out))
}

func wgKeyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	priv = strings.TrimSpace(string(runOut(t, ".", "wg", "genkey")))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wg pubkey: %v: %s", err, string(out))
	}
	pub = strings.TrimSpace(string(out))
	return priv, pub
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, string(out))
	}
}

func runOut(t *testing.T, dir, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, string(out))
	}
	return out
}

func init() {
	// Prevent `go test` from running this package without context cancellation when executing
	// long-running `node serve` processes, even though we hard-kill via Cleanup.
	_ = context.Background()
}
