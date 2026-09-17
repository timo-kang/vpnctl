// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("VPNCTL_INTEGRATION") != "1" {
		t.Skip("set VPNCTL_INTEGRATION=1 in an isolated network environment")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("explicit integration run requires Linux root with network namespace capabilities")
	}
	for _, tool := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
}

func integrationBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("VPNCTL_BIN"); bin != "" {
		return bin
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "..", "..")
	bin := filepath.Join(t.TempDir(), "vpnctl")
	run(t, root, "go", "build", "-race", "-o", bin, "./cmd/vpnctl")
	return bin
}

// command output can include bootstrap secrets; only print diagnostics from
// commands that do not take secrets as arguments.
func netCommand(ctx context.Context, ns string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

func netOutput(t *testing.T, ns string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := netCommand(ctx, ns, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("namespace command %s: %v: %s", args[0], err, out)
	}
	return strings.TrimSpace(string(out))
}

type networkProcess struct {
	cmd     *exec.Cmd
	log     string
	stopped bool
}

func startNetworkProcess(t *testing.T, ns, log string, env []string, args ...string) *networkProcess {
	t.Helper()
	f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := netCommand(context.Background(), ns, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	p := &networkProcess{cmd: cmd, log: log}
	t.Cleanup(func() { p.stop() })
	return p
}

func (p *networkProcess) stop() {
	if p == nil || p.stopped {
		return
	}
	p.stopped = true
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

func (p *networkProcess) finish(t *testing.T) {
	t.Helper()
	if p.stopped {
		t.Fatal("network worker was stopped before reporting completion")
	}
	p.stopped = true
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			log, _ := os.ReadFile(p.log)
			t.Fatalf("network worker failed: %v: %s", err, log)
		}
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
		t.Fatal("network worker did not drain its pending probes")
	}
}

func eventually(t *testing.T, timeout time.Duration, what string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not converge within %s: %v", what, timeout, last)
}

func newNamespaces(t *testing.T, size int) []string {
	t.Helper()
	suffix := fmt.Sprintf("%x", time.Now().UnixNano()&0xffffff)
	bridge := "vb" + suffix
	var namespaces []string
	t.Cleanup(func() {
		for _, ns := range namespaces {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
		_ = exec.Command("ip", "link", "del", bridge).Run()
	})
	run(t, ".", "ip", "link", "add", bridge, "type", "bridge")
	run(t, ".", "ip", "link", "set", bridge, "up")
	for i := 0; i <= size; i++ {
		ns := fmt.Sprintf("vpnctl-%s-%d", suffix, i)
		run(t, ".", "ip", "netns", "add", ns)
		namespaces = append(namespaces, ns)
		veth := fmt.Sprintf("v%s%x", suffix, i) // Linux IFNAMSIZ: at most 15 bytes.
		run(t, ".", "ip", "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", ns)
		run(t, ".", "ip", "link", "set", veth, "master", bridge)
		run(t, ".", "ip", "link", "set", veth, "up")
		netOutput(t, ns, "ip", "link", "set", "lo", "up")
		netOutput(t, ns, "ip", "address", "add", fmt.Sprintf("192.0.2.%d/24", i+1), "dev", "eth0")
		netOutput(t, ns, "ip", "link", "set", "eth0", "up")
	}
	return namespaces
}

func (p *networkProcess) terminate(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	p.finishWithin(t, 12*time.Second)
}

func (p *networkProcess) finishWithin(t *testing.T, timeout time.Duration) {
	t.Helper()
	if p.stopped {
		t.Fatal("process already stopped")
	}
	p.stopped = true
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process failed: %v (log: %s)", err, p.log)
		}
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-done
		t.Fatal("process did not exit within", timeout)
	}
}
