// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
)

// Re-exec the race-instrumented test binary through the production CLI entrypoint.
func TestControllerCLIProcess(t *testing.T) {
	if os.Getenv("VPNCTL_CLI_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"vpnctl"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func cliProcess(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary, append([]string{"-test.run=^TestControllerCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "VPNCTL_CLI_TEST_PROCESS=1", "GORACE=atexit_sleep_ms=0")
	return cmd
}

func TestAdminCLIProcessesAndCrashRestart(t *testing.T) {
	// Keep Unix socket paths short even with verbose Go test names.
	dir, err := os.MkdirTemp("", "vpnctl-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := filepath.Join(dir, "controller.yaml")
	body := fmt.Sprintf("controller:\n  listen: 127.0.0.1:0\n  data_dir: %q\n  vpn_cidr: 10.7.0.0/24\n  wg_address: 10.7.0.1/24\n  probe_port: -1\n  pki: {}\n", dir)
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(dir, "registry.yaml")
	if err := store.SaveRegistry(regPath, &store.Registry{Nodes: []store.NodeInfo{{ID: "a", Name: "a", VPNIP: "10.7.0.2/32", PubKey: "pub-a"}}}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := cliProcess(t, append([]string{"controller"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("CLI failed: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	start := func() func() {
		t.Helper()
		cmd := cliProcess(t, "controller", "init", "--config", cfg)
		log, err := os.CreateTemp(dir, "controller-log-")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		var once sync.Once
		stop := func() { once.Do(func() { _ = cmd.Process.Kill(); <-exited; log.Close() }) }
		t.Cleanup(stop)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.list"}); err == nil {
				return stop
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("controller admin IPC did not start")
		return stop
	}
	stop := start()
	if out, err := cliProcess(t, "controller", "init", "--config", cfg).CombinedOutput(); err == nil || !bytes.Contains(out, []byte("already owns data_dir")) {
		t.Fatalf("second owner: %v: %s", err, out)
	}
	token := run("token", "create", "--config", cfg, "--ttl", "2h", "--single-use")
	var records []pki.TokenRecord
	if err := json.Unmarshal([]byte(run("token", "list", "--json", "--config", cfg)), &records); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range records {
		if r.Token == token {
			found = r.SingleUse && r.ExpiresAt.Sub(r.CreatedAt) == 2*time.Hour
		}
	}
	if !found {
		t.Fatal("CLI lost token policy")
	}
	run("token", "revoke", token, "--config", cfg) // documented token-first order
	other := run("token", "create", "--config", cfg)
	run("token", "revoke", "--config", cfg, other) // flags-first order
	run("remove-node", "--config", cfg, "--name", "a")
	for _, r := range records {
		run("token", "revoke", r.Token, "--config", cfg)
	}
	before, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	stop() // SIGKILL leaves the socket on disk; flock must release automatically.
	if _, err := cliProcess(t, "controller", "token", "create", "--config", cfg).CombinedOutput(); err == nil {
		t.Fatal("offline CLI succeeded")
	}
	after, err := os.ReadFile(regPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("offline CLI changed registry")
	}
	stop = start()
	if active := run("token", "list", "--config", cfg); active != "no active tokens" {
		t.Fatal("restart created or resurrected a token")
	}
	run("remove-node", "--config", cfg, "--name", "a") // idempotent across restart
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Nodes) != 0 || len(reg.RemovedNodes) != 1 {
		t.Fatal("restart lost removal")
	}
	stop()
}
