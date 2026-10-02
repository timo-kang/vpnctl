// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
)

func TestRelayCommandLockWaitSharesBudgetAndPreservesFailFast(t *testing.T) {
	busy := errors.New("busy")
	calls := 0
	open := func() (int, error) { calls++; return 0, busy }
	if _, err := openRelayCommandLock(context.Background(), false, open, busy); !errors.Is(err, busy) || calls != 1 {
		t.Fatal("default command no longer fails fast", calls, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	// Simulate obtaining the cache after consuming part of the shared budget.
	if _, err := openRelayCommandLock(ctx, true, func() (int, error) {
		if time.Since(start) < 100*time.Millisecond {
			return 0, busy
		}
		return 1, nil
	}, busy); err != nil {
		t.Fatal(err)
	}
	if _, err := openRelayCommandLock(ctx, true, open, busy); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, busy) || time.Since(start) > time.Second {
		t.Fatal("namespace wait lost shared deadline or busy classification", err)
	}
	calls = 0
	if _, err := openRelayCommandLock(ctx, true, open, busy); !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatal("expired wait opened resource", calls, err)
	}
	denied := errors.New("unsafe journal")
	calls = 0
	if _, err := openRelayCommandLock(context.Background(), true, func() (int, error) { calls++; return 0, denied }, busy); !errors.Is(err, denied) || calls != 1 {
		t.Fatal("retried non-contention failure", calls, err)
	}
	canceled, stop := context.WithCancel(context.Background())
	calls = 0
	if _, err := openRelayCommandLock(canceled, true, func() (int, error) { calls++; stop(); return 0, busy }, busy); !errors.Is(err, context.Canceled) || !errors.Is(err, busy) || calls != 1 {
		t.Fatal("cancelled waiter opened resources later", calls, err)
	}
}

// Exercise the real CLI flag/context wiring and a real cache flock. The held
// cache prevents all kernel access, so this test needs no network privileges.
func TestRelayPeerCommandBoundedWaitOnHeldCache(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "node.yaml")
	if err := os.WriteFile(cfg, []byte("node:\n  name: agent\n  pki_dir: "+root+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	holder, err := relaycache.OpenDeployment(cache, relaycache.DeploymentOptions{PrincipalID: "agent", RelayID: "r", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	args := []string{"inspect", "--config", cfg, "--relay-id", "r", "--cache-dir", cache}
	if err := runRelayPeerApply(args); !errors.Is(err, relaycache.ErrBusy) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("default lock rejection", err)
	}
	started := time.Now()
	err = runRelayPeerApply(append(args, "--lock-wait", "60ms", "--timeout", "100ms"))
	if !errors.Is(err, relaycache.ErrBusy) || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) < 50*time.Millisecond || time.Since(started) > time.Second {
		t.Fatal("CLI wait not bounded", time.Since(started), err)
	}
	for _, flags := range [][]string{{"--lock-wait", "-1s"}, {"--lock-wait", "6s"}, {"--lock-wait", "2s", "--timeout", "1s"}} {
		if err := runRelayPeerApply(append(args, flags...)); err == nil || errors.Is(err, relaycache.ErrBusy) {
			t.Fatal("invalid lock wait reached cache", flags, err)
		}
	}
}
