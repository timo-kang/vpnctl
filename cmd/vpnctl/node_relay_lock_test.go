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

func TestNodeCommandsRespectHeldCacheAndOverallDeadline(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.yaml")
	if err := os.WriteFile(path, []byte("node:\n  name: robot\n  pki_dir: "+dir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cache, err := relaycache.Open(filepath.Join(dir, "cache"), relaycache.Options{NodeID: "robot", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	for _, target := range []bool{false, true} {
		args := []string{"inspect", "--config", path, "--cache-dir", filepath.Join(dir, "cache"), "--timeout", "80ms"}
		start := time.Now()
		if target {
			args = append(args, "--target-id", "app")
			err = runNodeRelayTarget(args)
		} else {
			err = runNodeRelayApply(args)
		}
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) < 60*time.Millisecond || time.Since(start) > time.Second {
			t.Fatal("unbounded or fail-fast admission", err, time.Since(start))
		}
	}
}
