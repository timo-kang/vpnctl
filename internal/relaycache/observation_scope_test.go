// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObservationScopeReopenDoesNotRetainLocks(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "cache")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	initial, err := Open(dir, Options{NodeID: "robot", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	initial.Close()
	old, err := OpenQueued(ctx, dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	pin, err := old.PinObservationScope()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if pin.Matches(old) {
		t.Fatal("closed cache matched")
	}
	fresh, err := OpenQueued(ctx, dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal("identity pin retained cache/FIFO ownership", err)
	}
	defer fresh.Close()
	if !pin.Matches(fresh) {
		t.Fatal("same reopened scope did not match")
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if pin.Matches(fresh) {
		t.Fatal("closed pin remained usable")
	}
}

func TestObservationScopeRejectsReplacedDirectoryOrLock(t *testing.T) {
	for _, mode := range []string{"directory", "lock", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, "cache")
			old, err := Open(dir, Options{NodeID: "robot", Create: true})
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			pin, err := old.PinObservationScope()
			if err != nil {
				t.Fatal(err)
			}
			defer pin.Close()
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "directory":
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Remove(filepath.Join(dir, "cache.lock")); err != nil {
					t.Fatal(err)
				}
			}
			fresh, err := Open(dir, Options{NodeID: "robot", Create: true})
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if mode == "uncertain" {
				fresh.uncertain = true
			}
			if pin.Matches(fresh) {
				t.Fatal("changed scope matched")
			}
		})
	}
	if (&ObservationScope{}).Matches(nil) {
		t.Fatal("empty scope matched")
	}
}

func TestObservationScopeRejectsLiveLockNameReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old, err := Open(dir, Options{NodeID: "robot", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	pin, err := old.PinObservationScope()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if pin.Matches(old) {
		t.Fatal("original cache lifetime matched")
	}
	old.Close()
	fresh, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if !pin.Matches(fresh) {
		t.Fatal("reopened cache did not match")
	}
	if err := os.Rename(filepath.Join(dir, "cache.lock"), filepath.Join(dir, "old.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cache.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if pin.Matches(fresh) {
		t.Fatal("held inode matched despite replaced lock name")
	}
	if other, err := fresh.PinObservationScope(); err == nil {
		other.Close()
		t.Fatal("pinned a replaced lock name")
	}
}
