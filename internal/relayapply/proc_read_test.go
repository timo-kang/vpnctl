// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"vpnctl/internal/relayobserve"
)

// This only reads the current namespace. No sysctl or network mutation occurs.
func TestRPFilterReadDoesNotSpawnCat(t *testing.T) {
	const path = "/proc/sys/net/ipv4/conf/all/rp_filter"
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	ctx, recorder := relayobserve.Start(context.Background())
	got, err := command(ctx, "", "cat", path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("fresh native read: %q, %v", got, err)
	}
	for _, phase := range recorder.Snapshot().Phases {
		if phase.KernelCommands != 0 || phase.InventoryCommands != 0 {
			t.Fatal("native read counted as a child process", phase)
		}
	}
}

func TestRPFilterNativeReadBoundary(t *testing.T) {
	for _, name := range []string{"all", "default", "vr012345abcdef", "a-b.c_d"} {
		if !rpFilterPath("/proc/sys/net/ipv4/conf/" + name + "/rp_filter") {
			t.Fatal("safe interface rejected", name)
		}
	}
	for _, path := range []string{"/etc/passwd", "/proc/sys/net/ipv4/conf/all/forwarding", "/proc/sys/net/ipv4/conf/../rp_filter", "/proc/sys/net/ipv4/conf/./rp_filter", "/proc/sys/net/ipv4/conf//rp_filter", "/proc/sys/net/ipv4/conf/all/../default/rp_filter", "/proc/sys/net/ipv4/conf/0123456789abcdef/rp_filter", "/proc/sys/net/ipv4/conf/a\x00b/rp_filter"} {
		if rpFilterPath(path) {
			t.Fatal("unsupported path admitted", path)
		}
	}
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{{"/etc/passwd"}, {"/proc/sys/net/ipv4/conf/all/rp_filter", "extra"}} {
		if _, err := command(context.Background(), "", "cat", args...); err == nil {
			t.Fatal("unrelated cat call took native path")
		}
	}
	if _, err := command(context.Background(), "input", "cat", "/proc/sys/net/ipv4/conf/all/rp_filter"); err == nil {
		t.Fatal("input-bearing call took native path")
	}
}

func TestProcSettingFreshAndBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setting")
	for _, value := range []string{"0\n", "2\n", "malformed\n", strings.Repeat("x", 32)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readProcSetting(context.Background(), path)
		if err != nil || string(got) != value {
			t.Fatal("value was cached or transformed", string(got), err)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 33)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProcSetting(context.Background(), path); err == nil {
		t.Fatal("oversized read accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{link, fifo, dir, filepath.Join(dir, "absent")} {
		if _, err := readProcSetting(context.Background(), unsafe); err == nil {
			t.Fatal("unsafe file accepted", unsafe)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readProcSetting(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read attempted", err)
	}
}
