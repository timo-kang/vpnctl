//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
)

func TestNetns_M3PreparationENOSPCOptOut(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: true, independentRecipients: true, underlays: 4, extraTarget: true})
	f.releaseNodeCandidates()
	netOutput(t, f.robot, "sh", "-c", "mount -t proc proc /proc && printf 0 > /proc/sys/net/ipv4/conf/all/rp_filter && printf 0 > /proc/sys/net/ipv4/conf/default/rp_filter")
	for _, p := range f.plan.Paths {
		netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", p.PathID, "--app-routes")
	}
	enablePreparation(t, f, "p00")
	cfg, err := config.Load(f.node)
	if err != nil {
		t.Fatal(err)
	}
	cache := cfg.Node.RelayCacheDir
	if cache == "" {
		cache = filepath.Join(cfg.Node.PKIDir, "relay-cache")
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	backup := map[string][]byte{}
	defer func() {
		for _, b := range backup {
			clear(b)
		}
	}()
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(cache, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		backup[entry.Name()] = b
	}
	// Removing the one-page consent file must not free enough space to rewrite
	// this real eight-candidate journal; exercise failure AFTER durable opt-out.
	if len(backup["apply.json"]) <= 8192 {
		t.Fatal("fixture journal too small for ENOSPC boundary")
	}
	if b, err := exec.Command("mount", "-t", "tmpfs", "-o", "size=1m,mode=0700", "tmpfs", cache).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	t.Cleanup(func() {
		if b, err := exec.Command("umount", "-l", cache).CombinedOutput(); err != nil {
			t.Error(err, string(b))
		}
	})
	for name, b := range backup {
		if err := os.WriteFile(filepath.Join(cache, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Admit the real engine before exhausting storage. Filling before CLI
	// admission only tests its earlier cache-open write, not durable opt-out.
	marker := filepath.Join(f.private, "enospc-admitted")
	worker := startNetworkProcess(t, f.robot, filepath.Join(f.results, "preparation-enospc-release.jsonl"), []string{"VPNCTL_WORKER=preparation-enospc-release", "VPNCTL_ENOSPC_CONFIG=" + f.node, "VPNCTL_ENOSPC_MARKER=" + marker}, f.worker, "-test.run=^TestNetworkWorker$")
	eventually(t, 10*time.Second, "engine admitted before ENOSPC", func() error {
		_, err := os.Stat(marker)
		return err
	})
	before, err := os.ReadFile(filepath.Join(cache, "apply.json"))
	if err != nil {
		t.Fatal(err)
	}
	fill := filepath.Join(cache, "fill")
	file, err := os.Create(fill)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 512 && err == nil; n++ {
		_, err = file.Write(make([]byte, 4096))
	}
	file.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("ENOSPC not reached", err)
	}
	if err := os.WriteFile(marker+".continue", nil, 0600); err != nil {
		t.Fatal(err)
	}
	worker.finish(t)
	b, err := os.ReadFile(worker.log)
	if err != nil {
		t.Fatal(err)
	}
	var release struct {
		Result relayapply.Result `json:"result"`
		ENOSPC bool              `json:"enospc"`
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &release); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !release.ENOSPC || release.Result.Reason != "preparation_disabled_cleanup_pending" {
		t.Fatal("post-revocation journal failure missing", string(b))
	}
	after, err := os.ReadFile(filepath.Join(cache, "apply.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("expected older journal retained")
	}
	entries, err = os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "prepare-") {
			t.Fatal("consent remained after release", entry.Name())
		}
	}
	if err := os.Remove(fill); err != nil {
		t.Fatal(err)
	}
	startNodeLeaseWatch(t, f, "enospc-reopened")
	wg := f.plan.Paths[0].Pin.WGInterface
	eventually(t, 30*time.Second, "disabled candidate cleanup after ENOSPC", func() error {
		if strings.Contains(netOutput(t, f.robot, "ip", "-j", "link", "show"), wg) {
			return errors.New("owned cleanup pending")
		}
		return nil
	})
	// Repeated fresh authenticated supervision must not resurrect the old desire.
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if strings.Contains(netOutput(t, f.robot, "ip", "-j", "link", "show"), wg) {
			t.Fatal("old intent resurrected after ENOSPC")
		}
		time.Sleep(200 * time.Millisecond)
	}
	writeM3Report(t, filepath.Join(f.results, "preparation-enospc.json"), map[string]any{"completed": true, "real_enospc": true, "old_journal_retained": true, "consent_revoked_before_failed_rewrite": true, "fresh_supervision_cannot_resurrect": true})
}

// Worker runs production cache/namespace locking and Release, pausing only
// between admission and operation so the coordinator can fill a real tmpfs.
func runPreparationENOSPCRelease() error {
	cfg, err := config.Load(os.Getenv("VPNCTL_ENOSPC_CONFIG"))
	if err != nil {
		return err
	}
	dir := cfg.Node.RelayCacheDir
	if dir == "" {
		dir = filepath.Join(cfg.Node.PKIDir, "relay-cache")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cache, err := relaycache.OpenQueued(ctx, dir, relaycache.Options{NodeID: cfg.Node.Name})
	if err != nil {
		return err
	}
	defer cache.Close()
	engine, err := relayapply.Open(cache, cfg.Node.RelayUnderlays)
	if err != nil {
		return err
	}
	defer engine.Close()
	marker := os.Getenv("VPNCTL_ENOSPC_MARKER")
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(marker + ".continue"); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ENOSPC coordinator: %w", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	result, releaseErr := engine.Release(ctx, "p00")
	return json.NewEncoder(os.Stdout).Encode(struct {
		Result relayapply.Result `json:"result"`
		ENOSPC bool              `json:"enospc"`
	}{result, errors.Is(releaseErr, syscall.ENOSPC)})
}
