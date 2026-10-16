// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vpnctl/internal/controller"
	"vpnctl/internal/history"
	"vpnctl/internal/wgstats"
)

func TestStoppedMonitorHistorySnapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Microsecond)
	path := filepath.Join(dir, "history.db")
	store, err := history.Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	yes, no, rtt := true, false, 1.0
	observation := history.Observation{ID: "success", Timestamp: now, Source: "monitor-overlay", PeerID: "node-1", Path: "unknown", Success: &yes, RTTMs: &rtt}
	put := func(node string, o history.Observation) {
		t.Helper()
		if err := store.Ingest(ctx, node, []history.Observation{o}, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	put("node-0", observation)
	put("node-2", observation) // another reporter must not enter this baseline
	other := observation
	other.Source = "cli-ping"
	put("node-0", other)
	other = observation
	other.ID, other.Timestamp = "lower-exclusive", now.Add(-time.Hour)
	put("node-0", other)
	other.ID, other.Timestamp = "future", now.Add(time.Microsecond)
	put("node-0", other)
	other = observation
	other.ID, other.Success, other.RTTMs = "failure", &no, nil
	put("node-0", other)
	other.ID, other.Success, other.Validity, other.Reason = "unknown", nil, "unknown", "collector_unavailable"
	put("node-0", other)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	report := wgstats.Report{ID: wgstats.ID(), ObservedAt: now, Interface: "wg0", Reporter: wgstats.Binding{NodeID: "node-0", PublicKey: key, VPNIP: "10.77.0.2", Epoch: "00000000000000000000000000000001"}}
	want := monitorHistorySnapshot{Attempts: 2, Successes: 1, Unknown: 1, WGIDs: []string{report.ID}}
	for _, at := range []time.Time{now.Add(-time.Hour), now, now.Add(time.Microsecond)} {
		r := report
		r.ObservedAt = at
		if !at.Equal(now) {
			r.ID = wgstats.ID()
		}
		if err := store.IngestWireGuard(ctx, r, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	report.ID, report.Reporter.NodeID = wgstats.ID(), "node-2"
	if err := store.IngestWireGuard(ctx, report, now); err != nil {
		t.Fatal(err)
	}

	lock, err := controller.AcquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err = readStoppedMonitorHistory(ctx, dir, now); err == nil {
		t.Fatal("accepted a baseline while controller still owns state")
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := readStoppedMonitorHistory(ctx, dir, now)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("drained snapshot", got, want, err)
	}
	// Cross-check the fixture's raw SQL against the production query semantics.
	buckets, err := store.Query(ctx, "node-0", now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	apiCounts := monitorHistorySnapshot{WGIDs: want.WGIDs}
	for _, b := range buckets {
		if b.Source == "monitor-overlay" {
			apiCounts.Attempts += b.Count
			apiCounts.Successes += b.Successes
			apiCounts.Unknown += b.UnknownCount
		}
	}
	if !reflect.DeepEqual(got, apiCounts) {
		t.Fatal("snapshot disagrees with history query", got, apiCounts)
	}
	// The reader neither expires old rows nor deletes future rows. Moving the
	// same query window proves both remained in the actual source database.
	later, err := readStoppedMonitorHistory(ctx, dir, now.Add(time.Microsecond))
	if err != nil || later.Attempts != 3 || len(later.WGIDs) != 2 {
		t.Fatal("reader changed source records", later, err)
	}
	earlier, err := readStoppedMonitorHistory(ctx, dir, now.Add(-time.Hour))
	if err != nil || earlier.Attempts != 1 || len(earlier.WGIDs) != 1 {
		t.Fatal("reader expired source records", earlier, err)
	}
	other = observation
	other.ID, other.PeerID = "unexpected-peer", "node-9"
	put("node-0", other)
	if _, err := readStoppedMonitorHistory(ctx, dir, now); err == nil {
		t.Fatal("silently filtered an unexpected monitor route")
	}
}

func TestStoppedMonitorHistoryDoesNotCreateMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	if _, err := readStoppedMonitorHistory(context.Background(), dir, time.Now()); err == nil {
		t.Fatal("accepted missing history")
	}
	if _, err := os.Stat(filepath.Join(dir, "history.db")); !os.IsNotExist(err) {
		t.Fatal("reader created a database", err)
	}
}
