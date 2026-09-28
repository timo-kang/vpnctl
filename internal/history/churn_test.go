// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func fullArchivedPaths(t *testing.T, otherNodes ...string) (*Store, time.Time, []Observation) {
	t.Helper()
	s, now := newStore(t)
	now = now.Truncate(time.Hour)
	ctx := context.Background()
	old := now.Add(-24 * time.Hour)
	if err := s.EnableTiering(ctx, old); err != nil {
		t.Fatal(err)
	}
	var batch []Observation
	for peer := 0; peer < 32; peer++ {
		for _, source := range []string{"agent-direct", "monitor-overlay"} {
			for generation := 0; generation < 4; generation++ {
				batch = append(batch, Observation{ID: "old", Source: source, Timestamp: old,
					PeerID: fmt.Sprintf("peer-%02d", peer), Path: "direct",
					Uplink: fmt.Sprintf("uplink-%d", generation), Success: pointer(true), RTTMs: pointer(1.)})
			}
		}
	}
	ingest(t, s, "robot", batch, old)
	for _, node := range otherNodes {
		ingest(t, s, node, batch, old)
	}
	if err := s.Maintain(ctx, now); err != nil {
		t.Fatal(err)
	}
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.RawRows != 0 || stats.RollupRows != int64(len(batch)*(len(otherNodes)+1)) {
		t.Fatal("fixture did not archive all old streams", stats, err)
	}
	return s, now, batch
}

func TestPathChurnGlobalQuotaAndOwnQuotaIsolation(t *testing.T) {
	t.Run("global", func(t *testing.T) {
		var others []string
		for i := 0; i < 31; i++ {
			others = append(others, fmt.Sprintf("old-node-%02d", i))
		}
		s, now, old := fullArchivedPaths(t, others...)
		ctx := context.Background()
		if err := s.EnableReclamation(ctx); err != nil {
			t.Fatal(err)
		}
		o := old[0]
		o.ID, o.Timestamp = "new-node", now
		ingest(t, s, "new-node", []Observation{o}, now)
		stats, err := s.TieredStats(ctx)
		if err != nil || stats.ReclaimedStreams != 1 || stats.RawRows != 1 || stats.RollupRows != TieredMaxStreams-1 {
			t.Fatal(stats, err)
		}
		for _, node := range []string{"robot", "new-node"} {
			p, err := s.QueryPage(ctx, PageRequest{Node: node, End: now, Window: 48 * time.Hour, Width: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if node == "robot" {
				want = 1
			}
			if p.Coverage.DiscardedSamples != want {
				t.Fatal("loss owner changed", node, p.Coverage)
			}
		}
		if err := Check(ctx, s.path); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("own_recent_paths", func(t *testing.T) {
		s, now, batch := fullArchivedPaths(t, "other")
		ctx := context.Background()
		if err := s.EnableReclamation(ctx); err != nil {
			t.Fatal(err)
		}
		for i := range batch {
			batch[i].ID, batch[i].Timestamp = "active", now
		}
		ingest(t, s, "robot", batch, now)
		extra := batch[0]
		extra.ID, extra.Uplink = "new", "new-path"
		assertProbeQuota(t, s.Ingest(ctx, "robot", []Observation{extra}, now), "node_streams", TieredMaxNodeStreams)
		stats, err := s.TieredStats(ctx)
		if err != nil || stats.ReclaimedStreams != 0 || stats.RollupRows != 512 {
			t.Fatal("own quota discarded another reporter's history", stats, err)
		}
	})
}

func TestPathChurnWorkBudgetIsAtomic(t *testing.T) {
	s, now := newStore(t)
	now = now.Truncate(time.Hour)
	ctx := context.Background()
	// Add seven earlier hours to each archived stream using real ingestion on a
	// fresh store; all 2,048 raw samples pass through the production compactor.
	if err := s.EnableTiering(ctx, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for hour := 0; hour < 8; hour++ {
		var batch []Observation
		for stream := 0; stream < 256; stream++ {
			batch = append(batch, Observation{ID: fmt.Sprint(hour), Timestamp: now.Add(time.Duration(hour-24) * time.Hour), PeerID: "peer", Path: "direct", Uplink: fmt.Sprint(stream), Success: pointer(true), RTTMs: pointer(1.)})
		}
		ingest(t, s, "robot", batch, now)
	}
	if err := s.Maintain(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	var batch []Observation
	for i := 0; i < 129; i++ {
		batch = append(batch, Observation{ID: "new", Timestamp: now, PeerID: "peer", Path: "direct", Uplink: fmt.Sprintf("new-%d", i), Success: pointer(false)})
	}
	assertProbeQuota(t, s.Ingest(ctx, "robot", batch, now), "reclamation_work", maxReclaimRows)
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.ReclaimedStreams != 0 || stats.RollupRows != 2048 || stats.RawRows != 0 || stats.ReclamationRows != 0 {
		t.Fatal("work cap committed partial batch", stats, err)
	}
	ingest(t, s, "robot", batch[:128], now)
	ingest(t, s, "robot", batch[128:], now)
	stats, err = s.TieredStats(ctx)
	if err != nil || stats.ReclaimedSamples != 1032 || stats.RawRows != 129 {
		t.Fatal("split batches did not recover", stats, err)
	}
	if err := Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
}

func TestPathChurnExistingRetentionBlocksNewGeneration(t *testing.T) {
	s, now, batch := fullArchivedPaths(t)
	next := batch[0]
	next.ID, next.Uplink, next.Timestamp = "new", "uplink-4", now
	assertProbeQuota(t, s.Ingest(context.Background(), "robot", []Observation{next}, now), "node_streams", TieredMaxNodeStreams)
}

func TestPathChurnReclamationAtomicCoverageAndRestore(t *testing.T) {
	s, now, old := fullArchivedPaths(t)
	ctx := context.Background()
	if err := s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	req := PageRequest{Node: "robot", End: now, Window: 48 * time.Hour, Width: time.Hour}
	before, err := s.QueryPage(ctx, req)
	if err != nil || before.Coverage == nil || before.Coverage.Partial || before.NextCursor == "" {
		t.Fatal(before, err)
	}
	live := s.Latest(now)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER fail_reclaim BEFORE DELETE ON streams BEGIN SELECT RAISE(ABORT,'injected reclamation failure'); END`); err != nil {
		t.Fatal(err)
	}
	next := old[0]
	next.ID, next.Timestamp, next.Uplink = "new", now, "uplink-4"
	if err = s.Ingest(ctx, "robot", []Observation{next}, now); err == nil {
		t.Fatal("injected deletion failure succeeded")
	}
	if !reflect.DeepEqual(live, s.Latest(now)) {
		t.Fatal("failed reclamation published live changes")
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal("rollback corrupted storage", err)
	}
	after, err := s.QueryPage(ctx, req)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed reclamation changed history", err)
	}
	if _, err = db.Exec("DROP TRIGGER fail_reclaim"); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "robot", []Observation{next}, now)
	ingest(t, s, "robot", []Observation{next}, now) // lost acknowledgement: same request after commit
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.ReclaimedSamples != 1 || stats.ReclaimedStreams != 1 || stats.RawRows != 1 || stats.RollupRows != 255 {
		t.Fatal(stats, err)
	}
	after, err = s.QueryPage(ctx, req)
	if err != nil || !after.Coverage.Partial || after.Coverage.DiscardedSamples != 1 || !after.Coverage.Valid(after.Start, after.End) {
		t.Fatal(after.Coverage, err)
	}
	stale := req
	stale.Cursor = before.NextCursor
	if _, err = s.QueryPage(ctx, stale); !errors.Is(err, ErrInvalid) {
		t.Fatal("reclamation did not invalidate old pagination", err)
	}
	for _, source := range []string{"agent-direct", "monitor-overlay"} {
		filtered := req
		filtered.Source = source
		p, e := s.QueryPage(ctx, filtered)
		if e != nil {
			t.Fatal(e)
		}
		want := int64(0)
		if source == "agent-direct" {
			want = 1
		}
		if p.Coverage.DiscardedSamples != want {
			t.Fatal("loss source leaked", source, p.Coverage)
		}
	}
	if err = s.Ingest(ctx, "robot", []Observation{old[0]}, now); !errors.Is(err, ErrSealed) {
		t.Fatal("retired raw ID could return", err)
	}
	backup, restored := filepath.Join(t.TempDir(), "backup.db"), filepath.Join(t.TempDir(), "restored.db")
	if err = Backup(ctx, s.path, backup); err != nil {
		t.Fatal(err)
	}
	if err = Restore(ctx, backup, restored, now); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(restored, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.QueryPage(ctx, req)
	if err != nil || !reflect.DeepEqual(after, got) {
		t.Fatal("restore lost coverage", err)
	}
	if !reflect.DeepEqual(s.Latest(now), reopened.Latest(now)) {
		t.Fatal("restore changed live measurements")
	}
	if err = reopened.Maintain(ctx, now.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	stats, err = reopened.TieredStats(ctx)
	if err != nil || stats.ReclamationRows != 0 || stats.ReclaimedSamples != 1 {
		t.Fatal("loss retention/cumulative counters", stats, err)
	}
	if err = Check(ctx, reopened.path); err != nil {
		t.Fatal(err)
	}
}

func TestPathChurnProtectsRecentRawAndBatchRollback(t *testing.T) {
	s, now, old := fullArchivedPaths(t)
	ctx := context.Background()
	if err := s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	// Make the oldest identity active, so it cannot be selected for reclamation.
	active := old[0]
	active.ID, active.Timestamp = "active", now
	ingest(t, s, "robot", []Observation{active}, now)
	next := old[1]
	next.ID, next.Timestamp, next.Uplink = "fresh", now, "new-path"
	conflict := active
	conflict.RTTMs = pointer(99.)
	if err := s.Ingest(ctx, "robot", []Observation{next, conflict}, now); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.ReclaimedStreams != 0 || stats.ReclamationRows != 0 || stats.RawRows != 1 {
		t.Fatal("failed batch deleted accepted history", stats, err)
	}
	ingest(t, s, "robot", []Observation{next}, now)
	ingest(t, s, "robot", []Observation{active}, now)
	if err := Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
	// A new timestamp can revisit an archived path; its numeric stream ID must
	// increase, rather than reuse IDs that a pagination cursor has passed.
	db, err := connect(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var maxID int64
	if err = db.QueryRow("SELECT max(id) FROM streams").Scan(&maxID); err != nil || maxID != 257 {
		t.Fatal(maxID, err)
	}
}

func TestPathChurnAdversarialVariantsDoNotEvictActivePeer(t *testing.T) {
	s, now, old := fullArchivedPaths(t)
	ctx := context.Background()
	if err := s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	healthy := old[0]
	healthy.ID, healthy.Timestamp, healthy.PeerID, healthy.Uplink = "healthy", now, "healthy-peer", "stable"
	ingest(t, s, "robot", []Observation{healthy}, now)
	for i := 0; i < 255; i++ {
		o := old[0]
		o.ID, o.Timestamp, o.PeerID, o.Uplink = fmt.Sprint(i), now, "noisy-peer", fmt.Sprintf("variant-%d", i)
		ingest(t, s, "robot", []Observation{o}, now)
		if i%16 == 0 {
			ingest(t, s, "robot", []Observation{healthy}, now)
		}
	}
	extra := healthy
	extra.ID, extra.Uplink = "excess", "new-variant"
	assertProbeQuota(t, s.Ingest(ctx, "robot", []Observation{extra}, now), "node_streams", TieredMaxNodeStreams)
	healthy.ID = "healthy-next"
	ingest(t, s, "robot", []Observation{healthy}, now)
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.ReclaimedSamples != 256 || stats.ReclaimedStreams != 256 || stats.RawRows != 257 {
		t.Fatal("active data lost or duplicate accepted", stats, err)
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
}

// A candidate cached by the first new path must not delete a path refreshed
// later in the same atomic upload, regardless of observation order.
func TestPathChurnProtectsEntireIncomingBatch(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2}, {1, 0, 2}, {0, 2, 1}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			s, now, old := fullArchivedPaths(t)
			ctx := context.Background()
			if err := s.EnableReclamation(ctx); err != nil {
				t.Fatal(err)
			}
			active := old[1]
			active.ID, active.Timestamp = "refresh", now
			first, second := active, active
			first.Uplink, second.Uplink = "new-a", "new-b"
			choices := []Observation{first, active, second}
			batch := []Observation{choices[order[0]], choices[order[1]], choices[order[2]]}
			ingest(t, s, "robot", batch, now)
			ingest(t, s, "robot", batch, now)
			stats, err := s.TieredStats(ctx)
			if err != nil || stats.RawRows != 3 || stats.ReclaimedSamples != 2 || stats.ReclaimedStreams != 2 {
				t.Fatal(stats, err)
			}
			db, err := connect(s.path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var retained int
			if err := db.QueryRow(`SELECT count(*) FROM rollups a JOIN streams s ON s.id=a.stream WHERE s.node='robot' AND s.peer=? AND s.source=? AND s.uplink=?`, active.PeerID, active.Source, active.Uplink).Scan(&retained); err != nil || retained != 1 {
				t.Fatal("active path history reclaimed", retained, err)
			}
			if err := Check(ctx, s.path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPathChurnLossLedgerQuotaAndExpiry(t *testing.T) {
	s, now, old := fullArchivedPaths(t)
	ctx := context.Background()
	if err := s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Stage a full, internally consistent ledger of previously removed nodes.
	// This is a boundary fault fixture, not evidence of producer throughput.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<?)
INSERT INTO history_loss SELECT 'retired-'||n,'agent-direct',?,1 FROM seq`, MaxReclamationRows, now.Add(-24*time.Hour).UnixMicro()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE reclamation_metadata SET evicted_streams=?,evicted_samples=?,loss_rows=?,next_stream_id=next_stream_id+? WHERE id=1`, MaxReclamationRows, MaxReclamationRows, MaxReclamationRows, MaxReclamationRows); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE tier_metadata SET compacted_samples=compacted_samples+? WHERE id=1`, MaxReclamationRows); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
	o := old[0]
	o.Timestamp, o.ID, o.Uplink = now, "new", "new-path"
	assertProbeQuota(t, s.Ingest(ctx, "robot", []Observation{o}, now), "reclamation_rows", MaxReclamationRows)
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.ReclaimedSamples != MaxReclamationRows || stats.ReclamationRows != MaxReclamationRows || stats.RawRows != 0 || stats.RollupRows != 256 {
		t.Fatal("ledger overflow changed admitted data", stats, err)
	}
	if err = s.Maintain(ctx, now.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	stats, err = s.TieredStats(ctx)
	if err != nil || stats.ReclaimedSamples != MaxReclamationRows || stats.ReclamationRows != 0 {
		t.Fatal("bounded expiry failed", stats, err)
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
}

func TestPathChurnByteWorkBudget(t *testing.T) {
	s, now, old := fullArchivedPaths(t)
	ctx := context.Background()
	if err := s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	var aggregate ProbeAggregate
	for i := 0; i < MaxAggregateRTTValues; i++ {
		if err := aggregate.Add(pointer(true), pointer(float64(i)*.9)); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := aggregate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	within := maxReclaimBytes / len(payload)
	if within < 1 || within >= 255 {
		t.Fatal("fixture cannot cross byte boundary", len(payload))
	}
	// Stage high-density but valid archived distributions. Production upload and
	// reclamation must enforce the byte bound even below the row work bound.
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("UPDATE rollups SET payload=? WHERE stream<=?", payload, within+1); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE tier_metadata SET rollup_bytes=(SELECT sum(length(payload)) FROM rollups),compacted_samples=compacted_samples+?", (within+1)*(MaxAggregateRTTValues-1)); err != nil {
		t.Fatal(err)
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
	var batch []Observation
	for i := 0; i <= within; i++ {
		o := old[0]
		o.Timestamp, o.ID, o.Uplink = now, "new", fmt.Sprintf("new-%d", i)
		batch = append(batch, o)
	}
	assertProbeQuota(t, s.Ingest(ctx, "robot", batch, now), "reclamation_work_bytes", maxReclaimBytes)
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.RawRows != 0 || stats.ReclaimedSamples != 0 || stats.RollupRows != 256 {
		t.Fatal("byte cap committed partial batch", stats, err)
	}
	ingest(t, s, "robot", batch[:within], now)
	ingest(t, s, "robot", batch[within:], now)
	stats, err = s.TieredStats(ctx)
	if err != nil || stats.RawRows != int64(within+1) || stats.ReclaimedSamples != int64((within+1)*MaxAggregateRTTValues) {
		t.Fatal("split byte-bounded batches lost population", stats, err)
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
}
