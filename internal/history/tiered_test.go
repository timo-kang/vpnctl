// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

func tieredFixture(t *testing.T) (*Store, time.Time, []Bucket, map[string][]Measurement) {
	t.Helper()
	s, _ := newStore(t)
	now := time.Now().UTC().Truncate(time.Hour)
	var batch []Observation
	for i := 0; i < 1100; i++ {
		o := obs(fmt.Sprintf("old-%04d", i), now.Add(-8*time.Hour+time.Duration(i)*time.Millisecond), pointer(float64(i%73)))
		if i%10 == 0 {
			o.Success = pointer(false)
			o.RTTMs = nil
			o.Reason = "probe_timeout"
		}
		if i%20 == 0 {
			o.Success = nil
			o.Validity = "unknown"
			o.Reason = "collector_unavailable"
		}
		batch = append(batch, o)
		if len(batch) == MaxBatch {
			ingest(t, s, "robot", batch, now)
			batch = nil
		}
	}
	ingest(t, s, "robot", batch, now)
	// Exact hour boundaries, successful zero, recent raw and an unknown-only hour.
	ingest(t, s, "robot", []Observation{obs("boundary", now.Add(-7*time.Hour), pointer(0.)), obs("recent", now.Add(-time.Second), pointer(60000.))}, now)
	oracle, err := s.Query(context.Background(), "robot", now, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	live := s.Latest(now)
	if err = s.EnableTiering(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	return s, now, oracle, live
}

func assertTieredPopulation(t *testing.T, s *Store, now time.Time, want []Bucket) {
	t.Helper()
	got, err := s.Query(context.Background(), "robot", now, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatal("raw/aggregate population changed")
	}
}

func TestTieredAtomicCompactionRestartAndBackup(t *testing.T) {
	s, now, oracle, live := tieredFixture(t)
	ctx := context.Background()
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER fail_compaction BEFORE DELETE ON probes BEGIN SELECT RAISE(ABORT,'injected write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.Maintain(ctx, now); err == nil {
		t.Fatal("injected failure succeeded")
	}
	stats, err := s.TieredStats(ctx)
	if err != nil || stats.RollupRows != 0 || stats.RawRows != 1102 || stats.CompactedSamples != 0 {
		t.Fatal(stats, err)
	}
	assertTieredPopulation(t, s, now, oracle)
	if _, err = db.Exec("DROP TRIGGER fail_compaction"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.compactStep(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	stats, err = s.TieredStats(ctx)
	if err != nil || stats.CompactedSamples == 0 || stats.PendingSamples == 0 {
		t.Fatal("fixture did not stop in partial compaction", stats, err)
	}
	assertTieredPopulation(t, s, now, oracle)
	reopened, err := Open(s.path, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(live, reopened.Latest(now)) {
		t.Fatal("partial compaction changed live snapshot")
	}
	assertTieredPopulation(t, reopened, now, oracle)
	if err = reopened.Maintain(ctx, now); err != nil {
		t.Fatal(err)
	}
	assertTieredPopulation(t, reopened, now, oracle)
	stats, err = reopened.TieredStats(ctx)
	if err != nil || stats.PendingSamples != 0 || stats.RawRows != 1 || stats.CompactedSamples != 1101 {
		t.Fatal(stats, err)
	}
	backup := filepath.Join(t.TempDir(), "tiered.db")
	if err = Backup(ctx, s.path, backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err = Restore(ctx, backup, restored, now); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(restored, now)
	if err != nil {
		t.Fatal(err)
	}
	assertTieredPopulation(t, copy, now, oracle)
	if !reflect.DeepEqual(live, copy.Latest(now)) {
		t.Fatal("backup lost live state")
	}
	// Retries, new late samples and a mixed batch are explicitly rejected.
	for _, id := range []string{"old-0001", "late-new"} {
		err = copy.Ingest(ctx, "robot", []Observation{obs("not-committed", now, pointer(1.)), obs(id, now.Add(-8*time.Hour), pointer(1.))}, now)
		if !errors.Is(err, ErrSealed) {
			t.Fatal(err)
		}
	}
	assertTieredPopulation(t, copy, now, oracle)
	before, _ := copy.TieredStats(ctx)
	if err = copy.Maintain(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, _ := copy.TieredStats(ctx)
	if !before.SealedUntil.Equal(after.SealedUntil) || !before.ExpiredUntil.Equal(after.ExpiredUntil) {
		t.Fatal("durable time moved backwards")
	}
	if err = copy.Maintain(ctx, now.Add(Retention+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = Check(ctx, copy.path); err != nil {
		t.Fatal(err)
	}
	d, err := connect(copy.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var count int
	if err = d.QueryRow("SELECT count(*) FROM streams").Scan(&count); err != nil || count != 0 {
		t.Fatal("expired stream not reclaimed", count, err)
	}
	if len(copy.Latest(now.Add(Retention+time.Hour))) != 0 {
		t.Fatal("expired live state remained")
	}
}

func TestTieredInactiveStreamRetainsLiveSnapshot(t *testing.T) {
	s, now := newStore(t)
	now = now.Truncate(time.Hour)
	ingest(t, s, "robot", []Observation{obs("old-2", now.Add(-8*time.Hour-2*time.Second), pointer(12.)), obs("old-1", now.Add(-8*time.Hour-time.Second), pointer(12.)), obs("old", now.Add(-8*time.Hour), pointer(12.))}, now)
	want := s.Latest(now)
	if err := s.EnableTiering(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(s.path, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, copy.Latest(now)) {
		t.Fatal("aggregate-only stream lost last observation/success")
	}
	regressed := copy.Latest(now.Add(-8 * time.Hour))["robot"][0]
	if regressed.Quality != "unknown" || !regressed.Stale || regressed.ErrorReason != "clock_regressed" {
		t.Fatal("clock regression resurrected sealed quality", regressed)
	}
	// New failures retain provenance of the old success, without replaying hours.
	ingest(t, copy, "robot", []Observation{obs("new", now, nil)}, now)
	m := copy.Latest(now)["robot"][0]
	if m.SampleCount != 1 || m.LastSuccessAt == nil || !m.LastSuccessAt.Equal(now.Add(-8*time.Hour)) {
		t.Fatal(m)
	}
}

func TestTieredQueryPagesFiltersAndBoundaries(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	now = now.Truncate(time.Hour).Add(15 * time.Minute)
	if err := s.EnableTiering(ctx, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 70; i++ {
		o := obs("one", now.Add(-time.Hour), pointer(float64(i)))
		o.PeerID = fmt.Sprintf("peer-%03d", i)
		o.Source = "monitor-overlay"
		if i%2 == 0 {
			o.Source = "cli-ping"
		}
		ingest(t, s, "robot", []Observation{o}, now)
	}
	req := PageRequest{Node: "robot", Window: 24 * time.Hour, End: now, Align: true}
	seen := map[Stream]bool{}
	pages := 0
	for {
		page, err := s.QueryPage(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if !page.Aligned || page.Width != time.Hour || !page.End.Equal(now.Truncate(time.Hour)) {
			t.Fatal(page.PageInfo)
		}
		for _, b := range page.Buckets {
			if b.Count > 0 {
				if seen[b.Stream] {
					t.Fatal("stream repeated")
				}
				seen[b.Stream] = true
			}
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		req.Cursor = page.NextCursor
	}
	if pages != 5 || len(seen) != 70 {
		t.Fatal(pages, len(seen))
	}
	req.Cursor = ""
	req.Source = "cli-ping"
	page, err := s.QueryPage(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == "" {
		t.Fatal("filter did not paginate")
	}
	for _, b := range page.Buckets {
		if b.Source != "cli-ping" {
			t.Fatal(b)
		}
	}
	req.Cursor = page.NextCursor
	req.Source = "monitor-overlay"
	if _, err = s.QueryPage(ctx, req); !errors.Is(err, ErrInvalid) {
		t.Fatal("cursor accepted changed scope", err)
	}
	for _, r := range []PageRequest{{End: now, Window: 24 * time.Hour, Width: 15 * time.Minute, Align: true}, {End: now, Window: 24 * time.Hour, Width: time.Hour}, {End: now, Window: 7*time.Hour + time.Minute, Align: true}, {Cursor: "malformed", Window: time.Hour}} {
		if _, err = s.QueryPage(ctx, r); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsupported query accepted", r, err)
		}
	}
	page, err = s.QueryPage(ctx, PageRequest{Node: "robot", End: now, Window: time.Hour, Width: time.Minute})
	if err != nil || page.Aligned {
		t.Fatal("recent raw lost fine resolution", err)
	}
	if _, err = s.Query(ctx, "robot", now, time.Hour, time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatal("unpaged caller silently received partial fleet", err)
	}
}

func TestTieredCheckRejectsCorruptionWithoutPublishingRestore(t *testing.T) {
	for _, mutation := range []string{"UPDATE rollups SET payload=x'00'", "UPDATE tier_metadata SET rollup_rows=rollup_rows+1", "UPDATE tier_metadata SET rollup_bytes=rollup_bytes+1", "UPDATE tier_metadata SET sealed_until=sealed_until-1", "UPDATE tier_metadata SET compacted_samples=0", "UPDATE probe_live SET digest=zeroblob(32)", "UPDATE probe_live SET observed=observed+1", "UPDATE metadata SET row_count=row_count+1"} {
		t.Run(mutation, func(t *testing.T) {
			s, now, _, _ := tieredFixture(t)
			ctx := context.Background()
			if err := s.Maintain(ctx, now); err != nil {
				t.Fatal(err)
			}
			db, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if mutation == "UPDATE rollups SET payload=x'00'" {
				_, queryErr := s.Query(ctx, "robot", now, 24*time.Hour, time.Hour)
				if queryErr == nil || errors.Is(queryErr, ErrInvalid) {
					t.Fatal("stored corruption blamed on query input", queryErr)
				}
			}
			if err = Check(ctx, s.path); err == nil {
				t.Fatal("corrupt backup accepted")
			}
			if _, err = Open(s.path, now); err == nil {
				t.Fatal("corrupt tiered DB opened")
			}
			target := filepath.Join(t.TempDir(), "restore.db")
			if err = Restore(ctx, s.path, target, now); err == nil {
				t.Fatal("corrupt restore succeeded")
			}
			if _, err = os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("failed restore published")
			}
		})
	}
}

func TestTieredCrashAfterCommit(t *testing.T) {
	if path := os.Getenv("VPNCTL_TIER_CRASH_DB"); path != "" {
		before := os.Getenv("VPNCTL_TIER_CRASH_STAGE") == "before"
		if before {
			if err := sqlite.RegisterScalarFunction("test_compact_crash", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) { os.Exit(77); return nil, nil }); err != nil {
				t.Fatal(err)
			}
		}
		now := time.Now().UTC().Truncate(time.Hour)
		s, err := Open(path, now)
		if err != nil {
			t.Fatal(err)
		}
		db, err := connect(path, false)
		if err != nil {
			t.Fatal(err)
		}
		if before {
			if _, err = db.Exec(`CREATE TRIGGER crash_compaction BEFORE DELETE ON probes BEGIN SELECT test_compact_crash(); END`); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = s.compactStep(context.Background(), db, now); err != nil {
			t.Fatal(err)
		}
		os.Exit(77) // no Close/checkpoint or deferred cleanup
	}
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			s, now, oracle, _ := tieredFixture(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestTieredCrashAfterCommit$")
			cmd.Env = append(os.Environ(), "VPNCTL_TIER_CRASH_DB="+s.path, "VPNCTL_TIER_CRASH_STAGE="+stage)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("crash child failed: %v %s", err, output)
			}
			copy, err := Open(s.path, now)
			if err != nil {
				t.Fatal(err)
			}
			assertTieredPopulation(t, copy, now, oracle)
			stats, err := copy.TieredStats(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (stage == "before" && stats.CompactedSamples != 0) || (stage == "after" && stats.CompactedSamples == 0) {
				t.Fatal("wrong crash boundary", stats)
			}
			db, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("DROP TRIGGER IF EXISTS crash_compaction")
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err = copy.Maintain(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			assertTieredPopulation(t, copy, now, oracle)
		})
	}
}

func TestTieredMigrationPreflightAndLegacyVersions(t *testing.T) {
	ctx := context.Background()
	for version := 1; version <= 5; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			var s *Store
			var now time.Time
			if version == 5 {
				s, now = newStore(t)
			} else {
				old, at := legacyStore(t, version)
				now = at
				var err error
				s, err = Open(old.path, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			ingest(t, s, "robot", []Observation{obs("a", now, pointer(12.))}, now)
			backup := filepath.Join(t.TempDir(), "before.db")
			if err := Backup(ctx, s.path, backup); err != nil {
				t.Fatal(err)
			}
			if err := s.EnableTiering(ctx, now); err != nil {
				t.Fatal(err)
			}
			if err := Check(ctx, s.path); err != nil {
				t.Fatal(err)
			}
			old, err := Inspect(ctx, backup)
			if err != nil || old.SchemaVersion != 5 || old.Tiering != nil {
				t.Fatal("backup was altered by migration", old, err)
			}
			info, err := Inspect(ctx, s.path)
			if err != nil || info.SchemaVersion != 6 || info.Tiering == nil {
				t.Fatal(info, err)
			}
			if err = s.EnableTiering(ctx, now); err != nil {
				t.Fatal("repeated enable", err)
			}
		})
	}
	t.Run("dense preflight rolls back", func(t *testing.T) {
		s, now := newStore(t)
		ingest(t, s, "robot", []Observation{obs("seed", now, pointer(1.))}, now)
		db, err := connect(s.path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, err = db.Exec(`WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<65537) INSERT INTO probes(stream,id,ts,rtt) SELECT 1,cast(i AS TEXT),?+i,1000 FROM n; UPDATE metadata SET row_count=65538`, now.Truncate(time.Hour).Add(-24*time.Hour).UnixMicro())
		if err != nil {
			t.Fatal(err)
		}
		if err = s.EnableTiering(ctx, now); err == nil {
			t.Fatal("unrepresentable old density accepted")
		}
		var version, count int
		if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 5 {
			t.Fatal(version, err)
		}
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='rollups'").Scan(&count); err != nil || count != 0 {
			t.Fatal("partial migration schema", count, err)
		}
	})
	t.Run("cancel and inspect absent", func(t *testing.T) {
		s, now := newStore(t)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := s.EnableTiering(cancelled, now); err == nil {
			t.Fatal("cancelled migration succeeded")
		}
		info, err := Inspect(ctx, s.path)
		if err != nil || info.SchemaVersion != 5 {
			t.Fatal(info, err)
		}
		missing := filepath.Join(t.TempDir(), "missing.db")
		if _, err = Inspect(ctx, missing); err == nil {
			t.Fatal("inspected absent DB")
		}
		if _, err = os.Stat(missing); !os.IsNotExist(err) {
			t.Fatal("inspect created a database")
		}
	})
}

func TestTieredPinnedReaderAndCancelledMaintenance(t *testing.T) {
	s, now, oracle, _ := tieredFixture(t)
	ctx := context.Background()
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TABLE pressure(data BLOB)"); err != nil {
		t.Fatal(err)
	}
	reader, err := connect(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM probes").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO pressure VALUES(zeroblob(68157440))"); err != nil {
		t.Fatal(err)
	}
	err = s.Maintain(ctx, now)
	var quota *QuotaError
	if !errors.Is(err, ErrCapacity) || errors.As(err, &quota) {
		t.Fatal("pinned WAL classification", err)
	}
	assertTieredPopulation(t, s, now, oracle)
	tx.Rollback()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = s.Maintain(cancelled, now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	assertTieredPopulation(t, s, now, oracle)
	if err = s.Maintain(ctx, now); err != nil {
		t.Fatal(err)
	}
	assertTieredPopulation(t, s, now, oracle)
}

func TestTieredBackfillCannotPoisonCompaction(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	now = now.Truncate(time.Hour)
	if err := s.EnableTiering(ctx, now); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "robot", []Observation{obs("latest", now, pointer(1.))}, now)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := now.Add(-2 * time.Hour)
	_, err = db.Exec(`WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<65536) INSERT INTO probes(stream,id,ts,rtt) SELECT 1,cast(i AS TEXT),?+i,1000 FROM n; UPDATE metadata SET row_count=65537`, at.UnixMicro())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Ingest(ctx, "robot", []Observation{obs("fresh-not-committed", now, nil), obs("poison", at.Add(time.Second), pointer(2.))}, now)
	assertProbeQuota(t, err, "hour_samples", MaxAggregateRTTValues)
	var count int
	if err = db.QueryRow("SELECT count(*) FROM probes").Scan(&count); err != nil || count != 65537 {
		t.Fatal("failed density batch changed raw population", count, err)
	}
	if s.Latest(now)["robot"][0].SampleCount != 1 {
		t.Fatal("failed backfill changed live snapshot")
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
}

func TestTieredMaximumEscapedLabelsFitPage(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	if err := s.EnableTiering(ctx, now); err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("<", 128)
	for i := 0; i < 16; i++ {
		o := obs("one", now, pointer(60000.))
		o.PeerID = strings.Repeat(">", 128)
		o.RelayID = strings.Repeat("&", 128)
		o.Uplink = strings.Repeat("<", 126) + fmt.Sprintf("%02d", i)
		ingest(t, s, node, []Observation{o}, now)
	}
	page, err := s.QueryPage(ctx, PageRequest{Node: node, End: now, Window: 200 * time.Minute, Width: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Buckets) != 3200 || page.NextCursor != "" || len(data) < 8<<20 || len(data) > MaxHistoryResponseBytes {
		t.Fatal("worst escaped label page budget", len(page.Buckets), len(data))
	}
}
