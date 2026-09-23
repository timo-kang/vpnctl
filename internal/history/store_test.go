// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	s, e := Open(filepath.Join(t.TempDir(), "history.db"), now)
	if e != nil {
		t.Fatal(e)
	}
	return s, now
}
func obs(id string, at time.Time, ms *float64) Observation {
	return Observation{ID: id, Timestamp: at, PeerID: "peer", Path: "relay", RelayID: "controller", Uplink: "wlan0", Success: pointer(ms != nil), RTTMs: ms}
}
func ingest(t *testing.T, s *Store, node string, os []Observation, now time.Time) {
	t.Helper()
	if e := s.Ingest(context.Background(), node, os, now); e != nil {
		t.Fatal(e)
	}
}
func query(t *testing.T, s *Store, now time.Time) []Bucket {
	t.Helper()
	b, e := s.Query(context.Background(), "", now, time.Hour, 15*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestMeasurementsSurviveRestartRetryBackupRestore(t *testing.T) {
	s, now := newStore(t)
	samples := []Observation{obs("a", now.Add(-3*time.Second), pointer(0.0)), obs("b", now.Add(-2*time.Second), nil), obs("c", now.Add(-time.Second), pointer(30.0))}
	ingest(t, s, "robot", samples, now)
	before := query(t, s, now)
	b := before[3]
	if b.Count != 3 || b.Successes != 2 || *b.AvgRTTMs != 15 || *b.P95RTTMs != 30 || math.Abs(*b.LossPct-100.0/3) > 1e-9 {
		t.Fatal(b)
	}
	if before[0].AvgRTTMs != nil || before[0].AvailabilityPct != nil {
		t.Fatal("gap became zero")
	}
	m := s.Latest(now)["robot"][0]
	if m.Quality != "poor" || m.Stale || m.SampleCount != 3 || *m.RTTMs != 15 {
		t.Fatal(m)
	}
	// Snapshots own their pointers. A consumer cannot mutate future responses.
	*m.RTTMs = 999
	if *s.Latest(now)["robot"][0].RTTMs != 15 {
		t.Fatal("aliased snapshot")
	}
	restarted, e := Open(s.path, now)
	if e != nil {
		t.Fatal(e)
	}
	ingest(t, restarted, "robot", samples, now)
	if !reflect.DeepEqual(before, query(t, restarted, now)) {
		t.Fatal("restart/retry changed history")
	}
	if m = restarted.Latest(now.Add(17 * time.Second))["robot"][0]; m.Quality != "unknown" || !m.Stale || m.RTTMs == nil {
		t.Fatal(m)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if e = Backup(context.Background(), s.path, backup); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(backup)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if e = Backup(context.Background(), s.path, backup); e == nil {
		t.Fatal("backup overwrote file")
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if e = Restore(context.Background(), backup, restored, now); e != nil {
		t.Fatal(e)
	}
	copy, e := Open(restored, now)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, query(t, copy, now)) {
		t.Fatal("restore changed history")
	}
	if e = Restore(context.Background(), backup, restored, now); e == nil {
		t.Fatal("restore overwrote data")
	}
}
func TestInvalidBatchAndConflictAreAtomic(t *testing.T) {
	s, now := newStore(t)
	good := obs("ok", now, pointer(5.0))
	ingest(t, s, "robot", []Observation{good}, now)
	variants := []Observation{obs("future", now.Add(time.Microsecond), nil), obs("old", now.Add(-Retention), nil), obs("nan", now, pointer(math.NaN())), obs("inf", now, pointer(math.Inf(1))), obs("negative", now, pointer(-1.0)), obs("too-long", now, pointer(60001.0))}
	missing := good
	missing.ID = "missing"
	missing.Success = nil
	variants = append(variants, missing)
	mismatch := good
	mismatch.ID = "mismatch"
	mismatch.Success = pointer(false)
	variants = append(variants, mismatch)
	badPath := good
	badPath.ID = "path"
	badPath.Path = "auto"
	variants = append(variants, badPath)
	badLabel := good
	badLabel.ID = "label"
	badLabel.Uplink = "x\nspoof"
	variants = append(variants, badLabel)
	for _, bad := range variants {
		fresh := obs("new-"+bad.ID, now, pointer(6.0))
		if e := s.Ingest(context.Background(), "robot", []Observation{fresh, bad}, now); !errors.Is(e, ErrInvalid) {
			t.Fatalf("%s: %v", bad.ID, e)
		}
	}
	conflict := good
	conflict.RTTMs = pointer(10.0)
	if e := s.Ingest(context.Background(), "robot", []Observation{obs("not-committed", now, nil), conflict}, now); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if query(t, s, now)[3].Count != 1 {
		t.Fatal("partial failed batch was committed")
	}
}
func TestOutOfOrderAndWindowEdges(t *testing.T) {
	s, now := newStore(t)
	os := []Observation{obs("end", now, pointer(10.0)), obs("start", now.Add(-time.Hour), pointer(999.0)), obs("inside", now.Add(-time.Hour+time.Microsecond), nil), obs("late", now.Add(-time.Second), pointer(20.0))}
	ingest(t, s, "robot", os, now)
	bs := query(t, s, now)
	if bs[0].Count != 1 || bs[0].AvgRTTMs != nil || *bs[0].LossPct != 100 || bs[3].Count != 2 {
		t.Fatal(bs)
	}
	m := s.Latest(now)["robot"][0]
	if m.SampleCount != 2 || *m.RTTMs != 15 || !m.ObservedAt.Equal(now) {
		t.Fatal(m)
	}
	// Future rows on disk (e.g. a clock step) must not enter query aggregates.
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("INSERT INTO probes(stream,id,ts,rtt) VALUES(1,'future',?,999999)", now.Add(time.Hour).UnixMicro()); e != nil {
		t.Fatal(e)
	}
	if query(t, s, now)[3].Count != 2 {
		t.Fatal("future row included")
	}
}
func TestRetentionAndCapacityRollback(t *testing.T) {
	s, now := newStore(t)
	ingest(t, s, "robot", []Observation{obs("old", now.Add(-Retention+time.Second), pointer(1.0)), obs("new", now, pointer(2.0))}, now)
	if e := s.Maintain(context.Background(), now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var count int
	if e = db.QueryRow("SELECT row_count FROM metadata").Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	if _, e = db.Exec("UPDATE metadata SET row_count=?", MaxRows); e != nil {
		t.Fatal(e)
	}
	if e = s.Ingest(context.Background(), "robot", []Observation{obs("over", now, pointer(8.0))}, now); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	assertProbeQuota(t, e, "rows", MaxRows)
	if query(t, s, now)[3].Count != 1 {
		t.Fatal("capacity failure was committed")
	}
	if e = s.Maintain(context.Background(), now.Add(Retention)); e != nil {
		t.Fatal(e)
	}
	if len(s.Latest(now.Add(Retention))) != 0 {
		t.Fatal("retention left published status")
	}
}
func TestSchemaAndBackupRejectForeignOrNewerDB(t *testing.T) {
	s, now := newStore(t)
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("PRAGMA user_version=999"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if _, e = Open(s.path, now); e == nil {
		t.Fatal("newer schema accepted")
	}
	if e = Restore(context.Background(), s.path, filepath.Join(t.TempDir(), "x.db"), now); e == nil {
		t.Fatal("newer backup accepted")
	}
	foreign := filepath.Join(t.TempDir(), "foreign.db")
	os.WriteFile(foreign, nil, 0600)
	db, e = connect(foreign, false)
	if e != nil {
		t.Fatal(e)
	}
	db.Exec("CREATE TABLE unrelated (id INTEGER)")
	db.Close()
	if _, e = Open(foreign, now); e == nil {
		t.Fatal("foreign schema initialized")
	}
}
func TestConcurrentRetryAndSnapshotWhileWriterBlocked(t *testing.T) {
	s, now := newStore(t)
	sample := obs("same", now, pointer(8.0))
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Ingest(context.Background(), "robot", []Observation{sample}, now); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if query(t, s, now)[3].Count != 1 {
		t.Fatal("concurrent retries inflated count")
	}
	s.writer <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := s.Ingest(ctx, "robot", []Observation{sample}, now); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	start := time.Now()
	if len(s.Latest(now)["robot"]) != 1 {
		t.Fatal("snapshot missing")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("status waited for DB")
	}
	<-s.writer
}
func TestDimensionsAndStreamCapacity(t *testing.T) {
	s, now := newStore(t)
	for i := 0; i < MaxNodeStreams; i++ {
		o := obs(fmt.Sprint(i), now, pointer(float64(i)))
		o.Uplink = fmt.Sprint(i)
		ingest(t, s, "robot", []Observation{o}, now)
	}
	over := obs("over", now, nil)
	over.Uplink = "overflow"
	assertProbeQuota(t, s.Ingest(context.Background(), "robot", []Observation{over}, now), "node_streams", MaxNodeStreams)
	if len(s.Latest(now)["robot"]) != MaxNodeStreams {
		t.Fatal("streams merged")
	}
}

func TestRepeatedConflictsDensityAndCancelledBackup(t *testing.T) {
	s, now := newStore(t)
	original := obs("original", now, pointer(0.0))
	ingest(t, s, "robot", []Observation{original}, now)
	bad := original
	bad.RTTMs = pointer(1.0)
	for i := 0; i < 100; i++ {
		if e := s.Ingest(context.Background(), "robot", []Observation{obs(fmt.Sprintf("not-committed-%d", i), now, nil), bad}, now); !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	if query(t, s, now)[3].Count != 1 {
		t.Fatal("conflicts changed counts")
	}
	for i := 1; i < MaxWindowSamples; {
		batch := []Observation{}
		for len(batch) < MaxBatch && i < MaxWindowSamples {
			batch = append(batch, obs(fmt.Sprint(i), now, pointer(1.0)))
			i++
		}
		ingest(t, s, "robot", batch, now)
	}
	assertProbeQuota(t, s.Ingest(context.Background(), "robot", []Observation{obs("over-density", now, nil)}, now), "window_samples", MaxWindowSamples)
	if query(t, s, now)[3].Count != MaxWindowSamples {
		t.Fatal("density failure mutated history")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target := filepath.Join(t.TempDir(), "cancelled.db")
	if e := Backup(ctx, s.path, target); e == nil {
		t.Fatal("cancelled backup succeeded")
	}
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("cancelled snapshot published", e)
	}
}

func assertProbeQuota(t *testing.T, err error, resource string, limit int) {
	t.Helper()
	var quota *QuotaError
	if !errors.Is(err, ErrCapacity) || !errors.As(err, &quota) || quota.Resource != resource || quota.Limit != limit {
		t.Fatalf("want %s quota %d, got %v", resource, limit, err)
	}
}

func TestGlobalProbeStreamQuotaAndExistingStreamRecovery(t *testing.T) {
	s, now := newStore(t)
	for n := 0; n < MaxStreams/MaxNodeStreams; n++ {
		var batch []Observation
		for p := 0; p < MaxNodeStreams; p++ {
			o := obs("first", now, pointer(1.0))
			o.PeerID = fmt.Sprint(p)
			batch = append(batch, o)
		}
		ingest(t, s, fmt.Sprint(n), batch, now)
	}
	o := obs("new-node", now, pointer(1.0))
	assertProbeQuota(t, s.Ingest(context.Background(), "another", []Observation{o}, now), "streams", MaxStreams)
	o.PeerID = "0"
	ingest(t, s, "0", []Observation{o}, now)
	ingest(t, s, "0", []Observation{o}, now)
	if len(s.Latest(now)) != MaxStreams/MaxNodeStreams {
		t.Fatal("rejected stream published")
	}
}

func TestFailedStorageDoesNotPublishStatus(t *testing.T) {
	s, now := newStore(t)
	sample := obs("first", now, pointer(10.0))
	ingest(t, s, "robot", []Observation{sample}, now)
	saved := s.path + ".saved"
	if e := os.Rename(s.path, saved); e != nil {
		t.Fatal(e)
	}
	sample.ID = "new"
	sample.RTTMs = pointer(999.0)
	if e := s.Ingest(context.Background(), "robot", []Observation{sample}, now); e == nil {
		t.Fatal("missing store accepted write")
	}
	if got := s.Latest(now)["robot"][0]; got.SampleCount != 1 || *got.RTTMs != 10 {
		t.Fatal("failed persistence published", got)
	}
	if e := os.Rename(saved, s.path); e != nil {
		t.Fatal(e)
	}
	ingest(t, s, "robot", []Observation{sample}, now)
	if query(t, s, now)[3].Count != 2 {
		t.Fatal("retry after storage recovery failed")
	}
}

func TestLastSuccessAndFreshnessAfterRestart(t *testing.T) {
	s, now := newStore(t)
	lastSuccess := now.Add(-5 * time.Minute)
	ingest(t, s, "robot", []Observation{obs("success", lastSuccess, pointer(10.0)), obs("fail1", now.Add(-2*time.Second), nil), obs("fail2", now.Add(-time.Second), nil), obs("fail3", now, nil)}, now)
	restarted, e := Open(s.path, now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		m := restarted.Latest(now)["robot"][0]
		if m.Quality != "offline" || m.RTTMs != nil || *m.LossPct != 100 || m.LastSuccessAt == nil || !m.LastSuccessAt.Equal(lastSuccess) {
			t.Fatal(m)
		}
	}
	m := restarted.Latest(now.Add(17 * time.Second))["robot"][0]
	if m.Quality != "unknown" || !m.Stale || m.ErrorReason != "stale" {
		t.Fatal(m)
	}
	m = restarted.Latest(now.Add(-time.Microsecond))["robot"][0]
	if m.Quality != "unknown" || !m.Stale || m.ErrorReason != "clock_regressed" {
		t.Fatal(m)
	}
}

func TestIngestDoesNotWaitForHistoryReadSnapshot(t *testing.T) {
	s, now := newStore(t)
	ingest(t, s, "robot", []Observation{obs("first", now, pointer(10.0))}, now)
	db, e := connect(s.path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var before int
	if e = tx.QueryRow("SELECT count(*) FROM probes").Scan(&before); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e = s.Ingest(ctx, "robot", []Observation{obs("second", now, pointer(20.0))}, now); e != nil {
		t.Fatal("history reader blocked ingest", e)
	}
	var snapshot int
	if e = tx.QueryRow("SELECT count(*) FROM probes").Scan(&snapshot); e != nil || snapshot != before {
		t.Fatal("read snapshot changed", snapshot, e)
	}
	tx.Rollback()
	if query(t, s, now)[3].Count != 2 {
		t.Fatal("concurrent write was lost")
	}
}
