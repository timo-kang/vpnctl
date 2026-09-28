// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestJitterAggregateBoundariesLegacyAndAtomicity(t *testing.T) {
	// 10,30, duplicate timestamp(20,100),50,60,unknown,0,0 => 20+10+0 / 3.
	values := []float64{10, 30, 20, 100, 50, 60, -1, 0, 0}
	times := []int64{1, 2, 3, 3, 4, 5, 6, 7, 8}
	var whole ProbeAggregate
	add := func(a *ProbeAggregate, i int) {
		t.Helper()
		var success *bool
		var ms *float64
		if values[i] >= 0 {
			success = pointer(true)
			ms = pointer(values[i])
		}
		if err := a.AddAt(times[i], success, ms); err != nil {
			t.Fatal(err)
		}
	}
	for i := range values {
		add(&whole, i)
	}
	got := whole.Bucket(Stream{}, time.Time{})
	if got.JitterMs == nil || *got.JitterMs != 10 || *got.JitterPairs != 3 || got.JitterKnownSamples != 9 {
		t.Fatal(got)
	}
	for split := 0; split <= len(values); split++ {
		var left, right ProbeAggregate
		for i := range values {
			a := &left
			if i >= split {
				a = &right
			}
			add(a, i)
		}
		// Round-trip each partition then merge in reverse order, as compaction does.
		l, e := DecodeProbeAggregate(encodedAggregate(t, &left))
		if e != nil {
			t.Fatal(e)
		}
		r, e := DecodeProbeAggregate(encodedAggregate(t, &right))
		if e != nil {
			t.Fatal(e)
		}
		if e = r.Merge(l); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(encodedAggregate(t, r), encodedAggregate(t, &whole)) {
			t.Fatalf("split %d", split)
		}
	}
	before := encodedAggregate(t, &whole)
	if err := whole.AddAt(1, pointer(true), pointer(1.)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	var overlap ProbeAggregate
	overlap.AddAt(4, pointer(true), pointer(1.))
	if err := whole.Merge(&overlap); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if !bytes.Equal(before, encodedAggregate(t, &whole)) {
		t.Fatal("rejected mutation changed state")
	}
	var legacy ProbeAggregate
	legacy.Add(pointer(true), pointer(50.))
	if err := whole.Merge(&legacy); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProbeAggregate(encodedAggregate(t, &whole))
	if err != nil {
		t.Fatal(err)
	}
	mixed := decoded.Bucket(Stream{}, time.Time{})
	if mixed.JitterMs != nil || mixed.JitterPairs != nil || mixed.JitterKnownSamples != 9 || mixed.JitterStatus != "unavailable_order" {
		t.Fatal(mixed)
	}
}

func TestJitterPartialCompactionTiesAndRestore(t *testing.T) {
	for _, reclaim := range []bool{false, true} {
		t.Run(fmt.Sprint(reclaim), func(t *testing.T) {
			ctx := context.Background()
			s, now := newStore(t)
			now = now.Truncate(time.Hour)
			// Put a duplicate timestamp on both sides of the 512-row batch boundary.
			var samples []Observation
			for i := 0; i < 1026; i++ {
				at := i
				if i == 512 {
					at = 511
				}
				o := obs(fmt.Sprintf("j-%04d", i), now.Add(-2*time.Hour+time.Duration(at+1)*time.Millisecond), pointer(float64(i%17)))
				if i%29 == 0 {
					o.Success = pointer(false)
					o.RTTMs = nil
				}
				if i%47 == 0 {
					o.Success = nil
					o.RTTMs = nil
					o.Validity = "unknown"
					o.Reason = "collector_unavailable"
				}
				samples = append(samples, o)
			}
			for end := len(samples); end > 0; {
				start := max(0, end-MaxBatch)
				ingest(t, s, "robot", samples[start:end], now)
				ingest(t, s, "robot", samples[start:end], now)
				end = start
			}
			want, err := s.Query(ctx, "robot", now, 3*time.Hour, 3*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if want[0].JitterMs == nil {
				t.Fatal("fixture has no jitter")
			}
			if err = s.EnableTiering(ctx, now); err != nil {
				t.Fatal(err)
			}
			if reclaim {
				if err = s.EnableReclamation(ctx); err != nil {
					t.Fatal(err)
				}
			}
			backup := filepath.Join(t.TempDir(), "pre.db")
			if err = Backup(ctx, s.path, backup); err != nil {
				t.Fatal(err)
			}
			if err = s.EnableJitter(ctx); err != nil {
				t.Fatal(err)
			}
			version := 8
			if reclaim {
				version = 9
			}
			info, _ := Inspect(ctx, s.path)
			if info.SchemaVersion != version || !info.Tiering.JitterEnabled {
				t.Fatal(info)
			}
			db, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			check := func(store *Store) {
				t.Helper()
				got, e := store.Query(ctx, "robot", now, 3*time.Hour, 3*time.Hour)
				if e != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("population changed: %v %v want %v", got, e, want)
				}
			}
			// Failed transaction publishes neither summary nor raw deletion.
			if _, err = db.Exec(`CREATE TRIGGER jitter_fail BEFORE DELETE ON probes BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
				t.Fatal(err)
			}
			if _, err = s.compactStep(ctx, db, now.Add(7*time.Hour)); err == nil {
				t.Fatal("failure committed")
			}
			check(s)
			if _, err = db.Exec("DROP TRIGGER jitter_fail"); err != nil {
				t.Fatal(err)
			}
			for step := 0; step < 3; step++ {
				if _, err = s.compactStep(ctx, db, now.Add(7*time.Hour)); err != nil {
					t.Fatal(err)
				}
				check(s)
				if err = Check(ctx, s.path); err != nil {
					t.Fatal(err)
				}
				reopened, e := Open(s.path, now.Add(7*time.Hour))
				if e != nil {
					t.Fatal(e)
				}
				check(reopened)
			}
			stats, _ := s.TieredStats(ctx)
			if stats.RawRows != 0 {
				t.Fatal(stats)
			}
			copyPath := filepath.Join(t.TempDir(), "copy.db")
			if err = Backup(ctx, s.path, copyPath); err != nil {
				t.Fatal(err)
			}
			restorePath := filepath.Join(t.TempDir(), "restore.db")
			if err = Restore(ctx, copyPath, restorePath, now.Add(7*time.Hour)); err != nil {
				t.Fatal(err)
			}
			restored, err := Open(restorePath, now.Add(7*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			check(restored)
		})
	}
}

func TestJitterLegacyMigrationAndMixedArchive(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	now = now.Truncate(time.Hour)
	ingest(t, s, "robot", []Observation{obs("old", now.Add(-2*time.Hour), pointer(10.))}, now)
	if err := s.EnableTiering(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(ctx, now.Add(7*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableJitter(ctx); err != nil {
		t.Fatal(err)
	}
	future := now.Add(8 * time.Hour)
	ingest(t, s, "robot", []Observation{obs("new1", future.Add(-time.Second), pointer(20.)), obs("new2", future, pointer(40.))}, future)
	page, err := s.QueryPage(ctx, PageRequest{Node: "robot", End: future, Window: 12 * time.Hour, Width: 12 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b := page.Buckets[0]
	if b.JitterMs != nil || b.JitterPairs != nil || b.JitterKnownSamples != 2 || b.JitterStatus != "unavailable_order" {
		t.Fatal(b)
	}
	if err = s.Maintain(ctx, future.Add(7*time.Hour)); err != nil {
		t.Fatal(err)
	}
	again, err := s.QueryPage(ctx, PageRequest{Node: "robot", End: future, Window: 12 * time.Hour, Width: 12 * time.Hour})
	if err != nil || !reflect.DeepEqual(page.Buckets, again.Buckets) {
		t.Fatal(again, err)
	}
	// Enabling reclamation after jitter must preserve the format gate.
	if err = s.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(ctx, s.path)
	if err != nil || info.SchemaVersion != 9 || !info.Tiering.JitterEnabled || !info.Tiering.ReclamationEnabled {
		t.Fatal(info, err)
	}
}

func TestJitterAllTiesAcrossReverseMerge(t *testing.T) {
	var early, late ProbeAggregate
	for i := 0; i < 512; i++ {
		if err := early.AddAt(1, pointer(true), pointer(1.)); err != nil {
			t.Fatal(err)
		}
	}
	late.AddAt(1, pointer(true), pointer(2.))
	late.AddAt(2, pointer(true), pointer(3.))
	late.AddAt(3, pointer(true), pointer(4.))
	if err := late.Merge(&early); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProbeAggregate(encodedAggregate(t, &late))
	if err != nil {
		t.Fatal(err)
	}
	b := decoded.Bucket(Stream{}, time.Time{})
	if *b.JitterPairs != 1 || *b.JitterMs != 1 {
		t.Fatal(b)
	}
}

func TestJitterRejectsImpossibleOrderedEncoding(t *testing.T) {
	var original ProbeAggregate
	for i := int64(1); i <= 4; i++ {
		if err := original.AddAt(i, pointer(true), pointer(float64(i))); err != nil {
			t.Fatal(err)
		}
	}
	valid := encodedAggregate(t, &original)
	for i := range valid {
		bad := append([]byte(nil), valid...)
		bad[i] ^= 0x80
		if _, err := DecodeProbeAggregate(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("corruption %d accepted", i)
		}
	}
	for _, mutate := range []func(*ProbeAggregate){
		func(a *ProbeAggregate) { a.jitter.Groups = 0 },
		func(a *ProbeAggregate) { a.jitter.First.Count = 2 },
		func(a *ProbeAggregate) { a.jitter.First.At = 0 },
		func(a *ProbeAggregate) { a.jitter.Total.Pairs = 5 },
		func(a *ProbeAggregate) { a.jitter.Total.SumUS = 60_000_000 * 4 },
		func(a *ProbeAggregate) { a.jitter.Head.Pairs = 2 },
		func(a *ProbeAggregate) { a.jitter.First.RTTUS = 99 },
		func(a *ProbeAggregate) { a.unordered = 5 },
	} {
		a, err := DecodeProbeAggregate(valid)
		if err != nil {
			t.Fatal(err)
		}
		mutate(a)
		if _, err = DecodeProbeAggregate(encodedAggregate(t, a)); !errors.Is(err, ErrInvalid) {
			t.Fatal("impossible summary accepted", a, err)
		}
	}
}

func TestJitterMigrationCancelledAndFutureSchema(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	if err := s.EnableJitter(ctx); err == nil {
		t.Fatal("enabled without tiering")
	}
	if err := s.EnableTiering(ctx, now); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.EnableJitter(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	info, err := Inspect(ctx, s.path)
	if err != nil || info.SchemaVersion != 6 || s.JitterEnabled() {
		t.Fatal(info, err)
	}
	if err = s.EnableJitter(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.EnableJitter(ctx); err != nil {
		t.Fatal("idempotent", err)
	}
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=10"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err = Open(s.path, now); err == nil {
		t.Fatal("future schema accepted")
	}
	if err = Check(ctx, s.path); err == nil {
		t.Fatal("future backup accepted")
	}
}

func TestJitterReportedStreamAndQueryWindowIsolation(t *testing.T) {
	s, now := newStore(t)
	now = now.Truncate(time.Minute)
	for sourceIndex, source := range []string{"agent-direct", "monitor-overlay"} {
		for pathIndex, path := range []string{"first", "second"} {
			var batch []Observation
			for i, rtt := range []float64{1000, 1, 4, 99} {
				offset := []time.Duration{-61 * time.Second, -3 * time.Second, -2 * time.Second, 0}[i]
				o := obs(fmt.Sprintf("%d", i), now.Add(offset), pointer(rtt+float64(sourceIndex*100+pathIndex*200)))
				o.Source, o.Path, o.RelayID, o.Uplink = source, "direct", "", path
				batch = append(batch, o)
			}
			ingest(t, s, "robot", batch, now)
		}
	}
	// Lower edge excludes the 1000ms sample; upper edge excludes the final 99ms.
	got, err := s.Query(context.Background(), "robot", now.Add(-time.Second), time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// All four streams independently retain 1,4 here; no cross-stream edges.
	for _, b := range got {
		if b.Count != 2 || b.JitterPairs == nil || *b.JitterPairs != 1 || b.JitterMs == nil || *b.JitterMs != 3 {
			t.Fatal(b)
		}
	}
	if len(got) != 4 {
		t.Fatal("source/path populations mixed", got)
	}
}
