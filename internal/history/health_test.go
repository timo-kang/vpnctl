// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestStorageHealthSchemaAndCachedFreshness(t *testing.T) {
	for _, base := range []int{5, 6, 7, 8, 9} {
		for _, wg := range []bool{false, true} {
			t.Run(fmt.Sprintf("schema_%d_wg_%t", base, wg), func(t *testing.T) {
				s, now := newStore(t)
				ctx := context.Background()
				if h := s.StorageHealth(now); h.Validity != "unknown" || h.Values != nil || h.Reason != "not_collected" {
					t.Fatal(h)
				}
				if base >= 6 {
					if e := s.EnableTiering(ctx, now); e != nil {
						t.Fatal(e)
					}
				}
				if base == 7 || base == 9 {
					if e := s.EnableReclamation(ctx); e != nil {
						t.Fatal(e)
					}
				}
				if base >= 8 {
					if e := s.EnableJitter(ctx); e != nil {
						t.Fatal(e)
					}
				}
				if wg {
					putWG(t, s, wgReport(now, 0, 42), now)
				}
				ingest(t, s, "robot", []Observation{obs("a", now, pointer(12.0))}, now)
				// Background health sampling does not queue behind API history or uploads.
				s.writer <- struct{}{}
				s.query <- struct{}{}
				err := s.RefreshStorageHealth(ctx, now)
				<-s.writer
				<-s.query
				if err != nil {
					t.Fatal(err)
				}
				h := s.StorageHealth(now)
				v := h.Values
				version := base
				if wg {
					version += 10
				}
				if h.Validity != "observed" || h.Stale || v == nil || v.SchemaVersion != version || v.RawRows != 1 || v.Streams != 1 || v.DatabaseBytes <= 0 || v.DatabaseBytes != v.UsedBytes+v.FreeBytes {
					t.Fatalf("%+v %+v", h, v)
				}
				if v.WireGuard.Enabled != wg || (wg && v.WireGuard.Rows != 1) || (base >= 6) != (v.Tiering != nil) {
					t.Fatal(v)
				}
				v.RawRows = 999
				v.WireGuard.Rows = 999
				if v.Tiering != nil {
					v.Tiering.RollupRows = 999
				}
				if s.StorageHealth(now).Values.RawRows != 1 || s.StorageHealth(now).Values.WireGuard.Rows == 999 {
					t.Fatal("cache alias")
				}
				ingest(t, s, "robot", []Observation{obs("b", now.Add(time.Second), pointer(9.0))}, now.Add(time.Second))
				if s.StorageHealth(now).Values.RawRows != 1 {
					t.Fatal("read unexpectedly queried SQLite")
				}
				for _, at := range []time.Time{now.Add(HealthStaleAfter), now.Add(-time.Second)} {
					h = s.StorageHealth(at)
					if !h.Stale || h.Values != nil || h.Validity != "unknown" {
						t.Fatal(h)
					}
				}
				if e := s.RefreshStorageHealth(ctx, now.Add(2*time.Second)); e != nil {
					t.Fatal(e)
				}
				if s.StorageHealth(now.Add(2*time.Second)).Values.RawRows != 2 {
					t.Fatal("no refresh")
				}
			})
		}
	}
}

func TestStorageHealthFailureRecoveryAndCancellation(t *testing.T) {
	s, now := newStore(t)
	if e := s.RefreshStorageHealth(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(s.path, s.path+".saved"); e != nil {
		t.Fatal(e)
	}
	if e := s.RefreshStorageHealth(context.Background(), now.Add(time.Second)); e == nil {
		t.Fatal("missing file accepted")
	}
	h := s.StorageHealth(now.Add(time.Second))
	if h.Validity != "unknown" || h.Reason != "collection_failed" || h.Values != nil || h.LastSuccessAt == nil || !h.LastSuccessAt.Equal(now) {
		t.Fatal(h)
	}
	if _, e := os.Stat(s.path); !os.IsNotExist(e) {
		t.Fatal("read recreated DB", e)
	}
	if e := os.Rename(s.path+".saved", s.path); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if e := s.RefreshStorageHealth(ctx, now.Add(2*time.Second)); e == nil {
		t.Fatal("cancel accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation stalled")
	}
	if e := s.RefreshStorageHealth(context.Background(), now.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.StorageHealth(now.Add(3*time.Second)).Validity != "observed" {
		t.Fatal("no recovery")
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				h := s.StorageHealth(now.Add(3 * time.Second))
				if h.Values != nil {
					h.Values.RawRows = 42
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if e := s.RefreshStorageHealth(context.Background(), now.Add(3*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	workers.Wait()
}

func TestStorageHealthCompactionBacklog(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	if e := s.EnableTiering(ctx, now); e != nil {
		t.Fatal(e)
	}
	ingest(t, s, "robot", []Observation{obs("a", now, pointer(12.0))}, now)
	later := now.Add(8 * time.Hour)
	if e := s.RefreshStorageHealth(ctx, later); e != nil {
		t.Fatal(e)
	}
	v := s.StorageHealth(later).Values
	if v.CompactionEligibleRows == nil || *v.CompactionEligibleRows != 1 || v.OldestCompactionEligible == nil || !v.OldestCompactionEligible.Equal(now) {
		t.Fatal(v)
	}
	if e := s.Maintain(ctx, later); e != nil {
		t.Fatal(e)
	}
	if e := s.RefreshStorageHealth(ctx, later); e != nil {
		t.Fatal(e)
	}
	v = s.StorageHealth(later).Values
	if *v.CompactionEligibleRows != 0 || v.OldestCompactionEligible != nil || v.Tiering.RollupRows != 1 || v.RawRows != 0 {
		t.Fatal(v)
	}
}
