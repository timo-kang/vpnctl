// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUplinkServiceTimingPersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	v := uplinkFixture(now.Add(-time.Second), "timed")
	start := now.Add(-3*time.Second + 123*time.Nanosecond).In(time.FixedZone("fixture", 9*3600))
	end := now.Add(-2*time.Second + 456*time.Nanosecond)
	v.Targets[0].ServiceStartedAt, v.Targets[0].ServiceCompletedAt = &start, &end
	if err := s.IngestUplink(ctx, "robot", v, now); err != nil {
		t.Fatal(err)
	}
	if v.Targets[0].ServiceStartedAt != &start || start.Nanosecond()%1000 != 123 || end.Nanosecond()%1000 != 456 {
		t.Fatal("ingestion mutated caller timestamps")
	}
	// Equivalent event instants from another zone remain idempotent.
	v.Targets[0].ServiceStartedAt = pointer(start.UTC())
	if err := s.IngestUplink(ctx, "robot", v, now); err != nil {
		t.Fatal(err)
	}
	v.Targets[0].ServiceCompletedAt = pointer(end.Add(time.Microsecond))
	if err := s.IngestUplink(ctx, "robot", v, now); !errors.Is(err, ErrConflict) {
		t.Fatal("changed time did not conflict", err)
	}
	s, err = Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	latest := s.LatestUplinks(now)["robot"]
	got := latest.Targets[0]
	if got.ServiceStartedAt == nil || !got.ServiceStartedAt.Equal(start.UTC().Truncate(time.Microsecond)) || got.ServiceCompletedAt == nil || !got.ServiceCompletedAt.Equal(end.Truncate(time.Microsecond)) {
		t.Fatal("restart lost timing", got)
	}
	*got.ServiceStartedAt = now
	if s.LatestUplinks(now)["robot"].Targets[0].ServiceStartedAt.Equal(now) {
		t.Fatal("returned time aliases cache")
	}
	query, err := s.QueryUplinks(ctx, "robot", now, time.Hour, 10)
	if err != nil || len(query.Snapshots) != 1 || !query.Snapshots[0].Targets[0].ServiceCompletedAt.Equal(end.Truncate(time.Microsecond)) {
		t.Fatal("query lost timing", query, err)
	}
	// Legacy payloads remain admissible and are not backfilled with cycle time.
	legacy := uplinkFixture(now, "legacy")
	if err := s.IngestUplink(ctx, "robot", legacy, now); err != nil {
		t.Fatal(err)
	}
	if s.LatestUplinks(now)["robot"].Targets[0].ServiceStartedAt != nil {
		t.Fatal("legacy time fabricated")
	}
}

func TestUplinkTimingRejectsRawInvalidBeforeRounding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	s, err := Open(filepath.Join(t.TempDir(), "history.db"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"future-cycle", "reversed", "after-cycle"} {
		t.Run(kind, func(t *testing.T) {
			v := uplinkFixture(now, kind)
			switch kind {
			case "future-cycle":
				v.At = now.Add(time.Nanosecond)
			case "reversed":
				v.Targets[0].ServiceStartedAt = pointer(now.Add(-time.Second + time.Nanosecond))
				v.Targets[0].ServiceCompletedAt = pointer(now.Add(-time.Second))
			case "after-cycle":
				v.Targets[0].ServiceStartedAt = pointer(now.Add(-time.Second))
				v.Targets[0].ServiceCompletedAt = pointer(now.Add(time.Nanosecond))
			}
			if err := s.IngestUplink(context.Background(), "robot", v, now); !errors.Is(err, ErrInvalid) {
				t.Fatal("rounding admitted invalid raw time", err)
			}
		})
	}
	if len(s.LatestUplinks(now)) != 0 {
		t.Fatal("rejected evidence entered live cache")
	}
}
