// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// A retired path eventually has aggregates/live metadata but no raw rows. The
// old raw-only cleanup must not delete its stream before admitting new producers.
func TestTieredCompactedOnlyStreamKeepsUplinksAndEventsWritable(t *testing.T) {
	for _, kind := range []string{"uplink", "event"} {
		t.Run(kind, func(t *testing.T) {
			s, now := newStore(t)
			now = now.Truncate(time.Hour)
			ctx := context.Background()
			old := obs("retired-path-observation", now.Add(-8*time.Hour), pointer(12.))
			old.PeerID = "removed-peer"
			ingest(t, s, "robot", []Observation{old}, now)
			before, e := s.Query(ctx, "robot", now, 24*time.Hour, time.Hour)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.EnableTiering(ctx, now); e != nil {
				t.Fatal(e)
			}
			if e = s.EnableReclamation(ctx); e != nil {
				t.Fatal(e)
			}
			if e = s.EnableJitter(ctx); e != nil {
				t.Fatal(e)
			}
			if e = s.Maintain(ctx, now); e != nil {
				t.Fatal(e)
			}
			// Reopening a tiered store leaves inline legacy cleanup due. This models
			// both a controller restart and the first upload after a maintenance minute.
			s, e = Open(s.path, now)
			if e != nil {
				t.Fatal(e)
			}
			for n := 0; n < 3; n++ {
				at := now.Add(time.Duration(n) * time.Minute)
				if kind == "uplink" {
					e = s.IngestUplink(ctx, "robot", uplinkFixture(at, fmt.Sprintf("sample-%d", n)), at)
				} else {
					e = s.IngestEvent(ctx, "robot", Event{ID: fmt.Sprintf("event-%d", n), Timestamp: at, Kind: "collector_error", Source: "producer", Target: "retired-peer", Current: "up", Severity: "info", Validity: "observed"}, at)
				}
				if e != nil {
					t.Fatalf("%s blocked by unrelated compacted stream: %v", kind, e)
				}
			}
			after, e := s.Query(ctx, "robot", now, 24*time.Hour, time.Hour)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("mixed admission changed compacted population")
			}
			if kind == "uplink" {
				got, e := s.QueryUplinks(ctx, "robot", now.Add(2*time.Minute), time.Hour, 10)
				if e != nil || len(got.Snapshots) != 3 || got.Snapshots[0].Stale {
					t.Fatal("new uplink did not become fresh", e)
				}
			} else {
				got, e := s.QueryEvents(ctx, "robot", now.Add(2*time.Minute), time.Hour, 10)
				if e != nil || len(got.Events) != 3 {
					t.Fatal("events were not retained", e)
				}
			}
			// Skipping legacy inline cleanup must not disable retention: the
			// tiered maintainer still retires all categories and their metadata.
			if e = s.Maintain(ctx, now.Add(Retention+time.Hour)); e != nil {
				t.Fatal(e)
			}
			db, e := connect(s.path, true)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			for _, table := range []string{"streams", "probes", "rollups", "probe_live", "uplink_snapshots", "events"} {
				var count int
				if e = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); e != nil || count != 0 {
					t.Fatal("tiered retention left expired data", table, count, e)
				}
			}
			if e = Check(ctx, s.path); e != nil {
				t.Fatal(e)
			}
		})
	}
}
