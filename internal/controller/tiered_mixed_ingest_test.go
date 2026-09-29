// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
)

func TestTieredRetiredPathsKeepMixedMTLSUploadsFresh(t *testing.T) {
	for _, nodes := range []int{1, 3, 8} {
		t.Run(fmt.Sprint(nodes), func(t *testing.T) {
			dir := t.TempDir()
			s, stop := testAdminServer(t, dir)
			st := s.history.(*history.Store)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Hour)
			if e := st.EnableTiering(ctx, now.Add(-12*time.Hour)); e != nil {
				t.Fatal(e)
			}
			if e := st.EnableReclamation(ctx); e != nil {
				t.Fatal(e)
			}
			if e := st.EnableJitter(ctx); e != nil {
				t.Fatal(e)
			}
			for n := 0; n < nodes; n++ {
				id := fmt.Sprintf("robot-%02d", n)
				// Two successive retired path identities, aged past raw retention. The
				// clock advances only in storage; network authentication uses wall time.
				for gen := 0; gen < 2; gen++ {
					at := now.Add(-8*time.Hour + time.Duration(gen)*time.Minute)
					o := history.Observation{ID: fmt.Sprintf("old-%d", gen), Timestamp: at, PeerID: fmt.Sprintf("retired-%d", gen), Source: "agent-direct", Path: "direct", Success: historyPtr(true), RTTMs: historyPtr(2.)}
					if e := st.Ingest(ctx, id, []history.Observation{o}, now); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e := st.Maintain(ctx, now); e != nil {
				t.Fatal(e)
			}
			stop()
			s, _ = testAdminServer(t, dir)
			h, _, _ := testTLSAPI(t, s)
			for n := 0; n < nodes; n++ {
				id := fmt.Sprintf("robot-%02d", n)
				client, _ := lifecycleNode(t, s, h, id)
				for generation := 0; generation < 3; generation++ {
					snapshot := controllerUplinkFixture()
					snapshot.ID = fmt.Sprintf("fresh-%d", generation)
					snapshot.At = time.Now().UTC().Truncate(time.Microsecond)
					if e := client.SubmitUplink(ctx, api.UplinkRequest{NodeID: id, Snapshot: snapshot}); e != nil {
						t.Fatal("uplink rejected after compaction/restart", e)
					}
					event := history.Event{ID: fmt.Sprintf("fresh-event-%d", generation), Timestamp: snapshot.At, Kind: "collector_error", Source: "mixed-regression", Target: "uplink", Current: "up", Severity: "info", Validity: "observed"}
					if e := client.SubmitEvent(ctx, api.EventRequest{NodeID: id, Event: event}); e != nil {
						t.Fatal("event rejected after compaction/restart", e)
					}
					// Retry accepted identities to also verify unchanged idempotency.
					if e := client.SubmitUplink(ctx, api.UplinkRequest{NodeID: id, Snapshot: snapshot}); e != nil {
						t.Fatal(e)
					}
					if e := client.SubmitEvent(ctx, api.EventRequest{NodeID: id, Event: event}); e != nil {
						t.Fatal(e)
					}
				}
				view, e := client.FleetUplinks(ctx, id, "1h", 10)
				if e != nil || len(view.Snapshots) != 3 || view.Snapshots[0].Stale || view.Snapshots[0].ID != "fresh-2" {
					t.Fatal("fresh mTLS population", e)
				}
				events, e := client.FleetEvents(ctx, id, "1h", 100)
				if e != nil {
					t.Fatal(e)
				}
				count := 0
				for _, ev := range events.Events {
					if ev.Source == "mixed-regression" {
						count++
					}
				}
				if count != 3 {
					t.Fatal("event population", count)
				}
				buckets, e := s.history.(*history.Store).Query(ctx, id, now, 24*time.Hour, time.Hour)
				if e != nil {
					t.Fatal(e)
				}
				population := 0
				for _, b := range buckets {
					population += b.Count
				}
				if population != 2 {
					t.Fatal("retired path aggregate population changed", population)
				}
			}
			if e := history.Check(ctx, filepath.Join(dir, "history.db")); e != nil {
				t.Fatal(e)
			}
		})
	}
}
