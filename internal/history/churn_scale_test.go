// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"vpnctl/internal/quality"
)

// Actual Ingest/Maintain/QueryPage calls, without raw or aggregate SQL staging.
// Twenty-four unique generations fit inside seven days; old paths are not
// silently reused to make the stream quota disappear.
func TestPathChurnVariableMesh(t *testing.T) {
	for _, nodes := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(nodes), func(t *testing.T) {
			s, end := newStore(t)
			end = end.Truncate(time.Hour)
			generations := 24
			if nodes == 32 && os.Getenv("VPNCTL_HISTORY_CHURN_SCALE") != "1" {
				// Still cross the 8,192-stream ceiling under race detection.
				// The dedicated CI capacity step exercises all 24 generations.
				generations = 5
			}
			start := end.Add(-time.Duration(generations-1) * 7 * time.Hour)
			ctx := context.Background()
			if err := s.EnableTiering(ctx, start); err != nil {
				t.Fatal(err)
			}
			if err := s.EnableReclamation(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.EnableJitter(ctx); err != nil {
				t.Fatal(err)
			}
			original := map[Stream]Observation{}
			var total int64
			var maxIngest time.Duration
			for gen := 0; gen < generations; gen++ {
				now := start.Add(time.Duration(gen) * 7 * time.Hour)
				if err := s.Maintain(ctx, now); err != nil {
					t.Fatal(err)
				}
				for node := 0; node < nodes; node++ {
					name := fmt.Sprintf("robot-%02d", node)
					var batch []Observation
					for peer := nodes - 1; peer >= 0; peer-- {
						if peer == node {
							continue
						}
						for _, source := range []string{"monitor-overlay", "agent-direct"} {
							o := Observation{ID: fmt.Sprintf("%d-%d-%d", gen, node, peer), Timestamp: now.Add(-time.Minute), PeerID: fmt.Sprintf("robot-%02d", peer), Source: source, Path: "direct", Uplink: fmt.Sprintf("uplink-%02d", gen), Success: pointer(true), RTTMs: pointer(float64(gen + node + peer))}
							if source == "monitor-overlay" {
								o.Path, o.RelayID = "relay", fmt.Sprintf("relay-%d", gen%3)
							}
							if gen%3 == 0 {
								o.Success, o.RTTMs, o.Validity, o.Reason = nil, nil, "unknown", "collector_unavailable"
							}
							if gen%3 == 1 {
								o.Success, o.RTTMs, o.Reason = pointer(false), nil, "probe_timeout"
							}
							batch = append(batch, o)
							original[Stream{NodeID: name, PeerID: o.PeerID, Source: source, Path: o.Path, RelayID: o.RelayID, Uplink: o.Uplink}] = o
						}
					}
					if len(batch) == 0 {
						continue
					}
					began := time.Now()
					ingest(t, s, name, batch, now)
					maxIngest = max(maxIngest, time.Since(began))
					if gen%5 == 0 {
						ingest(t, s, name, batch, now)
					}
					total += int64(len(batch))
				}
			}
			if maxIngest > 3*time.Second {
				t.Fatal("churn ingest exceeded API budget", maxIngest)
			}
			var retained, lost int64
			var maxQuery time.Duration
			for node := 0; node < nodes; node++ {
				req := PageRequest{Node: fmt.Sprintf("robot-%02d", node), End: end, Window: Retention, Width: time.Hour}
				var coverage *HistoryCoverage
				began := time.Now()
				for {
					page, err := s.QueryPage(ctx, req)
					if err != nil {
						t.Fatal(err)
					}
					data, err := json.Marshal(page)
					if err != nil || len(data) > MaxHistoryResponseBytes {
						t.Fatal("response budget", len(data), err)
					}
					if coverage == nil {
						coverage = page.Coverage
						lost += coverage.DiscardedSamples
					} else if !reflect.DeepEqual(coverage, page.Coverage) {
						t.Fatal("coverage counted per-page instead of per-window")
					}
					for _, b := range page.Buckets {
						o, exists := original[b.Stream]
						if !exists {
							t.Fatal("invented path", b.Stream)
						}
						want := Bucket{Stream: b.Stream, Time: b.Time, JitterStats: quality.JitterStats{JitterStatus: "complete", JitterPairs: pointer(int64(0))}}
						if o.Timestamp.After(b.Time) && !o.Timestamp.After(b.Time.Add(time.Hour)) {
							want.JitterKnownSamples = 1
							if o.Success == nil {
								want.UnknownCount = 1
							} else {
								want.Count = 1
								want.AvailabilityPct = pointer(0.)
								want.LossPct = pointer(100.)
								if *o.Success {
									want.Successes = 1
									want.AvailabilityPct = pointer(100.)
									want.LossPct = pointer(0.)
									want.AvgRTTMs = o.RTTMs
									want.P95RTTMs = o.RTTMs
									want.P50RTTMs = o.RTTMs
									want.P99RTTMs = o.RTTMs
								}
							}
						}
						if !reflect.DeepEqual(want, b) {
							t.Fatalf("remaining data changed: want=%+v got=%+v", want, b)
						}
						retained += int64(b.Count + b.UnknownCount)
					}
					if page.NextCursor == "" {
						break
					}
					req.Cursor = page.NextCursor
				}
				maxQuery = max(maxQuery, time.Since(began))
			}
			if retained+lost != total {
				t.Fatal("unreported loss or duplicate", retained, lost, total)
			}
			if nodes >= 8 && lost == 0 {
				t.Fatal("fixture did not exercise reclamation")
			}
			if maxQuery > QueryTimeout {
				t.Fatal("reporter page sequence budget", maxQuery)
			}
			if err := Check(ctx, s.path); err != nil {
				t.Fatal(err)
			}
			stats, err := s.TieredStats(ctx)
			if err != nil || stats.ReclaimedSamples != lost || stats.DatabaseBytes > ProbeStorageBudget {
				t.Fatal(stats, err)
			}
			t.Logf("nodes=%d generations=%d admitted=%d retained=%d reported_loss=%d db_bytes=%d max_ingest=%s max_reporter_query_json_oracle=%s", nodes, generations, total, retained, lost, stats.DatabaseBytes, maxIngest, maxQuery)
		})
	}
}
