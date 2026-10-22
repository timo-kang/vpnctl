// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Guard the measured source of the full-retention regression: a secondary
// index scan followed by millions of lookups in the WITHOUT ROWID primary tree.
// Short windows must retain their selective time-range lookup.
func TestLegacyQueryPlanBoundsFullRetentionLookupCost(t *testing.T) {
	s, now := newStore(t)
	db, err := connect(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, window := range []time.Duration{time.Minute, time.Hour, 24 * time.Hour, Retention} {
		rows, err := db.Query("EXPLAIN QUERY PLAN "+legacyProbeQuery(window), 1, now.Add(-window).UnixMicro(), now.UnixMicro())
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plan.WriteString(detail + "\n")
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		if window == Retention {
			if !strings.Contains(plan.String(), "SEARCH probes USING PRIMARY KEY (stream=?)") || strings.Contains(plan.String(), "probe_stream_time") || strings.Contains(plan.String(), "TEMP B-TREE") {
				t.Fatal("full-retention scan reintroduced secondary lookups or SQL sorting", plan.String())
			}
		} else if !strings.Contains(plan.String(), "probe_stream_time (stream=? AND ts>? AND ts<?)") {
			t.Fatal("short window lost selective time range", window, plan.String())
		}
	}
}

func TestLegacyFullRetentionQueryKeepsBoundariesAndOrderedStatistics(t *testing.T) {
	s, now := newStore(t)
	end := now.Truncate(time.Hour)
	start := end.Add(-Retention)
	boundary := start.Add(time.Hour)
	samples := []Observation{
		obs("z-first", start.Add(time.Microsecond), pointer(0.0)),
		obs("a-boundary", boundary, pointer(10.0)),
		obs("failure", boundary.Add(time.Microsecond), nil),
		obs("unknown", boundary.Add(2*time.Microsecond), nil),
		obs("z-tie", boundary.Add(3*time.Microsecond), pointer(4.0)),
		obs("a-tie", boundary.Add(3*time.Microsecond), pointer(9.0)),
		obs("z-next", boundary.Add(4*time.Microsecond), pointer(12.0)),
		obs("a-last", boundary.Add(5*time.Microsecond), pointer(22.0)),
		obs("end", end, pointer(8.0)),
	}
	samples[3].Success, samples[3].Validity, samples[3].Reason = nil, "unknown", "collector_unavailable"
	// Reverse arrival and non-time-ordered IDs must not reorder jitter edges.
	for i, j := 0, len(samples)-1; i < j; i, j = i+1, j-1 {
		samples[i], samples[j] = samples[j], samples[i]
	}
	ingest(t, s, "robot", samples, end)
	ingest(t, s, "other", []Observation{obs("other", end, pointer(999.0))}, end)
	bs, err := s.Query(context.Background(), "robot", end, Retention, time.Hour)
	if err != nil || len(bs) != 168 {
		t.Fatal(len(bs), err)
	}
	first, second, last := bs[0], bs[1], bs[167]
	if first.Count != 2 || first.Successes != 2 || first.UnknownCount != 0 || *first.AvgRTTMs != 5 || *first.P50RTTMs != 0 || *first.P95RTTMs != 10 || *first.P99RTTMs != 10 || *first.JitterMs != 10 || *first.JitterPairs != 1 {
		t.Fatal("first boundary population changed", first)
	}
	if second.Count != 5 || second.Successes != 4 || second.UnknownCount != 1 || *second.AvgRTTMs != 11.75 || *second.P50RTTMs != 9 || *second.P95RTTMs != 22 || *second.P99RTTMs != 22 || *second.JitterMs != 10 || *second.JitterPairs != 1 || second.JitterKnownSamples != 6 {
		t.Fatal("ties, failure or unknown changed ordered statistics", second)
	}
	if last.Count != 1 || *last.AvgRTTMs != 8 || bs[2].AvailabilityPct != nil || bs[2].P95RTTMs != nil {
		t.Fatal("end boundary, node filter or empty buckets changed", last, bs[2])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.Query(ctx, "robot", end, Retention, time.Hour); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("cancellation returned a successful or partial population", got, err)
	}
}
