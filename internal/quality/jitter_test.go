// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package quality

import (
	"math/rand/v2"
	"reflect"
	"testing"
	"time"
)

// This independent oracle groups equal timestamps before considering adjacency.
func jitterOracle(samples []Sample) (sum, pairs int64) {
	var previous *Sample
	for i := 0; i < len(samples); {
		end := i + 1
		for end < len(samples) && samples[end].Timestamp.UnixMicro() == samples[i].Timestamp.UnixMicro() {
			end++
		}
		current := samples[i]
		if end-i != 1 || !current.Success || current.Unknown {
			previous = nil
		} else {
			if previous != nil {
				d := current.RTTus - previous.RTTus
				if d < 0 {
					d = -d
				}
				sum += d
				pairs++
			}
			previous = &current
		}
		i = end
	}
	return
}

func TestJitterOrderedSummaryPartitions(t *testing.T) {
	rng := rand.New(rand.NewPCG(87, 8))
	for trial := 0; trial < 100; trial++ {
		var samples []Sample
		at := time.Unix(1000, 0)
		for i := 0; i < 100; i++ {
			at = at.Add(time.Duration(rng.IntN(3)) * time.Microsecond)
			samples = append(samples, Sample{Timestamp: at, RTTus: int64(rng.IntN(100)) * 1000, Success: rng.IntN(5) != 0, Unknown: rng.IntN(7) == 0})
		}
		sum, pairs := jitterOracle(samples)
		var whole JitterSummary
		for _, s := range samples {
			if !whole.Add(s.Timestamp.UnixMicro(), s.RTTus, s.Success && !s.Unknown) {
				t.Fatal("order rejected")
			}
		}
		if whole.Total.SumUS != sum || whole.Total.Pairs != pairs {
			t.Fatalf("oracle %d: %+v want %d/%d", trial, whole, sum, pairs)
		}
		for split := 0; split <= len(samples); split++ {
			var left, right JitterSummary
			for i, s := range samples {
				target := &left
				if i >= split {
					target = &right
				}
				target.Add(s.Timestamp.UnixMicro(), s.RTTus, s.Success && !s.Unknown)
			}
			if !left.Append(right) || left != whole {
				t.Fatalf("partition %d/%d: %+v != %+v", trial, split, left, whole)
			}
		}
		// A right-associated merge tree also crosses ties and singleton boundaries.
		var right JitterSummary
		for i := len(samples) - 1; i >= 0; i-- {
			var one JitterSummary
			s := samples[i]
			one.Add(s.Timestamp.UnixMicro(), s.RTTus, s.Success && !s.Unknown)
			if !one.Append(right) {
				t.Fatal("append")
			}
			right = one
		}
		if right != whole {
			t.Fatal("merge association changed jitter")
		}
	}
}

func TestJitterLiveBoundariesAndClone(t *testing.T) {
	cfg, _ := (QualityConfig{}).Normalized(5 * time.Second)
	w := NewWindow()
	start := time.Unix(1000, 0)
	var q PeerQuality
	// |30-10|+|20-30|=30 ms across two pairs; timeout breaks the run.
	for i, v := range []int64{10000, 30000, 20000, -1, 0, 0} {
		q = w.Observe(start.Add(time.Duration(i)*time.Second), Outcome{Success: v >= 0, RTTus: max(0, v)}, cfg)
	}
	if q.JitterMs == nil || *q.JitterMs != 10 || *q.JitterPairs != 3 {
		t.Fatal(q)
	}
	clone := q.Clone()
	*clone.JitterMs = 999
	*clone.JitterPairs = 999
	if *q.JitterMs != 10 || *q.JitterPairs != 3 {
		t.Fatal("aliased jitter")
	}
	stale := FreshQuality(q, start.Add(time.Hour))
	if !stale.Stale || *stale.JitterMs != 10 {
		t.Fatal(stale)
	}
	q = w.Observe(start.Add(6*time.Second), Outcome{Unknown: true, Reason: "collector_unavailable"}, cfg)
	if q.JitterMs != nil || *q.JitterPairs != 0 {
		t.Fatal("unknown bridged", q)
	}
	q = w.Observe(start.Add(7*time.Second), Outcome{Success: true, RTTus: 0}, cfg)
	q = w.Observe(start.Add(8*time.Second), Outcome{Success: true, RTTus: 0}, cfg)
	if q.JitterMs == nil || *q.JitterMs != 0 || *q.JitterPairs != 1 {
		t.Fatal("zero lost", q)
	}
	q = w.Observe(start.Add(8*time.Second), Outcome{Success: true, RTTus: 99000}, cfg)
	if q.JitterMs != nil || *q.JitterPairs != 0 {
		t.Fatal("tie failed to retract pair", q)
	}
	q = w.Observe(start.Add(9*time.Second), Outcome{Success: true, RTTus: 1000}, cfg)
	if *q.JitterPairs != 0 {
		t.Fatal("tie bridged", q)
	}
	q = w.Observe(start.Add(9*time.Second+cfg.Window), Outcome{Success: true, RTTus: 2000}, cfg)
	if *q.JitterPairs != 0 || q.SampleCount != 1 {
		t.Fatal("window lower bound", q)
	}
	q = w.Observe(start, Outcome{Success: true, RTTus: 1000}, cfg)
	if *q.JitterPairs != 0 || q.SampleCount != 1 {
		t.Fatal("clock regression", q)
	}
	if !reflect.DeepEqual(q.JitterStats, ReplayQuality([]Sample{{Timestamp: start, Success: true, RTTus: 1000}}).JitterStats) {
		t.Fatal("replay contract")
	}
}
