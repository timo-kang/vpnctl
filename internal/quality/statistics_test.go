// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package quality

import (
	"reflect"
	"testing"
	"time"
)

func TestReplayPercentilesMatchIncrementalQuality(t *testing.T) {
	cfg, _ := (QualityConfig{}).Normalized(5 * time.Second)
	w := NewWindow()
	start := time.Now().UTC()
	var samples []Sample
	for i := 0; i < 80; i++ {
		s := Sample{Timestamp: start.Add(time.Duration(i) * time.Second), RTTus: int64(i%17) * 1000, Success: i%4 != 0}
		if i == 30 {
			s.Unknown, s.Reason = true, "collector_unavailable"
		}
		samples = append(samples, s)
		live := w.Observe(s.Timestamp, Outcome{RTTus: s.RTTus, Success: s.Success, Unknown: s.Unknown, Reason: s.Reason}, cfg)
		if replay := ReplayQuality(samples); !reflect.DeepEqual(live, replay) {
			t.Fatalf("prefix %d: live=%+v replay=%+v", i, live, replay)
		}
	}
}

func TestSuccessfulRTTPercentilesAndWindowBoundaries(t *testing.T) {
	start := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	cfg, _ := (QualityConfig{}).Normalized(5 * time.Second)
	w := NewWindow()
	var q PeerQuality
	for i := 0; i < 100; i++ {
		q = w.Observe(start.Add(time.Duration(i)*time.Millisecond), Outcome{Success: true, RTTus: int64(i) * 1000}, cfg)
	}
	q = w.Observe(start.Add(time.Second), Outcome{Success: false}, cfg)
	if *q.P50RTTMs != 49 || *q.P95RTTMs != 94 || *q.P99RTTMs != 98 || q.SampleCount != 101 {
		t.Fatalf("nearest-rank success population: %+v", q)
	}
	copy := FreshQuality(q, start.Add(time.Hour))
	if !copy.Stale || copy.Level != QualityUnknown || *copy.P99RTTMs != 98 {
		t.Fatal("stale changed measured values", copy)
	}
	*copy.P50RTTMs, *copy.P95RTTMs, *copy.P99RTTMs = 1, 2, 3
	if *q.P50RTTMs != 49 || *q.P95RTTMs != 94 || *q.P99RTTMs != 98 {
		t.Fatal("snapshot aliases percentiles")
	}
	q = w.Observe(start.Add(2*time.Second), Outcome{Unknown: true, Reason: "collector_unavailable"}, cfg)
	if q.P50RTTMs != nil || q.P95RTTMs != nil || q.P99RTTMs != nil || q.SampleCount != 0 {
		t.Fatal("unknown became RTT", q)
	}
	q = w.Observe(start.Add(3*time.Second), Outcome{Success: true, RTTus: 0}, cfg)
	if *q.P50RTTMs != 0 || *q.P95RTTMs != 0 || *q.P99RTTMs != 0 {
		t.Fatal("measured zero lost", q)
	}
	q = w.Observe(start.Add(3*time.Second+cfg.Window), Outcome{Success: false}, cfg)
	if q.SampleCount != 1 || q.P50RTTMs != nil || q.P95RTTMs != nil || q.P99RTTMs != nil {
		t.Fatal("exclusive lower edge/all failure", q)
	}
	q = w.Observe(start.Add(time.Second), Outcome{Success: true, RTTus: 999}, cfg)
	if q.SampleCount != 1 || *q.P50RTTMs != .999 || *q.P95RTTMs != .999 || *q.P99RTTMs != .999 {
		t.Fatal("clock regression retained future values", q)
	}
	if empty := ReplayQuality(nil); empty.P50RTTMs != nil || empty.P95RTTMs != nil || empty.P99RTTMs != nil {
		t.Fatal("empty window measured", empty)
	}
}
