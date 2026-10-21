// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictorinput

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/predictor"
)

func TestProbeValidityAndWindowBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rows      []history.Observation
		rtt, loss string
		ready     bool
	}{
		{"no samples", nil, "missing", "missing", false},
		{"valid zero", []history.Observation{probe("zero", tick, ptr(true), ptr(0.0))}, "observed", "observed", true},
		{"failure", []history.Observation{probe("fail", tick, ptr(false), nil)}, "missing", "observed", true},
		{"unknown", []history.Observation{probe("unknown", tick, nil, nil)}, "unknown", "unknown", false},
		{"expiry edge", []history.Observation{probe("expired", tick.Add(-config.MaxAge), ptr(true), ptr(1.0))}, "stale", "stale", false},
		{"before expiry", []history.Observation{probe("fresh", tick.Add(-config.MaxAge+time.Microsecond), ptr(true), ptr(1.0))}, "observed", "observed", true},
		{"unknown in current bucket", []history.Observation{probe("unknown", tick.Add(-time.Millisecond), nil, nil), probe("good", tick.Add(-time.Microsecond), ptr(true), ptr(3.0))}, "observed", "unknown", true},
		{"failure at equal time", []history.Observation{probe("a", tick, ptr(false), nil), probe("z", tick, ptr(true), ptr(3.0))}, "missing", "observed", true},
		{"unknown at equal time", []history.Observation{probe("a", tick, nil, nil), probe("z", tick, ptr(true), ptr(3.0))}, "unknown", "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildProbes(scope, tc.rows, tick, config)
			if err != nil {
				t.Fatal(err)
			}
			if got.Features[0].State != tc.rtt || got.Features[1].State != tc.loss || got.Ready != tc.ready {
				t.Fatalf("unexpected readiness: %+v", got)
			}
			if (got.Features[0].State != "observed" && len(got.Observation.RTTHistory) != 0) || (got.Features[1].State != "observed" && len(got.Observation.LossHistory) != 0) {
				t.Fatal("unavailable input retained for prediction")
			}
			if tc.name == "failure" && got.Observation.LossHistory[0].Value != 100 {
				t.Fatal("failure not counted")
			}
		})
	}
	rows := []history.Observation{
		probe("loss-left", tick.Add(-config.LossWindow), ptr(false), nil),
		probe("old-fail", tick.Add(-config.RTTWindow), ptr(false), nil),
		probe("rtt-left", tick.Add(-config.RTTWindow), ptr(true), ptr(60000.0)),
		probe("unknown-old", tick.Add(-2200*time.Millisecond), nil, nil),
		probe("good-old", tick.Add(-2100*time.Millisecond), ptr(true), ptr(5.0)),
		probe("now", tick, ptr(true), ptr(2.0)),
	}
	got, err := BuildProbes(scope, rows, tick, config)
	if err != nil {
		t.Fatal(err)
	}
	if got.Features[0].InputCount != 3 || got.Features[1].InputCount != 5 || got.Features[0].UnknownCount != 1 || got.Features[1].UnknownCount != 1 {
		t.Fatalf("window counts: %+v", got.Features)
	}
	if len(got.Observation.RTTHistory) != 2 || len(got.Observation.LossHistory) != 2 || got.Observation.LossHistory[0].Value != 50 {
		t.Fatalf("window/bucket boundaries: %+v", got.Observation)
	}
}

func TestRejectAmbiguousOrInvalidInput(t *testing.T) {
	valid := probe("sample", tick, ptr(true), ptr(1.0))
	for _, tc := range []struct {
		name string
		edit func(*history.Observation)
	}{
		{"different source", func(o *history.Observation) { o.Source = "cli-ping" }},
		{"different peer", func(o *history.Observation) { o.PeerID = "other" }},
		{"different path", func(o *history.Observation) { o.Path = "relay" }},
		{"different relay", func(o *history.Observation) { o.RelayID = "other" }},
		{"different uplink", func(o *history.Observation) { o.Uplink = "lte" }},
		{"future nanos", func(o *history.Observation) { o.Timestamp = tick.Add(time.Nanosecond) }},
		{"zero timestamp", func(o *history.Observation) { o.Timestamp = time.Time{} }},
		{"nan", func(o *history.Observation) { o.RTTMs = ptr(math.NaN()) }},
		{"infinite", func(o *history.Observation) { o.RTTMs = ptr(math.Inf(1)) }},
		{"negative", func(o *history.Observation) { o.RTTMs = ptr(-1.0) }},
		{"out of range", func(o *history.Observation) { o.RTTMs = ptr(60001.0) }},
		{"unknown with rtt", func(o *history.Observation) { o.Success = nil; o.Validity = "unknown"; o.Reason = "missing" }},
		{"empty id", func(o *history.Observation) { o.ID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := valid
			tc.edit(&o)
			if _, err := BuildProbes(scope, []history.Observation{o}, tick, config); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted invalid row: %v", err)
			}
		})
	}
	conflict := valid
	conflict.RTTMs = ptr(2.0)
	if _, err := BuildProbes(scope, []history.Observation{valid, conflict}, tick, config); !errors.Is(err, history.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := BuildProbes(scope, make([]history.Observation, MaxSamples+1), tick, config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded input: %v", err)
	}
	for _, cfg := range []Config{{}, {RTTWindow: MaxWindow + 1, LossWindow: MaxWindow, Bucket: time.Second, MaxAge: time.Second}, {RTTWindow: time.Second, LossWindow: time.Second, Bucket: 2 * time.Second, MaxAge: time.Second}, {RTTWindow: time.Second, LossWindow: time.Second, Bucket: time.Second, MaxAge: 2 * time.Second}} {
		if _, err := BuildProbes(scope, nil, tick, cfg); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid config accepted: %+v %v", cfg, err)
		}
	}
	badScope := scope
	badScope.NodeID = ""
	if _, err := BuildProbes(badScope, nil, tick, config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid empty scope accepted: %v", err)
	}
}

func TestReadTimeDoesNotInventMeasurements(t *testing.T) {
	rows := []history.Observation{probe("one", tick, ptr(true), ptr(1.0))}
	before := append([]history.Observation(nil), rows...)
	first, err := BuildProbes(scope, rows, tick, config)
	if err != nil {
		t.Fatal(err)
	}
	next, err := BuildProbes(scope, rows, tick.Add(time.Second), config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Observation.RTTHistory, next.Observation.RTTHistory) || !reflect.DeepEqual(first.Observation.LossHistory, next.Observation.LossHistory) {
		t.Fatal("reading created synthetic samples")
	}
	expired, err := BuildProbes(scope, rows, tick.Add(config.MaxAge), config)
	if err != nil || expired.Ready || *expired.Features[0].AgeNS != int64(config.MaxAge) {
		t.Fatalf("reading extended age: %+v %v", expired, err)
	}
	if !reflect.DeepEqual(rows, before) {
		t.Fatal("builder mutated input")
	}
}

func TestMaximumBoundedHistory(t *testing.T) {
	cfg := Config{RTTWindow: MaxWindow, LossWindow: MaxWindow, Bucket: time.Millisecond, MaxAge: time.Second}
	rows := make([]history.Observation, MaxSamples)
	for i := range rows {
		rows[i] = probe(fmt.Sprint(i), tick.Add(-time.Duration(MaxSamples-1-i)*100*time.Millisecond), ptr(true), ptr(float64(i)))
	}
	got, err := BuildProbes(scope, rows, tick, cfg)
	if err != nil || !got.Ready || len(got.Observation.RTTHistory) != MaxSamples || len(got.Observation.LossHistory) != MaxSamples {
		t.Fatalf("bounded full window: %v", err)
	}
	random := rand.New(rand.NewSource(29))
	for i := 0; i < 8; i++ {
		random.Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
		again, err := BuildProbes(scope, rows, tick, cfg)
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("permutation %d differs: %v", i, err)
		}
	}
}

func FuzzBuildProbes(f *testing.F) {
	f.Add([]byte{0, 1, 5, 4, 2, 7, 10, 3, 100})
	f.Add([]byte{0, 0, 0, 0, 1, 0, 0, 2, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 384 {
			return
		}
		var rows []history.Observation
		for i := 0; i+2 < len(data); i += 3 {
			at := tick.Add(time.Duration(int(data[i])-200) * time.Millisecond)
			success := ptr(data[i+1]%3 == 0)
			rtt := ptr(float64(data[i+2]))
			if !*success {
				rtt = nil
			}
			if data[i+1]%3 == 2 {
				success = nil
			}
			rows = append(rows, probe(fmt.Sprint(i), at, success, rtt))
		}
		got, err := BuildProbes(scope, rows, tick, config)
		slices.Reverse(rows)
		again, err2 := BuildProbes(scope, rows, tick, config)
		if (err == nil) != (err2 == nil) {
			t.Fatal("order changed validity")
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(got, again) {
			t.Fatal("order changed output")
		}
		for _, series := range [][]predictor.Sample{got.Observation.RTTHistory, got.Observation.LossHistory} {
			for i, s := range series {
				if s.At.After(tick) || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || i > 0 && !series[i-1].At.Before(s.At) {
					t.Fatalf("invalid measured sample: %+v", s)
				}
			}
		}
	})
}

func TestMovingWindowCannotInventZeroLoss(t *testing.T) {
	cfg := Config{RTTWindow: 11 * time.Second, LossWindow: 11 * time.Second, Bucket: 5 * time.Second, MaxAge: 11 * time.Second}
	for _, unknown := range []bool{false, true} {
		var outcome *bool
		if !unknown {
			outcome = ptr(false)
		}
		rows := []history.Observation{probe("old", tick.Add(-9800*time.Millisecond), outcome, nil), probe("good", tick.Add(-9600*time.Millisecond), ptr(true), ptr(5.0))}
		first, err := BuildProbes(scope, rows, tick, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !unknown && first.Observation.LossHistory[0].Value != 50 {
			t.Fatal("missing original completed failure")
		}
		next, err := BuildProbes(scope, rows, tick.Add(1300*time.Millisecond), cfg)
		if err != nil {
			t.Fatal(err)
		}
		// The whole bucket is excluded at equality too; dropping a sample at
		// the exclusive lower edge must not change a previously emitted ratio.
		equal, err := BuildProbes(scope, rows, tick.Add(time.Second), cfg)
		if err != nil || equal.Observation.Known[1] {
			t.Fatalf("partial bucket admitted at the exclusive edge: %+v %v", equal, err)
		}
		if next.Observation.Known[1] || len(next.Observation.LossHistory) > 0 {
			t.Fatalf("left-edge removal fabricated healthy loss without new data: %+v", next)
		}
	}
}
