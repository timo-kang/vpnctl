// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictorinput

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/predictor"
)

var tick = time.Unix(1700000040, 0).UTC()
var scope = history.Stream{Source: "monitor-overlay", NodeID: "robot", PeerID: "peer", Path: "unknown"}
var config = Config{RTTWindow: 10 * time.Second, LossWindow: 30 * time.Second, Bucket: time.Second, MaxAge: 5 * time.Second}

func probe(id string, at time.Time, success *bool, rtt *float64) history.Observation {
	o := history.Observation{ID: id, Source: scope.Source, PeerID: scope.PeerID, Path: scope.Path, Timestamp: at, Success: success, RTTMs: rtt}
	if success == nil {
		o.Validity, o.Reason = "unknown", "collector_unavailable"
	}
	return o
}
func ptr[T any](v T) *T { return &v }

func TestMeasuredProbeInputAndReplay(t *testing.T) {
	rows := []history.Observation{
		probe("a", tick.Add(-2200*time.Millisecond), ptr(true), ptr(12.0)),
		probe("b", tick.Add(-1700*time.Millisecond), ptr(false), nil),
		probe("c", tick.Add(-1100*time.Millisecond), ptr(true), ptr(0.0)),
	}
	got, err := BuildProbes(scope, rows, tick, config)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Ready || got.Reason != "" || got.Observation.Known == nil {
		t.Fatalf("not ready: %+v", got)
	}
	if !reflect.DeepEqual(got.Observation.RTTHistory, []predictor.Sample{{At: rows[0].Timestamp, Value: 12}, {At: rows[2].Timestamp, Value: 0}}) {
		t.Fatalf("RTT: %+v", got.Observation.RTTHistory)
	}
	if !reflect.DeepEqual(got.Observation.LossHistory, []predictor.Sample{{At: rows[0].Timestamp, Value: 0}, {At: rows[2].Timestamp, Value: 50}}) {
		t.Fatalf("probe failure ratio: %+v", got.Observation.LossHistory)
	}
	for i := 0; i < predictor.SignalCount; i++ {
		if got.Observation.Known[i] != (i < 2) {
			t.Fatalf("invented signal %d: %+v", i, got.Features)
		}
		if i >= 2 && (got.Features[i].State != "missing" || got.Features[i].Reason != "not_collected" || got.Features[i].AgeNS != nil) {
			t.Fatalf("missing evidence %d: %+v", i, got.Features[i])
		}
	}
	replay, err := BuildProbes(scope, []history.Observation{rows[2], rows[0], rows[1], rows[0]}, tick, config)
	if err != nil || !reflect.DeepEqual(got, replay) {
		t.Fatalf("reordered/idempotent replay differs: %v", err)
	}
	f, err := predictor.NewPersistence(time.Second).Predict(context.Background(), got.Observation)
	if err != nil || f.Q[predictor.SignalLoss] != 50 || f.Q[predictor.SignalRTT] != 0 || f.Health[predictor.SignalRTT] <= 0 || f.Health[predictor.SignalNATStability] != 0 {
		t.Fatalf("measured predictor: %+v %v", f, err)
	}
	if got.Features[0].Source != scope.Source || *got.Features[0].AgeNS != int64(1100*time.Millisecond) {
		t.Fatalf("lost provenance: %+v", got.Features[0])
	}
	// Results must not share input pointers or storage with another build.
	rows[2].RTTMs = ptr(99.0)
	got.Observation.RTTHistory[0].Value = 777
	got.Observation.Known[0] = false
	if replay.Observation.RTTHistory[0].Value != 12 || !replay.Observation.Known[0] {
		t.Fatal("result aliases another build")
	}
}

func TestCanonicalInputIsDetached(t *testing.T) {
	stream := scope
	stream.Source = "legacy-probe"
	rows := []history.Observation{probe("b", tick, ptr(true), ptr(2.0)), probe("a", tick.Add(-time.Second), ptr(true), ptr(1.0))}
	for i := range rows {
		rows[i].Source = ""
		rows[i].Timestamp = rows[i].Timestamp.In(time.FixedZone("fixture", 9*3600))
	}
	before, _ := json.Marshal(rows)
	got, err := BuildProbes(stream, rows, tick, config)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(rows)
	if string(before) != string(after) {
		t.Fatal("canonicalization or sorting mutated caller data")
	}
	*rows[0].RTTMs = 100
	if got.Observation.RTTHistory[len(got.Observation.RTTHistory)-1].Value != 2 {
		t.Fatal("output borrowed source scalar")
	}
	if got.Features[0].Source != "legacy-probe" || got.Features[0].ObservedAt.Location() != time.UTC {
		t.Fatalf("canonical provenance lost: %+v", got.Features[0])
	}
}
