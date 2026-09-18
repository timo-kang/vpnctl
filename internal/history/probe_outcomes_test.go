// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestUnknownOutcomesDenominatorsSourcesAndReplay(t *testing.T) {
	s, now := newStore(t)
	unavailable := Observation{ID: "unknown", Timestamp: now, PeerID: "peer", Path: "relay", RelayID: "controller", Uplink: "wlan0", Validity: "unknown", Reason: "collector_unavailable"}
	samples := []Observation{obs("success", now.Add(-2*time.Second), pointer(12.)), obs("failure", now.Add(-time.Second), nil), unavailable}
	// Reverse arrival and replay must produce the same measurement and history.
	ingest(t, s, "robot", []Observation{samples[2]}, now)
	ingest(t, s, "robot", samples, now)
	b := query(t, s, now)[3]
	if b.Count != 2 || b.Successes != 1 || b.UnknownCount != 1 || *b.AvgRTTMs != 12 || *b.AvailabilityPct != 50 || *b.LossPct != 50 {
		t.Fatal(b)
	}
	q := s.Latest(now)["robot"][0]
	if q.Quality != "unknown" || q.SampleCount != 0 || q.RTTMs != nil || q.LossPct != nil || q.Validity != "unknown" || q.Reason != "collector_unavailable" || q.LastSuccessAt == nil {
		t.Fatal(q)
	}
	other := unavailable
	other.Source = "monitor-overlay"
	other.ID = "candidate"
	ingest(t, s, "robot", []Observation{other}, now)
	if len(s.Latest(now)["robot"]) != 2 {
		t.Fatal("sources share history")
	}
	before := s.Latest(now)
	restart, err := Open(s.path, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, restart.Latest(now)) {
		t.Fatal("restart changed unknown state")
	}
	for _, change := range []func(*Observation){func(o *Observation) { o.Reason = "invalid_probe_target" }, func(o *Observation) { o.Success = pointer(false); o.Validity = "observed" }, func(o *Observation) { o.Timestamp = now.Add(-time.Second) }} {
		altered := unavailable
		change(&altered)
		if err := s.Ingest(context.Background(), "robot", []Observation{altered}, now); !errors.Is(err, ErrConflict) {
			t.Fatal("modified retry accepted", err)
		}
	}
	if !reflect.DeepEqual(before, s.Latest(now)) {
		t.Fatal("failed retry published")
	}
}

func TestAllUnknownAndAllFailureHaveDifferentNullSemantics(t *testing.T) {
	for _, unknown := range []bool{true, false} {
		t.Run(map[bool]string{true: "unknown", false: "failure"}[unknown], func(t *testing.T) {
			s, now := newStore(t)
			o := obs("outcome", now, nil)
			if unknown {
				o.Success = nil
				o.Validity = "unknown"
				o.Reason = "invalid_probe_target"
			}
			ingest(t, s, "robot", []Observation{o}, now)
			bs := query(t, s, now)
			b := bs[3]
			if b.AvgRTTMs != nil || b.P95RTTMs != nil || b.Successes != 0 {
				t.Fatal(b)
			}
			if unknown && (b.Count != 0 || b.UnknownCount != 1 || b.AvailabilityPct != nil || b.LossPct != nil) {
				t.Fatal(b)
			}
			if !unknown && (b.Count != 1 || b.UnknownCount != 0 || *b.AvailabilityPct != 0 || *b.LossPct != 100) {
				t.Fatal(b)
			}
			if bs[0].Count != 0 || bs[0].UnknownCount != 0 || bs[0].AvailabilityPct != nil {
				t.Fatal("empty bucket changed")
			}
		})
	}
}

func TestCandidateSuccessCannotAdvertiseHealthyVPN(t *testing.T) {
	s, now := newStore(t)
	for i := 0; i < 3; i++ {
		o := obs(string(rune('a'+i)), now.Add(time.Duration(i-3)*time.Second), pointer(1.))
		o.Source = "agent-direct"
		o.Path, o.RelayID = "direct", ""
		ingest(t, s, "robot", []Observation{o}, now)
	}
	m := s.Latest(now)["robot"][0]
	if m.Quality != "unknown" || m.ErrorReason != "candidate_probe_only" || m.Validity != "observed" || m.SampleCount != 3 || *m.RTTMs != 1 {
		t.Fatal(m)
	}
	if m = s.Latest(now.Add(17 * time.Second))["robot"][0]; !m.Stale || m.Quality != "unknown" {
		t.Fatal(m)
	}
}

func TestUnknownValidationAndCapacityUseRawRows(t *testing.T) {
	s, now := newStore(t)
	valid := Observation{ID: "u", Timestamp: now, PeerID: "peer", Path: "unknown", Validity: "unknown", Reason: "discovery_failed"}
	for _, change := range []func(*Observation){func(o *Observation) { o.Validity = "" }, func(o *Observation) { o.Reason = "" }, func(o *Observation) { o.RTTMs = pointer(0.) }, func(o *Observation) { o.Source = "other" }, func(o *Observation) { o.Reason = "spoof\nline" }, func(o *Observation) { o.Timestamp = now.Add(time.Hour) }, func(o *Observation) { o.Success = pointer(false) }} {
		bad := valid
		change(&bad)
		if err := s.Ingest(context.Background(), "robot", []Observation{bad}, now); !errors.Is(err, ErrInvalid) {
			t.Fatal(bad, err)
		}
	}
	ingest(t, s, "robot", []Observation{valid}, now)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows int
	if err = db.QueryRow("SELECT row_count FROM metadata").Scan(&rows); err != nil || rows != 1 {
		t.Fatal(rows, err)
	}
	if _, err = db.Exec("UPDATE metadata SET row_count=?", MaxRows); err != nil {
		t.Fatal(err)
	}
	valid.ID = "excess"
	if err = s.Ingest(context.Background(), "robot", []Observation{valid}, now); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if query(t, s, now)[3].UnknownCount != 1 {
		t.Fatal("overflow committed")
	}
}
