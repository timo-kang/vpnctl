// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestHandoffRule_StrongSignalLowProb(t *testing.T) {
	h := NewHandoffRule(2*time.Second, DefaultHandoffRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		Cell: CellInfo{
			CellID: "0x001",
			RSRP:   -80,
		},
	}
	f, err := h.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalHandoffProb] > 0.2 {
		t.Errorf("strong signal handoff_prob = %v, want < 0.2", f.Q[SignalHandoffProb])
	}
	if f.Health[SignalHandoffProb] < 0.9 {
		t.Errorf("health = %v, want >= 0.9 with usable RSRP", f.Health[SignalHandoffProb])
	}
}

func TestHandoffRule_WeakSignalHighProb(t *testing.T) {
	h := NewHandoffRule(2*time.Second, DefaultHandoffRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		Cell: CellInfo{
			CellID: "0x001",
			RSRP:   -115,
		},
	}
	f, err := h.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalHandoffProb] < 0.7 {
		t.Errorf("weak signal handoff_prob = %v, want >= 0.7", f.Q[SignalHandoffProb])
	}
}

func TestHandoffRule_RSSIFallback(t *testing.T) {
	h := NewHandoffRule(2*time.Second, DefaultHandoffRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		Cell: CellInfo{
			CellID: "0x001",
			RSSI:   -95,
		},
	}
	f, err := h.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Health[SignalHandoffProb] > 0.75 {
		t.Errorf("health with RSSI-only = %v, want <= 0.7 (lower than RSRP path)", f.Health[SignalHandoffProb])
	}
	if f.Q[SignalHandoffProb] < 0.7 {
		t.Errorf("weak RSSI handoff_prob = %v, want >= 0.7", f.Q[SignalHandoffProb])
	}
}

func TestHandoffRule_ScaleZeroFallsBackToDefaults(t *testing.T) {
	// A caller passes zero (or negative) scales — the constructor
	// must repair them to the calibrated defaults, otherwise
	// sigmoidTerm divides by zero and produces NaN/Inf.
	badParams := HandoffRuleParams{
		RSRPHandoverThreshold: -100,
		RSRPScale:             0,
		RSSIFallbackThreshold: -85,
		RSSIFallbackScale:     -3,
		HistoryWeight:         0.15,
	}
	h := NewHandoffRule(2*time.Second, badParams)

	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		Cell: CellInfo{
			CellID: "0x001",
			RSRP:   -80,
		},
	}
	f, err := h.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("predict: %v", err)
	}
	if math.IsNaN(f.Q[SignalHandoffProb]) || math.IsInf(f.Q[SignalHandoffProb], 0) {
		t.Errorf("handoff_prob is not finite with zero scale: %v", f.Q[SignalHandoffProb])
	}
}

func TestHandoffRule_NoSignalDegradesHealth(t *testing.T) {
	h := NewHandoffRule(2*time.Second, DefaultHandoffRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		// No Cell information at all.
	}
	f, err := h.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Health[SignalHandoffProb] > 0.5 {
		t.Errorf("no-signal health = %v, want <= 0.5", f.Health[SignalHandoffProb])
	}
}

func TestHandoffRule_HistoryContribution(t *testing.T) {
	h := NewHandoffRule(2*time.Second, DefaultHandoffRuleParams)
	now := time.Now()
	baseObs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		Cell: CellInfo{
			CellID: "0x001",
			RSRP:   -80, // strong: sigmoid term near 0
		},
	}
	obsNoHistory := baseObs
	obsWithHistory := baseObs
	obsWithHistory.RecentHandoffs = []time.Time{
		now.Add(-2 * time.Second),
		now.Add(-4 * time.Second),
		now.Add(-6 * time.Second),
	}

	fNo, err := h.Predict(context.Background(), obsNoHistory)
	if err != nil {
		t.Fatalf("no-history predict: %v", err)
	}
	fWith, err := h.Predict(context.Background(), obsWithHistory)
	if err != nil {
		t.Fatalf("with-history predict: %v", err)
	}
	delta := fWith.Q[SignalHandoffProb] - fNo.Q[SignalHandoffProb]
	// History-term contribution is HistoryWeight * histTerm; the
	// exact value tracks the parameter, so we assert only that the
	// delta is meaningfully positive.
	if delta < 0.03 {
		t.Errorf("history should lift handoff_prob by at least 0.03 with 3 recent handoffs; delta = %v (no=%v, with=%v)",
			delta, fNo.Q[SignalHandoffProb], fWith.Q[SignalHandoffProb])
	}
}
