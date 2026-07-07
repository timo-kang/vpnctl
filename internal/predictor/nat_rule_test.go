// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"testing"
	"time"
)

func TestNATRule_QuietWindowStable(t *testing.T) {
	n := NewNATRule(2*time.Second, nil, DefaultNATRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
	}
	f, err := n.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalNATStability] < 0.99 {
		t.Errorf("quiet stability = %v, want >= 0.99", f.Q[SignalNATStability])
	}
}

func TestNATRule_RemapDropsStability(t *testing.T) {
	n := NewNATRule(2*time.Second, nil, DefaultNATRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		RecentNATRemaps: []time.Time{
			now.Add(-1 * time.Second),
			now.Add(-2 * time.Second),
		},
	}
	f, err := n.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalNATStability] > 0.01 {
		t.Errorf("two-remap stability = %v, want ~0", f.Q[SignalNATStability])
	}
}

func TestNATRule_OldRemapsIgnored(t *testing.T) {
	n := NewNATRule(2*time.Second, nil, DefaultNATRuleParams)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		RecentNATRemaps: []time.Time{
			now.Add(-10 * time.Second), // outside 5 s window
		},
	}
	f, err := n.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalNATStability] < 0.99 {
		t.Errorf("old-remap stability = %v, want >= 0.99", f.Q[SignalNATStability])
	}
}

func TestNATRule_HandoffCouplingLowersStability(t *testing.T) {
	// Compose a HandoffRule that will report high handoff_prob.
	h := NewHandoffRule(2*time.Second, DefaultHandoffRuleParams)
	n := NewNATRule(2*time.Second, h, DefaultNATRuleParams)

	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 30}},
		BandwidthLast: Sample{At: now, Value: 20},
		Cell: CellInfo{
			CellID: "0x001",
			RSRP:   -115, // triggers high handoff_prob from HandoffRule
		},
	}
	f, err := n.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Handoff coupling of 0.5 with handoff_prob ~0.9 → stability ~0.55.
	if f.Q[SignalNATStability] > 0.7 {
		t.Errorf("stability under high handoff = %v, want <= 0.7", f.Q[SignalNATStability])
	}
	// The composed HandoffRule's handoff_prob should also flow through.
	if f.Q[SignalHandoffProb] < 0.7 {
		t.Errorf("composed handoff_prob = %v, want >= 0.7", f.Q[SignalHandoffProb])
	}
}
