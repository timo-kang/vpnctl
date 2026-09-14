// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPersistence_EchoesLatestSample(t *testing.T) {
	p := NewPersistence(2 * time.Second)
	now := time.Now()
	obs := Observation{
		Now: now,
		RTTHistory: []Sample{
			{At: now.Add(-100 * time.Millisecond), Value: 40},
			{At: now, Value: 55},
		},
		LossHistory:   []Sample{{At: now, Value: 1.2}},
		BandwidthLast: Sample{At: now.Add(-15 * time.Second), Value: 12.5},
	}
	f, err := p.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalRTT] != 55 {
		t.Errorf("q[RTT] = %v, want 55", f.Q[SignalRTT])
	}
	if f.Q[SignalLoss] != 1.2 {
		t.Errorf("q[Loss] = %v, want 1.2", f.Q[SignalLoss])
	}
	if f.Q[SignalBandwidth] != 12.5 {
		t.Errorf("q[BW] = %v, want 12.5", f.Q[SignalBandwidth])
	}
	if f.PredictorName != "persistence" {
		t.Errorf("PredictorName = %q, want persistence", f.PredictorName)
	}
	for i := 0; i < SignalCount; i++ {
		if f.Health[i] != 0.5 {
			t.Errorf("Health[%d] = %v, want 0.5", i, f.Health[i])
		}
	}
}

func TestPersistence_ReturnsErrorOnEmptyObservation(t *testing.T) {
	p := NewPersistence(2 * time.Second)
	_, err := p.Predict(context.Background(), Observation{Now: time.Now()})
	if !errors.Is(err, ErrObservationInvalid) {
		t.Errorf("err = %v, want ErrObservationInvalid", err)
	}
}

func TestPersistence_ClampsProbabilities(t *testing.T) {
	p := NewPersistence(2 * time.Second)
	now := time.Now()
	obs := Observation{
		Now:           now,
		RTTHistory:    []Sample{{At: now, Value: 10}},
		BandwidthLast: Sample{At: now, Value: 5},
		RecentHandoffs: []time.Time{
			now.Add(-1 * time.Second),
			now.Add(-2 * time.Second),
		},
	}
	f, err := p.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.QHi[SignalHandoffProb] > 1.0 {
		t.Errorf("QHi[handoff] = %v, want <= 1.0", f.QHi[SignalHandoffProb])
	}
	if f.QLo[SignalHandoffProb] < 0.0 {
		t.Errorf("QLo[handoff] = %v, want >= 0.0", f.QLo[SignalHandoffProb])
	}
	if f.QLo[SignalNATStability] < 0.0 || f.QHi[SignalNATStability] > 1.0 {
		t.Errorf("nat CI out of range: [%v, %v]", f.QLo[SignalNATStability], f.QHi[SignalNATStability])
	}
}

func TestPersistence_ReadyAlwaysTrue(t *testing.T) {
	p := NewPersistence(0) // 0 falls back to default
	if !p.Ready() {
		t.Error("Ready() = false, want true")
	}
	if p.Horizon() != 2*time.Second {
		t.Errorf("Horizon() = %v, want 2s", p.Horizon())
	}
}
