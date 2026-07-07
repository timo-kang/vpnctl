// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestAR2RTT_ColdStartMatchesPersistence(t *testing.T) {
	p := NewAR2RTT(2*time.Second, 300)
	now := time.Now()
	obs := Observation{
		Now: now,
		RTTHistory: []Sample{
			{At: now.Add(-100 * time.Millisecond), Value: 40},
			{At: now, Value: 45},
		},
		BandwidthLast: Sample{At: now, Value: 10},
	}
	f, err := p.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Cold-start AR(2) coefficients (a=1, b=0, c=0) mean forecast
	// equals the most recent RTT sample.
	if math.Abs(f.Q[SignalRTT]-45) > 1e-9 {
		t.Errorf("cold-start Q[RTT] = %v, want 45", f.Q[SignalRTT])
	}
}

func TestAR2RTT_LearnsLinearTrend(t *testing.T) {
	p := NewAR2RTT(1*time.Second, 300)

	// Feed a linear-trend dataset: RTT(t+Δ) = 0.5 * RTT(t) + 0.5 * RTT(t-1) + 5.
	// This should be recovered exactly (up to numerical precision) by OLS.
	rng := seededDeterministicRNG()
	for i := 0; i < 200; i++ {
		x1 := 40 + 10*rng()
		x2 := 40 + 10*rng()
		y := 0.5*x1 + 0.5*x2 + 5.0
		p.Update(x1, x2, y)
	}

	p.mu.Lock()
	a, b, c := p.a, p.b, p.c
	p.mu.Unlock()

	if math.Abs(a-0.5) > 0.05 {
		t.Errorf("learned a = %v, want ~0.5", a)
	}
	if math.Abs(b-0.5) > 0.05 {
		t.Errorf("learned b = %v, want ~0.5", b)
	}
	if math.Abs(c-5.0) > 1.0 {
		t.Errorf("learned c = %v, want ~5", c)
	}
}

func TestAR2RTT_PredictUsesRecentHistory(t *testing.T) {
	p := NewAR2RTT(1*time.Second, 300)
	// Force a known linear coefficient by direct assignment to avoid
	// fit-noise from small samples.
	p.mu.Lock()
	p.a, p.b, p.c = 0.8, 0.2, 0
	p.residualStd = 5
	p.mu.Unlock()

	now := time.Now()
	obs := Observation{
		Now: now,
		RTTHistory: []Sample{
			{At: now.Add(-100 * time.Millisecond), Value: 50},
			{At: now, Value: 100},
		},
		BandwidthLast: Sample{At: now, Value: 5},
	}
	f, err := p.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := 0.8*100 + 0.2*50 + 0
	if math.Abs(f.Q[SignalRTT]-want) > 1e-9 {
		t.Errorf("Q[RTT] = %v, want %v", f.Q[SignalRTT], want)
	}
}

func TestAR2RTT_NegativeForecastClampedToZero(t *testing.T) {
	p := NewAR2RTT(1*time.Second, 300)
	p.mu.Lock()
	p.a, p.b, p.c = -1, 0, -50
	p.residualStd = 5
	p.mu.Unlock()

	now := time.Now()
	obs := Observation{
		Now: now,
		RTTHistory: []Sample{
			{At: now.Add(-100 * time.Millisecond), Value: 10},
			{At: now, Value: 20},
		},
		BandwidthLast: Sample{At: now, Value: 5},
	}
	f, err := p.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Q[SignalRTT] < 0 {
		t.Errorf("Q[RTT] = %v, want >= 0 (clamped)", f.Q[SignalRTT])
	}
	if f.QLo[SignalRTT] < 0 {
		t.Errorf("QLo[RTT] = %v, want >= 0 (clamped)", f.QLo[SignalRTT])
	}
}

// seededDeterministicRNG returns a deterministic pseudo-random generator
// producing values in [0, 1). Uses a linear congruential generator seeded
// with a fixed value so test runs are reproducible without depending on
// math/rand's default source.
func seededDeterministicRNG() func() float64 {
	s := uint64(0xDEADBEEF)
	return func() float64 {
		s = s*6364136223846793005 + 1442695040888963407
		return float64(s>>32) / float64(1<<32)
	}
}
