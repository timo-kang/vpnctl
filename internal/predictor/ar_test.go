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

func TestAR2RTT_UpdateRejectsNaNInf(t *testing.T) {
	p := NewAR2RTT(1*time.Second, 300)

	// Seed with enough clean samples for the buffer to be near-refit.
	for i := 0; i < 30; i++ {
		p.Update(40, 40, 45)
	}
	p.mu.Lock()
	a0, b0, c0 := p.a, p.b, p.c
	p.mu.Unlock()

	// Poison attempts.
	p.Update(math.NaN(), 40, 45)
	p.Update(40, math.Inf(1), 45)
	p.Update(40, 40, math.Inf(-1))

	p.mu.Lock()
	a1, b1, c1 := p.a, p.b, p.c
	p.mu.Unlock()

	// Coefficients unchanged (no refit triggered by rejected samples).
	if a0 != a1 || b0 != b1 || c0 != c1 {
		t.Errorf("poison samples affected coefficients: (%v,%v,%v) → (%v,%v,%v)",
			a0, b0, c0, a1, b1, c1)
	}

	// Predictor still works on a clean input after poison.
	now := time.Now()
	obs := Observation{
		Now: now,
		RTTHistory: []Sample{
			{At: now.Add(-100 * time.Millisecond), Value: 40},
			{At: now, Value: 45},
		},
		BandwidthLast: Sample{At: now, Value: 5},
	}
	f, err := p.Predict(context.Background(), obs)
	if err != nil {
		t.Fatalf("post-poison predict: %v", err)
	}
	if math.IsNaN(f.Q[SignalRTT]) || math.IsInf(f.Q[SignalRTT], 0) {
		t.Errorf("post-poison forecast is not finite: %v", f.Q[SignalRTT])
	}
}

func TestAR2RTT_RefitIntervalWithNonMultipleWindow(t *testing.T) {
	// windowSize = 25 is not a multiple of 10; verify that refit
	// still triggers on exact 10-sample cadence via the dedicated
	// counter (the previous bufIndex%10 gate would fire irregularly
	// around the wrap-around).
	p := NewAR2RTT(1*time.Second, 25)

	// Use well-conditioned data (x1 ≠ x2) so the OLS refit is not
	// singular; the design is to verify the counter, not the fit
	// quality.
	seed := seededDeterministicRNG()
	feedOne := func() {
		x1 := 30 + 20*seed()
		x2 := 30 + 20*seed()
		y := 0.7*x1 + 0.2*x2 + 3
		p.Update(x1, x2, y)
	}

	// Fill 19 samples to leave filled()=19 < 20 (no refits possible
	// yet).
	for i := 0; i < 19; i++ {
		feedOne()
	}
	p.mu.Lock()
	if p.updatesSinceRefit != 0 {
		t.Errorf("counter should stay 0 while filled() < 20; got %d", p.updatesSinceRefit)
	}
	p.mu.Unlock()

	// Now feed exactly 10 more samples. Update 20 crosses the
	// threshold (counter → 1); updates 21–28 take counter to 9;
	// update 29 takes counter to 10, triggers refit, resets to 0.
	for i := 0; i < 10; i++ {
		feedOne()
	}
	p.mu.Lock()
	sinceRefit := p.updatesSinceRefit
	a, b, c := p.a, p.b, p.c
	p.mu.Unlock()
	if sinceRefit != 0 {
		t.Errorf("updatesSinceRefit = %d after refit-triggering 10th post-threshold sample, want 0", sinceRefit)
	}
	// Refit changed coefficients away from the cold-start (1, 0, 0).
	if a == 1 && b == 0 && c == 0 {
		t.Errorf("coefficients unchanged after refit: (%v, %v, %v)", a, b, c)
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
