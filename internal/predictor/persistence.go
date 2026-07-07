// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"time"
)

// Persistence is the naive predictor that forecasts q̂(t+Δ) = q(t)
// verbatim: the current observation is echoed as the prediction with a
// broad confidence interval reflecting the absence of any real
// modelling. It corresponds to the NoOp / persistence baseline used in
// the B0/B1 controllers per baselines-execution.md §3.1–§3.2.
//
// Persistence is always Ready() as soon as it has seen a single
// Observation with a populated RTT history. Its self-reported health is
// constant at 0.5 — high enough to be useful, low enough to signal
// "no meaningful model applied here." When the state machine's health
// gate is set at 0.3 (predictor-design §6.2), Persistence forecasts
// pass; when the gate is raised for stricter operation, Persistence
// is filtered out first.
type Persistence struct {
	horizon time.Duration
}

// NewPersistence constructs a Persistence predictor with the given
// prediction horizon. Pass 2 * time.Second for the default per
// state-machine-spec §2.
func NewPersistence(horizon time.Duration) *Persistence {
	if horizon <= 0 {
		horizon = 2 * time.Second
	}
	return &Persistence{horizon: horizon}
}

// Name implements Predictor.
func (p *Persistence) Name() string { return "persistence" }

// Horizon implements Predictor.
func (p *Persistence) Horizon() time.Duration { return p.horizon }

// Ready reports true unconditionally: Persistence has no warmup phase.
// The Predict call will still return ErrObservationInvalid if the
// input is empty, so downstream code cannot mistake unready output.
func (p *Persistence) Ready() bool { return true }

// Predict returns a Forecast that copies the current observation into
// each signal's point estimate, with a symmetric confidence interval of
// ±25% around the point (a coarse default reflecting the absence of
// modelling), and constant health 0.5.
func (p *Persistence) Predict(_ context.Context, obs Observation) (Forecast, error) {
	if len(obs.RTTHistory) == 0 && len(obs.LossHistory) == 0 && obs.BandwidthLast.At.IsZero() {
		return Forecast{}, ErrObservationInvalid
	}

	rtt := lastValue(obs.RTTHistory)
	loss := lastValue(obs.LossHistory)
	bw := obs.BandwidthLast.Value
	handoff := estimateHandoffFromHistory(obs)
	nat := estimateNATFromHistory(obs)

	q := [SignalCount]float64{rtt, loss, bw, handoff, nat}

	f := Forecast{
		Horizon:       p.horizon,
		Q:             q,
		PredictorName: p.Name(),
		ComputedAt:    obs.Now,
	}
	for i := 0; i < SignalCount; i++ {
		f.QLo[i] = q[i] * 0.75
		f.QHi[i] = q[i] * 1.25
		f.Health[i] = 0.5
	}
	// Probability-valued signals are clamped to [0, 1].
	f.QLo[SignalHandoffProb] = clamp(f.QLo[SignalHandoffProb], 0, 1)
	f.QHi[SignalHandoffProb] = clamp(f.QHi[SignalHandoffProb], 0, 1)
	f.QLo[SignalNATStability] = clamp(f.QLo[SignalNATStability], 0, 1)
	f.QHi[SignalNATStability] = clamp(f.QHi[SignalNATStability], 0, 1)
	return f, nil
}

// lastValue returns the value of the most recent sample or 0 if the
// history is empty.
func lastValue(hist []Sample) float64 {
	if len(hist) == 0 {
		return 0
	}
	return hist[len(hist)-1].Value
}

// estimateHandoffFromHistory returns a crude proxy for handoff
// probability: 1.0 if any handoff was observed in the last 5 s, else 0.
// Real handoff prediction lives in HandoffRule; this stub keeps
// Persistence self-contained.
func estimateHandoffFromHistory(obs Observation) float64 {
	if len(obs.RecentHandoffs) == 0 {
		return 0
	}
	cutoff := obs.Now.Add(-5 * time.Second)
	for _, t := range obs.RecentHandoffs {
		if t.After(cutoff) {
			return 1.0
		}
	}
	return 0
}

// estimateNATFromHistory returns a crude proxy for NAT stability:
// 1.0 if no remap has been observed in the last 5 s, decreasing
// linearly with the count observed. See NATRule for the real definition.
func estimateNATFromHistory(obs Observation) float64 {
	if len(obs.RecentNATRemaps) == 0 {
		return 1.0
	}
	cutoff := obs.Now.Add(-5 * time.Second)
	count := 0
	for _, t := range obs.RecentNATRemaps {
		if t.After(cutoff) {
			count++
		}
	}
	if count == 0 {
		return 1.0
	}
	stability := 1.0 - float64(count)/2.0
	return clamp(stability, 0, 1)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
