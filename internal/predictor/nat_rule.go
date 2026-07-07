// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"time"
)

// NATRuleParams tunes the rule-based NAT-stability predictor.
type NATRuleParams struct {
	// Window is the look-back window for counting remap events.
	// The nat_stability signal is defined as 1 - min(1, remap/2)
	// over this window; see predictor-design §4.5.
	Window time.Duration

	// RemapAtOne is the number of remap events at which stability
	// bottoms out at 0. Two remaps in the window pins stability at
	// zero by default; increase this if your carrier legitimately
	// remaps more often without breaking connectivity.
	RemapAtZero float64

	// HandoffCoupling is the extent to which a predicted handoff
	// forces a stability decrement, on the empirical observation
	// that CGNAT remaps overwhelmingly co-occur with cell changes.
	// Range [0, 1]: 0 = ignore handoff, 1 = a handoff-probability of
	// 1 unconditionally drops stability to 0.
	HandoffCoupling float64
}

// DefaultNATRuleParams reflects observations from typical Korean
// CGNAT-heavy carriers: 5 s window, cutoff at 2 remaps, moderate
// handoff coupling.
var DefaultNATRuleParams = NATRuleParams{
	Window:          5 * time.Second,
	RemapAtZero:     2,
	HandoffCoupling: 0.5,
}

// NATRule is a rule-based NAT-stability predictor used as the cold-
// start implementation for signal q[4] per predictor-design §4.5.
//
// The prediction uses two independent signals:
//   - The count of recent NAT remap events observed by the vpnctl
//     NAT probe.
//   - The predicted handoff probability, on the observation that
//     CGNAT remaps almost always accompany cell changes.
//
// Both contributions are combined and clamped to [0, 1]. Signals other
// than nat_stability are delegated to the composed Persistence
// baseline; a HandoffRule may be composed upstream to supply the
// coupling term.
type NATRule struct {
	horizon  time.Duration
	baseline *Persistence
	handoff  *HandoffRule
	params   NATRuleParams
}

// NewNATRule constructs a NATRule with the given horizon, handoff
// coupling predictor, and parameters. Pass nil for handoff to disable
// the coupling term (defers entirely to the remap-count rule).
func NewNATRule(horizon time.Duration, handoff *HandoffRule, params NATRuleParams) *NATRule {
	if horizon <= 0 {
		horizon = 2 * time.Second
	}
	if params.Window <= 0 {
		params.Window = 5 * time.Second
	}
	if params.RemapAtZero <= 0 {
		params.RemapAtZero = 2
	}
	return &NATRule{
		horizon:  horizon,
		baseline: NewPersistence(horizon),
		handoff:  handoff,
		params:   params,
	}
}

// Name implements Predictor.
func (n *NATRule) Name() string { return "nat-rule" }

// Horizon implements Predictor.
func (n *NATRule) Horizon() time.Duration { return n.horizon }

// Ready implements Predictor.
func (n *NATRule) Ready() bool { return true }

// Predict computes NAT stability and delegates the remaining signals
// to Persistence. If a handoff predictor is present, its handoff-
// probability term is folded into the stability output via
// HandoffCoupling.
func (n *NATRule) Predict(ctx context.Context, obs Observation) (Forecast, error) {
	base, err := n.baseline.Predict(ctx, obs)
	if err != nil {
		return Forecast{}, err
	}

	stability, health := n.computeStability(ctx, obs)
	base.Q[SignalNATStability] = stability
	base.QLo[SignalNATStability] = clamp(stability-0.15, 0, 1)
	base.QHi[SignalNATStability] = clamp(stability+0.15, 0, 1)
	base.Health[SignalNATStability] = health
	base.PredictorName = n.Name()

	// If a handoff predictor is composed in, adopt its handoff signal
	// as well — this lets a single NATRule instance carry both the
	// handoff and NAT-stability signals for downstream consumers.
	if n.handoff != nil {
		hFcst, hErr := n.handoff.Predict(ctx, obs)
		if hErr == nil {
			base.Q[SignalHandoffProb] = hFcst.Q[SignalHandoffProb]
			base.QLo[SignalHandoffProb] = hFcst.QLo[SignalHandoffProb]
			base.QHi[SignalHandoffProb] = hFcst.QHi[SignalHandoffProb]
			base.Health[SignalHandoffProb] = hFcst.Health[SignalHandoffProb]
		}
	}
	return base, nil
}

// computeStability returns the point estimate + a health self-report.
func (n *NATRule) computeStability(ctx context.Context, obs Observation) (float64, float64) {
	// Remap-count term.
	cutoff := obs.Now.Add(-n.params.Window)
	count := 0
	for _, t := range obs.RecentNATRemaps {
		if t.After(cutoff) {
			count++
		}
	}
	remapTerm := clamp(1.0-float64(count)/n.params.RemapAtZero, 0, 1)

	// Handoff-coupling term.
	handoffTerm := 1.0
	if n.handoff != nil {
		hFcst, hErr := n.handoff.Predict(ctx, obs)
		if hErr == nil {
			hp := hFcst.Q[SignalHandoffProb]
			handoffTerm = 1.0 - n.params.HandoffCoupling*hp
			handoffTerm = clamp(handoffTerm, 0, 1)
		}
	}

	// Combined stability is the minimum: whichever term believes the
	// network is more unstable wins.
	stability := remapTerm
	if handoffTerm < stability {
		stability = handoffTerm
	}

	// Health: high if we have either a fresh remap-history buffer
	// or a working handoff coupling; low if both are missing.
	health := 1.0
	if len(obs.RecentNATRemaps) == 0 && n.handoff == nil {
		health = 0.4
	}
	return stability, health
}
