// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package predictor

import (
	"context"
	"math"
	"time"
)

// HandoffRuleParams tunes the rule-based handoff-probability predictor.
// Defaults follow cellular industry practice: -100 dBm RSRP is a typical
// LTE/5G handover trigger threshold; a 5 dBm margin captures the
// hysteresis carriers apply around that threshold.
type HandoffRuleParams struct {
	// RSRPHandoverThreshold is the reference RSRP value (dBm) above
	// which handoff probability approaches 0 and below which it
	// approaches 1.
	RSRPHandoverThreshold float64

	// RSRPScale is the softness of the sigmoid around the threshold.
	// Smaller values yield a sharper decision boundary.
	RSRPScale float64

	// RSSIFallbackThreshold and RSSIFallbackScale mirror the RSRP
	// parameters for modems that expose RSSI but not RSRP.
	RSSIFallbackThreshold float64
	RSSIFallbackScale     float64

	// HistoryWeight blends the sigmoid output with the observed
	// recent-handoff-rate. Range [0, 1]: 0 = pure sigmoid, 1 = pure
	// history.
	HistoryWeight float64
}

// DefaultHandoffRuleParams returns tuning values calibrated to Korean
// carrier operating norms circa 2026. Refine with pilot data (M6 in
// predictor-design §11).
//
// HistoryWeight is intentionally low (0.15) for the cold-start rule
// because the recent-handoff-rate proxy is a weak signal on its own —
// signal-strength on the current cell drives most of the useful
// prediction until pilot data enables the trained variant. Phase-B
// data may push HistoryWeight higher once the rate signal is
// calibrated against real handoff-event lead times.
var DefaultHandoffRuleParams = HandoffRuleParams{
	RSRPHandoverThreshold: -100,
	RSRPScale:             5,
	RSSIFallbackThreshold: -85,
	RSSIFallbackScale:     5,
	HistoryWeight:         0.15,
}

// HandoffRule is a rule-based handoff-probability predictor used as the
// cold-start implementation for signal q[3] per predictor-design §4.4.
// It combines a signal-strength sigmoid with a recent-handoff-rate
// term. Both terms alone are noisy; blending them modestly with
// HistoryWeight typically outperforms either.
//
// The predictor is Ready as soon as one Observation with a plausible
// RSRP or RSSI has been seen; it does not require warmup.
//
// Signals other than handoff-probability are delegated to the composed
// Persistence baseline.
type HandoffRule struct {
	horizon  time.Duration
	baseline *Persistence
	params   HandoffRuleParams
}

// NewHandoffRule constructs a HandoffRule with the given horizon and
// parameters. Pass DefaultHandoffRuleParams for the calibrated defaults.
//
// Scale parameters are validated: a zero or negative RSRPScale or
// RSSIFallbackScale would produce a division by zero in sigmoidTerm.
// Both fall back to the calibrated defaults when misconfigured, matching
// the parameter-validation pattern used by NewNATRule.
func NewHandoffRule(horizon time.Duration, params HandoffRuleParams) *HandoffRule {
	if horizon <= 0 {
		horizon = 2 * time.Second
	}
	if params.RSRPScale <= 0 {
		params.RSRPScale = DefaultHandoffRuleParams.RSRPScale
	}
	if params.RSSIFallbackScale <= 0 {
		params.RSSIFallbackScale = DefaultHandoffRuleParams.RSSIFallbackScale
	}
	return &HandoffRule{
		horizon:  horizon,
		baseline: NewPersistence(horizon),
		params:   params,
	}
}

// Name implements Predictor.
func (h *HandoffRule) Name() string { return "handoff-rule" }

// Horizon implements Predictor.
func (h *HandoffRule) Horizon() time.Duration { return h.horizon }

// Ready implements Predictor.
func (h *HandoffRule) Ready() bool { return true }

// Predict computes handoff probability from the current cell signal
// strength and recent-handoff history, then delegates the remaining
// signals to Persistence.
func (h *HandoffRule) Predict(ctx context.Context, obs Observation) (Forecast, error) {
	base, err := h.baseline.Predict(ctx, obs)
	if err != nil {
		return Forecast{}, err
	}

	prob, health := h.computeHandoffProb(obs)
	base.Q[SignalHandoffProb] = prob

	// Rule-based CI: symmetric ±0.15 around the point, clamped to [0,1].
	base.QLo[SignalHandoffProb] = clamp(prob-0.15, 0, 1)
	base.QHi[SignalHandoffProb] = clamp(prob+0.15, 0, 1)
	base.Health[SignalHandoffProb] = health
	base.PredictorName = h.Name()
	return base, nil
}

// computeHandoffProb produces the point estimate + a self-report health
// score. Health drops when the signal-strength reading is unavailable
// or clearly out of range.
func (h *HandoffRule) computeHandoffProb(obs Observation) (float64, float64) {
	sigmoid, healthSig := h.sigmoidTerm(obs.Cell)
	histTerm, healthHist := h.historyTerm(obs)

	w := h.params.HistoryWeight
	prob := (1-w)*sigmoid + w*histTerm

	// Blended health is the min of contributing terms; if signal
	// strength is bad but history has data, health is still poor
	// because the primary decision axis is unreliable.
	health := healthSig
	if healthHist < health {
		health = healthHist
	}
	return clamp(prob, 0, 1), health
}

// sigmoidTerm computes 1 - σ((RSRP - threshold)/scale) preferring RSRP,
// falling back to RSSI. Returns the sigmoid value and a health score:
// 1.0 when a usable RSRP/RSSI is present, 0.2 when neither is present.
func (h *HandoffRule) sigmoidTerm(cell CellInfo) (float64, float64) {
	if cell.RSRP != 0 {
		x := (cell.RSRP - h.params.RSRPHandoverThreshold) / h.params.RSRPScale
		return 1 - sigmoid(x), 1.0
	}
	if cell.RSSI != 0 {
		x := (cell.RSSI - h.params.RSSIFallbackThreshold) / h.params.RSSIFallbackScale
		return 1 - sigmoid(x), 0.7
	}
	// Neither signal available — default to 0.5 (maximum uncertainty)
	// with low health.
	return 0.5, 0.2
}

// historyTerm counts handoffs in the last 30 s and maps the rate to
// [0, 1]. Health is 1.0 when at least one handoff or 30 s of quiet
// history is available; 0.5 if the observation is very fresh.
func (h *HandoffRule) historyTerm(obs Observation) (float64, float64) {
	cutoff := obs.Now.Add(-30 * time.Second)
	count := 0
	for _, t := range obs.RecentHandoffs {
		if t.After(cutoff) {
			count++
		}
	}
	// Each handoff observed in the last 30 s adds 0.2 to the
	// probability, capped at 1.0. A stationary robot in a stable
	// cell yields 0.
	prob := clamp(float64(count)*0.2, 0, 1)
	health := 1.0
	if len(obs.RecentHandoffs) == 0 && obs.Cell.CellID == "" {
		health = 0.5
	}
	return prob, health
}

// sigmoid is the standard logistic function 1 / (1 + e^(-x)).
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}
