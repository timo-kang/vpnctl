// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package predictor implements the 5-D network-quality forecaster q̂(t+Δ)
// that the autonomy state machine consumes as its trigger input.
//
// See docs/research/predictor-design.md for the full design specification.
// The package defines a pluggable Predictor interface with multiple
// implementations spanning the range from Persistence (no prediction) to
// per-signal learned models. The interface is intentionally minimal so
// that mock predictors can be substituted in tests and integration
// harnesses.
package predictor

import (
	"context"
	"errors"
	"time"
)

// Signal indexes into the 5-D vector q(t). The ordering is stable across
// the codebase; do not reorder without updating every consumer.
const (
	SignalRTT           = 0 // milliseconds
	SignalLoss          = 1 // percent [0, 100]
	SignalBandwidth     = 2 // Mbps
	SignalHandoffProb   = 3 // probability [0, 1]
	SignalNATStability  = 4 // stability [0, 1]

	SignalCount = 5
)

// SignalName returns a human-readable name for the given signal index.
func SignalName(i int) string {
	switch i {
	case SignalRTT:
		return "rtt_ms"
	case SignalLoss:
		return "loss_pct"
	case SignalBandwidth:
		return "bw_est_mbps"
	case SignalHandoffProb:
		return "handoff_prob"
	case SignalNATStability:
		return "nat_stability"
	}
	return "unknown"
}

// MissionPhase enumerates the mission phases used as threshold modifiers
// in the autonomy state machine. See docs/research/state-machine-spec.md
// §4 for the taxonomy and role semantics of each phase.
type MissionPhase int

const (
	PhaseNavigation      MissionPhase = 0
	PhaseInspection      MissionPhase = 1
	PhaseTeleSupervised  MissionPhase = 2
	PhaseEmergency       MissionPhase = 3
	PhaseRecovery        MissionPhase = 4
)

// String returns the phase's canonical short name.
func (p MissionPhase) String() string {
	switch p {
	case PhaseNavigation:
		return "navigation"
	case PhaseInspection:
		return "inspection"
	case PhaseTeleSupervised:
		return "tele-supervised"
	case PhaseEmergency:
		return "emergency"
	case PhaseRecovery:
		return "recovery"
	}
	return "unknown"
}

// Sample is a timestamped scalar measurement. Signal-history slices are
// ordered oldest-first.
type Sample struct {
	At    time.Time
	Value float64
}

// CellInfo captures the current cellular attachment as reported by
// mmcli. Values are unset (empty) when the modem does not expose them.
type CellInfo struct {
	CellID     string  // e.g., "0x0A1B2C3D"
	Band       string  // e.g., "B7", "n78"
	Technology string  // "LTE", "5G-NSA", "5G-SA"
	RSSI       float64 // dBm
	SINR       float64 // dB
	RSRP       float64 // dBm (LTE/5G Reference Signal Received Power)
	RSRQ       float64 // dB
}

// Observation is the input the predictor consumes on each tick. All
// fields are populated by an upstream integration layer (typically
// bridging vpnctl metrics, mmcli signal readouts, robot pose, and the
// mission planner). The predictor treats Observation as read-only.
type Observation struct {
	// Now is the timestamp at which prediction is requested. Predictions
	// target Now + Horizon (default 2.0 s; see Predictor.Horizon()).
	Now time.Time

	// Signal-history windows are sized by the implementation. Callers
	// should populate at least the last 10 s at 10 Hz for RTT and at
	// least the last 30 s at 1 Hz for loss, per predictor-design §2.1.
	RTTHistory     []Sample // 10 Hz recommended, most recent last
	LossHistory    []Sample // 1 Hz recommended
	BandwidthLast  Sample   // latest bandwidth probe (roughly every 30 s)

	// Cellular attachment at Now.
	Cell CellInfo

	// Recent handoff events (cell-ID change timestamps) within the
	// last 30 s. Empty when none observed.
	RecentHandoffs []time.Time

	// Recent NAT remap events (source-port change timestamps) within
	// the last 30 s. Empty when none observed.
	RecentNATRemaps []time.Time

	// Robot position in a stable metric frame (SLAM or ENU-projected
	// GNSS). Zero-value is acceptable when unavailable.
	PosXYZ [3]float64

	// Velocity in the same frame as PosXYZ, m/s. Zero-value acceptable.
	VelXYZ [3]float64

	// Mission phase at Now.
	Phase MissionPhase
}

// Forecast is the output of a Predictor call. For each of the 5 signal
// dimensions it carries a point estimate, a symmetric confidence
// interval, and a model-health self-report score.
type Forecast struct {
	// Horizon is the prediction horizon this forecast targets.
	// Forecast[k] applies to time ComputedAt + Horizon.
	Horizon time.Duration

	// Point estimates per signal, indexed by Signal* constants.
	Q [SignalCount]float64

	// Lower / upper bound of the confidence interval per signal.
	// Nominal confidence level 90% unless overridden by the
	// implementation.
	QLo [SignalCount]float64
	QHi [SignalCount]float64

	// Per-signal model-health score in [0, 1]. Values below 0.3
	// indicate the model does not confidently apply to this input;
	// the state machine consumes this to gate its predicates. See
	// docs/research/state-machine-spec.md §11 invariant I5.
	Health [SignalCount]float64

	// PredictorName identifies which implementation produced this
	// forecast. Used in metrics and log lines.
	PredictorName string

	// ComputedAt is set by the predictor to the wall-clock time at
	// which prediction was produced. Callers compare (now - ComputedAt)
	// against a staleness threshold (typically 500 ms) to detect
	// predictor failure per invariant I5.
	ComputedAt time.Time
}

// Predictor is the pluggable forecast producer. Implementations must be
// safe to call from a single goroutine at up to 10 Hz; concurrent calls
// from multiple goroutines are not required to be supported.
type Predictor interface {
	// Predict returns a Forecast for the given Observation. The call
	// must complete within its documented latency budget (30 ms for
	// production implementations). Implementations that need longer
	// should return an error; the caller then falls back to the last
	// good forecast or invokes the predictor-failure fallback.
	Predict(ctx context.Context, obs Observation) (Forecast, error)

	// Horizon returns the default prediction horizon Δ this predictor
	// targets. Callers should treat this as a hint; the actual horizon
	// applied to each Forecast is Forecast.Horizon.
	Horizon() time.Duration

	// Ready reports whether the predictor is ready to serve
	// predictions. Newly-constructed predictors may return false
	// until warmup (buffer fill, model load, remote handshake, etc.)
	// completes. The state machine treats a non-Ready predictor as
	// failed per invariant I5.
	Ready() bool

	// Name returns the predictor's identity string. Included in
	// Forecast.PredictorName and in metric labels.
	Name() string
}

// ErrNotReady is returned by Predict when the predictor is not yet
// warmed up. Callers should not treat this as a hard failure; the
// state machine's fallback logic handles it.
var ErrNotReady = errors.New("predictor: not ready")

// ErrObservationInvalid is returned when the Observation lacks required
// fields for the predictor to produce a meaningful forecast (e.g., an
// empty RTT history).
var ErrObservationInvalid = errors.New("predictor: observation invalid")
