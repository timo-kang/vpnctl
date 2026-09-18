// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package quality

import (
	"fmt"
	"math"
	"time"
)

// LinkQuality represents the network quality level.
type LinkQuality int

const (
	QualityUnknown  LinkQuality = -1
	QualityOffline  LinkQuality = 0
	QualityPoor     LinkQuality = 1
	QualityDegraded LinkQuality = 2
	QualityGood     LinkQuality = 3
)

func (q LinkQuality) String() string {
	switch q {
	case QualityUnknown:
		return "unknown"
	case QualityGood:
		return "good"
	case QualityDegraded:
		return "degraded"
	case QualityPoor:
		return "poor"
	default:
		return "offline"
	}
}

// QualityThresholds defines the boundaries for quality levels.
type QualityThresholds struct {
	GoodMaxRTTMs       float64 // default 50
	GoodMaxLossPct     float64 // default 2
	DegradedMaxRTTMs   float64 // default 200
	DegradedMaxLossPct float64 // default 10
}

var DefaultThresholds = QualityThresholds{
	GoodMaxRTTMs:       50,
	GoodMaxLossPct:     2,
	DegradedMaxRTTMs:   200,
	DegradedMaxLossPct: 10,
}

// QualityConfig defines the live, process-local measurement contract.
type QualityConfig struct {
	Window          time.Duration
	StaleAfter      time.Duration
	MinSamples      int
	RecoverySamples int
	Thresholds      *QualityThresholds
}

func (q QualityConfig) Normalized(interval time.Duration) (QualityConfig, error) {
	if q.Window == 0 {
		q.Window = time.Minute
	}
	if q.StaleAfter == 0 {
		q.StaleAfter = min(q.Window, 3*interval+2*time.Second)
	}
	if q.MinSamples == 0 {
		q.MinSamples = 3
	}
	if q.RecoverySamples == 0 {
		q.RecoverySamples = 3
	}
	if q.Thresholds == nil {
		q.Thresholds = ptr(DefaultThresholds)
	} else {
		q.Thresholds = copyPtr(q.Thresholds)
	}
	if q.Window <= 0 || q.StaleAfter <= 0 || q.StaleAfter > q.Window || q.MinSamples < 1 || q.RecoverySamples < 1 {
		return q, fmt.Errorf("quality requires positive window, stale-after <= window, min-samples and recovery-samples")
	}
	t := q.Thresholds
	for _, v := range []float64{t.GoodMaxRTTMs, t.DegradedMaxRTTMs, t.GoodMaxLossPct, t.DegradedMaxLossPct} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return q, fmt.Errorf("quality thresholds must be finite and nonnegative")
		}
	}
	if t.GoodMaxRTTMs > t.DegradedMaxRTTMs || t.GoodMaxLossPct > t.DegradedMaxLossPct || t.DegradedMaxLossPct > 100 {
		return q, fmt.Errorf("quality thresholds must be ordered; loss is a percentage in [0,100]")
	}
	return q, nil
}

// PeerQuality is shared verbatim by HTTP, terminal and Prometheus consumers.
// Nil RTT/loss means unmeasured, never a zero-latency or lossless observation.
type PeerQuality struct {
	PeerIP        string      `json:"peer"`
	Quality       string      `json:"quality"`
	RTTMs         *float64    `json:"rtt_ms"`
	LossPct       *float64    `json:"loss_pct"`
	ObservedAt    *time.Time  `json:"observed_at"`
	Window        float64     `json:"window"` // seconds, ending at ObservedAt
	SampleCount   int         `json:"sample_count"`
	LastSuccessAt *time.Time  `json:"last_success_at"`
	Stale         bool        `json:"stale"`
	ErrorReason   string      `json:"error_reason"`
	Level         LinkQuality `json:"-"`
}

func (q *PeerQuality) SetLevel(level LinkQuality) { q.Level = level; q.Quality = level.String() }

func ptr[T any](v T) *T { return &v }
func copyPtr[T any](v *T) *T {
	if v == nil {
		return nil
	}
	return ptr(*v)
}

func (q PeerQuality) Clone() PeerQuality {
	q.RTTMs = copyPtr(q.RTTMs)
	q.LossPct = copyPtr(q.LossPct)
	q.ObservedAt = copyPtr(q.ObservedAt)
	q.LastSuccessAt = copyPtr(q.LastSuccessAt)
	return q
}

type qualitySample struct {
	at      time.Time
	rtt     int64
	success bool
}
type Window struct {
	samples     []qualitySample
	lastSuccess *time.Time
	level       LinkQuality
	candidate   LinkQuality
	recovery    int
}

func (w *Window) Observe(now time.Time, p Outcome, cfg QualityConfig) PeerQuality {
	if p.Unknown || p.Reason == "invalid_probe_target" {
		w.samples, w.level, w.recovery = nil, QualityUnknown, 0
		q := PeerQuality{ObservedAt: ptr(now), Window: cfg.Window.Seconds(), LastSuccessAt: copyPtr(w.lastSuccess), ErrorReason: p.Reason}
		q.SetLevel(QualityUnknown)
		return q
	}
	if n := len(w.samples); n > 0 && now.Before(w.samples[n-1].at) {
		// A wall-clock step backwards cannot make future samples look current.
		w.samples, w.lastSuccess, w.level, w.recovery = nil, nil, QualityUnknown, 0
	}
	cutoff := now.Add(-cfg.Window)
	first := 0
	for first < len(w.samples) && !w.samples[first].at.After(cutoff) {
		first++
	}
	// Copy the live tail so expired samples do not retain an ever-growing backing array.
	w.samples = append(append([]qualitySample(nil), w.samples[first:]...), qualitySample{now, p.RTTus, p.Success})
	if p.Success {
		w.lastSuccess = ptr(now)
	}
	q := PeerQuality{ObservedAt: ptr(now), Window: cfg.Window.Seconds(), SampleCount: len(w.samples), LastSuccessAt: copyPtr(w.lastSuccess), ErrorReason: p.Reason}
	successes := 0
	totalRTT := float64(0)
	for _, s := range w.samples {
		if s.success {
			successes++
			totalRTT += float64(s.rtt)
		}
	}
	q.LossPct = ptr(100 * float64(len(w.samples)-successes) / float64(len(w.samples)))
	if successes > 0 {
		q.RTTMs = ptr(totalRTT / float64(successes) / 1000)
	}
	if q.SampleCount < cfg.MinSamples {
		w.level, w.recovery = QualityUnknown, 0
		q.ErrorReason = "insufficient_samples"
	} else {
		rtt := float64(0)
		if q.RTTMs != nil {
			rtt = *q.RTTMs
		}
		target := ComputeQuality(rtt, *q.LossPct, successes > 0, *cfg.Thresholds)
		// Deterioration is immediate. Only improvements need consecutive new samples;
		// HTTP reads and Prometheus scrapes never advance this state machine.
		if w.level == QualityUnknown || target <= w.level {
			w.level, w.recovery = target, 0
		} else {
			if target != w.candidate {
				w.candidate, w.recovery = target, 0
			}
			w.recovery++
			if w.recovery >= cfg.RecoverySamples {
				w.level, w.recovery = target, 0
			}
		}
	}
	if w.recovery > 0 && q.ErrorReason == "" {
		q.ErrorReason = "recovering"
	}
	q.SetLevel(w.level)
	return q
}

// ComputeQuality calculates quality from RTT (milliseconds) and loss percentage.
func ComputeQuality(rttMs float64, lossPct float64, probeSuccess bool, thresholds QualityThresholds) LinkQuality {
	if !probeSuccess {
		return QualityOffline
	}
	if rttMs <= thresholds.GoodMaxRTTMs && lossPct <= thresholds.GoodMaxLossPct {
		return QualityGood
	}
	if rttMs <= thresholds.DegradedMaxRTTMs && lossPct <= thresholds.DegradedMaxLossPct {
		return QualityDegraded
	}
	return QualityPoor
}

// Outcome describes one completed observation.
type Outcome struct {
	RTTus   int64
	Success bool
	Reason  string
	Unknown bool
}

func NewWindow() *Window { return &Window{level: QualityUnknown} }

// ResetAssessment invalidates classification without discarding observations.
func (w *Window) ResetAssessment() { w.level, w.recovery = QualityUnknown, 0 }
