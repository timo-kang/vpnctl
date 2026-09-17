// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"time"
	"vpnctl/internal/quality"
)

type LinkQuality = quality.LinkQuality
type QualityThresholds = quality.QualityThresholds
type QualityConfig = quality.QualityConfig
type PeerQuality = quality.PeerQuality

const (
	QualityUnknown  = quality.QualityUnknown
	QualityOffline  = quality.QualityOffline
	QualityPoor     = quality.QualityPoor
	QualityDegraded = quality.QualityDegraded
	QualityGood     = quality.QualityGood
)

var DefaultThresholds = quality.DefaultThresholds

func ComputeQuality(rtt, loss float64, success bool, t QualityThresholds) LinkQuality {
	return quality.ComputeQuality(rtt, loss, success, t)
}
func ptr[T any](v T) *T { return &v }

type qualityWindow struct{ state *quality.Window }

func (w *qualityWindow) observe(now time.Time, p probeOutcome, cfg QualityConfig) PeerQuality {
	if w.state == nil {
		w.state = quality.NewWindow()
	}
	return w.state.Observe(now, quality.Outcome{RTTus: p.rtt, Success: p.success, Reason: p.reason}, cfg)
}
