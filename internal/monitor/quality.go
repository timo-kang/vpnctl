// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

// LinkQuality represents the network quality level.
type LinkQuality int

const (
	QualityOffline  LinkQuality = 0
	QualityPoor     LinkQuality = 1
	QualityDegraded LinkQuality = 2
	QualityGood     LinkQuality = 3
)

func (q LinkQuality) String() string {
	switch q {
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

// PeerQuality holds the computed quality for one peer.
type PeerQuality struct {
	PeerIP  string      `json:"peer"`
	Quality string      `json:"quality"`
	RTTMs   float64     `json:"rtt_ms"`
	LossPct float64     `json:"loss_pct"`
	Level   LinkQuality `json:"-"`
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
