// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package quality

import "time"

// ReplayQuality evaluates ordered, individual probe observations with the same
// window, thresholds and recovery rule as the live monitor. Callers must supply
// samples ordered by timestamp and stable ID; replay does not add observations when read.
func ReplayQuality(samples []Sample) PeerQuality {
	cfg, _ := (QualityConfig{}).Normalized(5 * time.Second)
	w := NewWindow()
	q := PeerQuality{Quality: "unknown", Level: QualityUnknown, Window: cfg.Window.Seconds(), Stale: true, ErrorReason: "no_samples"}
	for _, s := range samples {
		q = w.Observe(s.Timestamp, Outcome{RTTus: s.RTTus, Success: s.Success}, cfg)
	}
	return q
}

// FreshQuality returns a detached snapshot. Old measurements remain visible,
// but cannot advertise a current quality level.
func FreshQuality(q PeerQuality, now time.Time) PeerQuality {
	q = q.Clone()
	if q.ObservedAt == nil {
		return q
	}
	age := now.Sub(*q.ObservedAt)
	if age < 0 || age >= 17*time.Second {
		q.Stale = true
		q.SetLevel(QualityUnknown)
		q.ErrorReason = "stale"
		if age < 0 {
			q.ErrorReason = "clock_regressed"
		}
	}
	return q
}

type Sample struct {
	Timestamp time.Time
	RTTus     int64
	Success   bool
}
