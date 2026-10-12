//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import "fmt"

type uplinkSample struct {
	Kind    string `json:"kind"`
	Begin   int64  `json:"begin_ns"` // Original request, retained across same-socket timeouts.
	Attempt int64  `json:"attempt_ns,omitempty"`
	End     int64  `json:"end_ns"`
	OK      bool   `json:"ok"`
	Relay   string `json:"relay,omitempty"`
	Failure string `json:"failure,omitempty"`
}
type uplinkMetric struct {
	FirstSuccess     int64 `json:"first_success_ns"`
	Failed           int   `json:"failed_attempts"`
	Censored         bool  `json:"unrecovered_at_end"`
	ObservedFor      int64 `json:"observed_for_ns"`
	BaselineFailures int   `json:"baseline_failures"`
	BaselineSamples  int   `json:"baseline_samples"`
	Samples          int   `json:"samples"`
	MaxSuccessGap    int64 `json:"max_success_gap_ns"`
	MaxSchedulingGap int64 `json:"max_sample_start_gap_ns"`
}

// Timing is guest CLOCK_MONOTONIC throughout. A completed response to a request
// begun during or before fault installation cannot establish post-fault recovery.
// The caller separately rejects unhealthy baselines and incomplete sampling.
func measureUplink(rows []uplinkSample, kind string, baseline, faultBegin, faultEnd, end int64) (uplinkMetric, error) {
	m := uplinkMetric{Censored: true, ObservedFor: end - faultEnd}
	if kind == "" || baseline < 0 || baseline >= faultBegin || faultBegin > faultEnd || faultEnd >= end {
		return m, fmt.Errorf("invalid observation window")
	}
	var previousBegin, previousAttempt, previousEnd int64
	var havePrevious, baselineSuccess bool
	lastSuccess, lastAttempt := faultEnd, faultEnd
	for _, r := range rows {
		if r.Kind != kind {
			continue
		}
		attempt := r.Attempt
		if attempt == 0 {
			attempt = r.Begin
		}
		if r.Begin < 0 || attempt < r.Begin || r.End < attempt || havePrevious && (r.Begin < previousBegin || attempt < previousAttempt || r.End < previousEnd) {
			return m, fmt.Errorf("invalid sample chronology")
		}
		previousBegin, previousAttempt, previousEnd, havePrevious = r.Begin, attempt, r.End, true
		if attempt >= baseline && r.End <= faultBegin {
			m.BaselineSamples++
			if r.OK && r.Begin >= baseline {
				baselineSuccess = true
			}
			if !r.OK {
				m.BaselineFailures++
			}
		}
		if attempt < faultEnd || attempt > end {
			continue
		}
		m.MaxSchedulingGap = max(m.MaxSchedulingGap, attempt-lastAttempt)
		lastAttempt = attempt
		if r.End > end {
			continue
		}
		m.Samples++
		if !r.OK {
			m.Failed++
			continue
		}
		m.MaxSuccessGap = max(m.MaxSuccessGap, r.End-lastSuccess)
		lastSuccess = r.End
		if r.Begin >= faultEnd && m.FirstSuccess == 0 {
			m.FirstSuccess = r.End
			m.Censored = false
		}
	}
	m.MaxSuccessGap = max(m.MaxSuccessGap, end-lastSuccess)
	m.MaxSchedulingGap = max(m.MaxSchedulingGap, end-lastAttempt)
	if !baselineSuccess || m.Samples == 0 {
		return m, fmt.Errorf("missing baseline or post-fault samples")
	}
	return m, nil
}
