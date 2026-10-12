//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import "time"

// ReceivedAt is an upper bound on publication, not the producer's write time.
// Record.FinishedAt is a lower bound. Only bounded, redacted value copies enter
// the report; no raw JSON, path IDs, proofs, addresses or arbitrary errors do.
type publicationSample struct {
	Record          continuityRecord `json:"record"`
	StartedAt       time.Time        `json:"started_at"`
	ReceivedAt      time.Time        `json:"received_at"`
	SelectedMatches int              `json:"selected_matches"`
}

type publicationSnapshot struct {
	Records        []publicationSample `json:"records"`
	CapturedAt     time.Time           `json:"captured_at"`
	Problem        string              `json:"problem,omitempty"`
	PendingBytes   int                 `json:"pending_bytes"`
	Bytes          int64               `json:"bytes"`
	Writes         int                 `json:"writes"`
	CaptureElapsed time.Duration       `json:"capture_elapsed_ns"`
}

type publicationProblem struct {
	Reason   string             `json:"reason"`
	Previous *publicationSample `json:"previous,omitempty"`
	Record   *publicationSample `json:"record,omitempty"`
	From     time.Time          `json:"from"`
	To       time.Time          `json:"to"`
	Gap      time.Duration      `json:"gap_ns"`
}

type publicationVerdict struct {
	ContractVersion int                 `json:"contract_version"`
	Status          string              `json:"status"`
	Baseline        int                 `json:"baseline_count"`
	BaselineRecord  *publicationSample  `json:"baseline_record,omitempty"`
	StartedAt       time.Time           `json:"started_at"`
	EndedAt         time.Time           `json:"ended_at"`
	Failure         *publicationProblem `json:"first_failure,omitempty"`
	Uncertainty     *publicationProblem `json:"first_uncertainty,omitempty"`
	Input           publicationSnapshot `json:"input"`
}

func evaluatePublicationContinuity(input publicationSnapshot, baseline int, start time.Time) publicationVerdict {
	out := publicationVerdict{ContractVersion: 2, Status: "pass", Baseline: baseline,
		StartedAt: start, EndedAt: input.CapturedAt, Input: input}
	// Freeze values even when a caller later mutates its input or appends
	// recovery/cleanup records. Post-window receipt cannot repair this window.
	out.Input.Records = nil
	for _, r := range input.Records {
		if !r.ReceivedAt.After(input.CapturedAt) {
			out.Input.Records = append(out.Input.Records, clonePublicationSample(r))
		}
	}
	rows := out.Input.Records
	uncertain := func(reason string, r *publicationSample) publicationVerdict {
		out.Status = "inconclusive"
		out.Uncertainty = &publicationProblem{Reason: reason, Record: r}
		return out
	}
	if input.Problem != "" {
		out.Input.Problem = continuityEnum(input.Problem, "invalid_record", "stream_limit", "record_limit", "record_count_limit")
		return uncertain("input_invalid", nil)
	}
	if start.IsZero() || input.CapturedAt.IsZero() || input.CapturedAt.Before(start) || input.CaptureElapsed < 0 {
		return uncertain("timestamp_invalid", nil)
	}
	if baseline < 1 || baseline > len(rows) {
		return uncertain("baseline_missing", nil)
	}
	// Reject contradictory time evidence before attributing a confirmed gap.
	// Monotonic receipt deltas can detect local wall steps, but JSON producer
	// timestamps have no monotonic component. This is a same-guest-clock test.
	previousReceipt := rows[0].ReceivedAt
	for i := range rows {
		r := &rows[i]
		if r.Record.Index != i {
			return uncertain("record_sequence", r)
		}
		if r.ReceivedAt.IsZero() || r.StartedAt.IsZero() || r.Record.FinishedAt.IsZero() ||
			r.StartedAt.After(r.Record.FinishedAt) || r.Record.FinishedAt.After(r.ReceivedAt) ||
			r.ReceivedAt.Before(previousReceipt) || i > 0 && !r.Record.FinishedAt.After(rows[i-1].Record.FinishedAt) {
			return uncertain("timestamp_invalid", r)
		}
		if c := r.Record.Candidate; c != nil && c.ObservedAt.After(r.Record.FinishedAt) {
			return uncertain("timestamp_invalid", r)
		}
		if !publicationClockConsistent(previousReceipt, r.ReceivedAt) {
			return uncertain("clock_invalid", r)
		}
		previousReceipt = r.ReceivedAt
	}
	if rows[baseline-1].ReceivedAt.After(start) || baseline < len(rows) && !rows[baseline].ReceivedAt.After(start) {
		return uncertain("baseline_boundary", nil)
	}
	if !publicationClockConsistent(rows[baseline-1].ReceivedAt, start) ||
		!publicationClockConsistent(previousReceipt, input.CapturedAt) || !publicationClockConsistent(start, input.CapturedAt) {
		return uncertain("clock_invalid", nil)
	}
	out.BaselineRecord = &rows[baseline-1]
	problem := func(reason string, previous, current *publicationSample, from, to time.Time, definite bool) {
		if from.Before(start) {
			from = start
		}
		if to.After(input.CapturedAt) {
			to = input.CapturedAt
		}
		if to.Before(from) {
			to = from // An invalid baseline can predate the window; no gap is inferred.
		}
		p := &publicationProblem{Reason: reason, Previous: previous, Record: current, From: from, To: to, Gap: to.Sub(from)}
		if definite {
			if out.Failure == nil {
				out.Failure = p
			}
		} else if out.Uncertainty == nil {
			out.Uncertainty = p
		}
	}
	for i := baseline - 1; i < len(rows); i++ {
		r := &rows[i]
		c := r.Record.Candidate
		if !r.Record.Applied || r.Record.PolicyMaxAge != 10*time.Second || r.Record.PolicySuccesses != 2 ||
			r.SelectedMatches != 1 || c == nil || !c.Eligible || c.State != "reachable" || c.ObservedAt.IsZero() {
			if i == baseline-1 {
				problem("baseline_invalid", nil, r, start, start, false)
			} else {
				problem("record_invalid", nil, r, r.ReceivedAt, r.ReceivedAt, true)
			}
			break
		}
		if i >= baseline {
			previous := &rows[i-1]
			from := previous.Record.Candidate.ObservedAt.Add(10 * time.Second)
			if from.Before(start) {
				from = start
			}
			if r.Record.FinishedAt.After(from) {
				problem("completion_gap", previous, r, from, r.Record.FinishedAt, true)
			} else if r.ReceivedAt.After(from) {
				problem("receipt_gap", previous, r, from, r.ReceivedAt, false)
			}
		}
		if r.Record.FinishedAt.After(start) && r.Record.FinishedAt.Sub(c.ObservedAt) > 10*time.Second {
			problem("completion_stale", nil, r, c.ObservedAt.Add(10*time.Second), r.Record.FinishedAt, true)
		}
	}
	last := &rows[len(rows)-1]
	if last.Record.Candidate != nil {
		from := last.Record.Candidate.ObservedAt.Add(10 * time.Second)
		if from.Before(start) {
			from = start
		}
		if input.CapturedAt.After(from) {
			problem("receipt_gap", last, nil, from, input.CapturedAt, false)
		}
	}
	switch {
	case out.Failure != nil:
		out.Status = "fail"
	case out.Uncertainty != nil:
		out.Status = "inconclusive"
	}
	return out
}

// A tolerance only detects clock discontinuities; it never widens freshness.
// Synthetic times without monotonic readings still exercise timestamp order.
func publicationClockConsistent(a, b time.Time) bool {
	drift := b.Round(0).Sub(a.Round(0)) - b.Sub(a)
	return drift >= -10*time.Millisecond && drift <= 10*time.Millisecond
}
