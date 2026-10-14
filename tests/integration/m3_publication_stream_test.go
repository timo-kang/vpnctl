//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

const publicationRecordLimit = 512
const publicationByteLimit = 32 * 1024 * 1024

// The opt-in stdout receiver runs in the test worker's resource group. It does
// not poll or spawn another process. Each complete line is parsed once, after
// the original log write. On invalid/oversized input it drains without growing
// or interrupting the producer, while retaining a sticky evidence error.
type publicationStream struct {
	mu      sync.Mutex
	now     func() time.Time
	input   publicationSnapshot
	pending []byte
	// Private inputs for the sampled gate, bounded by the same stream limits.
	// Preserve every candidate for historical gap checks, but no proofs or
	// diagnostics. These rows are never serialized into publication evidence.
	rows []relayapply.TargetReconcileResult
}

func newPublicationStream() *publicationStream { return &publicationStream{now: time.Now} }

func (s *publicationStream) Write(p []byte) (int, error) {
	started := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.input.Writes++
	s.input.Bytes += int64(len(p))
	if s.input.Bytes > publicationByteLimit && s.input.Problem == "" {
		s.input.Problem = "stream_limit"
	}
	n := len(p)
	for len(p) > 0 && s.input.Problem == "" {
		i := bytes.IndexByte(p, '\n')
		part := p
		if i >= 0 {
			part = p[:i]
		}
		if len(s.pending)+len(part) > applicationLogRecordLimit {
			s.input.Problem = "record_limit"
			break
		}
		s.pending = append(s.pending, part...)
		if i < 0 {
			break
		}
		if len(s.input.Records) >= publicationRecordLimit {
			s.input.Problem = "record_count_limit"
			break
		}
		var r relayapply.TargetReconcileResult
		if err := json.Unmarshal(s.pending, &r); err != nil || r.SchemaVersion != 1 {
			s.input.Problem = "invalid_record"
			break
		}
		at := s.now() // Includes complete newline receipt and JSON parsing.
		matches := 0
		for _, c := range r.Selection.Candidates {
			if c.PathID == r.Selection.DesiredPathID {
				matches++
			}
		}
		s.input.Records = append(s.input.Records, publicationSample{
			Record:    *snapshotContinuityRecord(r, len(s.input.Records), selectedContinuityCandidate(r), at),
			StartedAt: r.StartedAt, ReceivedAt: at, SelectedMatches: matches,
		})
		s.rows = append(s.rows, sampledContinuityInput(r))
		s.pending = s.pending[:0]
		p = p[i+1:]
	}
	s.input.CaptureElapsed += s.now().Sub(started)
	return n, nil
}

func sampledContinuityInput(r relayapply.TargetReconcileResult) relayapply.TargetReconcileResult {
	out := relayapply.TargetReconcileResult{Applied: r.Applied, FinishedAt: r.FinishedAt,
		Selection: relayselect.Decision{DesiredPathID: r.Selection.DesiredPathID,
			Reason: r.Selection.Reason, Policy: relayselect.Policy{MaxAge: r.Selection.Policy.MaxAge, Successes: r.Selection.Policy.Successes}},
		Application: relayapply.TargetGuardResult{State: r.Application.State}}
	for _, c := range r.Selection.Candidates {
		out.Selection.Candidates = append(out.Selection.Candidates, relayselect.Candidate{
			Eligible: c.Eligible, TargetObservation: relayobserve.TargetObservation{
				PathID: c.PathID, State: c.State, ObservedAt: c.ObservedAt}})
	}
	return out
}

// Bind the evaluated history and clock under the receiver lock. A file read
// followed by a later clock can report stale evidence after a timely new row
// has already arrived. This also avoids reparsing the full log at every poll.
func (s *publicationStream) checkContinuity(baseline int, role string, report map[string]any) (int, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now()
	cycles, gap, err := evaluateApplicationContinuity(s.rows, baseline, at)
	if s.input.Problem != "" && err == nil {
		err = &continuityFailure{Reason: "input_invalid", CheckedAt: at, Baseline: baseline, RecordCount: len(s.rows)}
	}
	if failure, ok := err.(*continuityFailure); ok {
		failure.SchemaVersion = 2
		failure.Role = continuityEnum(role, "app", "app2")
		if report["continuity_failure"] == nil {
			report["continuity_failure"] = failure
		}
	}
	return cycles, gap, err
}

func (s *publicationStream) requireContinuity(t *testing.T, baseline int, role string, report map[string]any) (int, time.Duration) {
	t.Helper()
	cycles, gap, err := s.checkContinuity(baseline, role, report)
	if err != nil {
		report["sampled_qualification_status"] = "fail"
		t.Fatal(err)
	}
	return cycles, gap
}

// Begin and Finish use the same atomic snapshot: baseline count, latest row,
// pending bytes and boundary time cannot race with a newly completed line.
func (s *publicationStream) snapshot() publicationSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.input
	out.Records = make([]publicationSample, len(s.input.Records))
	for i, r := range s.input.Records {
		out.Records[i] = clonePublicationSample(r)
	}
	out.PendingBytes = len(s.pending)
	out.CapturedAt = s.now()
	return out
}

func clonePublicationSample(r publicationSample) publicationSample {
	if r.Record.Candidate != nil {
		c := *r.Record.Candidate
		if c.Age != nil {
			age := *c.Age
			c.Age = &age
		}
		r.Record.Candidate = &c
	}
	return r
}
