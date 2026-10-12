//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func publicationTestTime(offset time.Duration) time.Time {
	return time.Unix(1000, 0).UTC().Add(offset)
}

func TestApplicationContinuityPublicationVerdictIsFrozen(t *testing.T) {
	base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
	late := publicationTestSample(1, 9*time.Second, 10300*time.Millisecond, 10500*time.Millisecond)
	input := publicationTestInput(11*time.Second, base, late)
	got := evaluatePublicationContinuity(input, 1, publicationTestTime(2*time.Second))
	requirePublicationVerdict(t, got, "fail", "completion_gap")
	before, _ := json.Marshal(got)
	input.Records[0].Record.Candidate.ObservedAt = publicationTestTime(8 * time.Second)
	*input.Records[0].Record.Candidate.Age = 0
	input.Records[1].Record.FinishedAt = publicationTestTime(9 * time.Second)
	input.Records = append(input.Records, publicationTestSample(2, 12*time.Second, 13*time.Second, 14*time.Second))
	after, _ := json.Marshal(got)
	if !bytes.Equal(before, after) {
		t.Fatal("caller recovery changed an already evaluated window")
	}
}

func publicationTestSample(index int, observed, finished, received time.Duration) publicationSample {
	age := received - observed
	return publicationSample{
		Record: continuityRecord{Index: index, Applied: true,
			FinishedAt: publicationTestTime(finished), PolicyMaxAge: 10 * time.Second,
			PolicySuccesses: 2, SelectionReason: "selected_path_verified", ApplicationState: "active",
			CandidateCount: 1, CandidateIndex: 0,
			Candidate: &continuityCandidate{Eligible: true, State: "reachable",
				ObservedAt: publicationTestTime(observed), Age: &age}},
		StartedAt:  publicationTestTime(observed - time.Millisecond),
		ReceivedAt: publicationTestTime(received), SelectedMatches: 1,
	}
}

func publicationTestInput(end time.Duration, records ...publicationSample) publicationSnapshot {
	return publicationSnapshot{Records: records, CapturedAt: publicationTestTime(end)}
}

func requirePublicationVerdict(t *testing.T, got publicationVerdict, status, reason string) *publicationProblem {
	t.Helper()
	if got.ContractVersion != 2 || got.Status != status {
		t.Fatalf("unexpected publication verdict: version=%d status=%s", got.ContractVersion, got.Status)
	}
	var p *publicationProblem
	switch status {
	case "pass":
		if got.Failure != nil || got.Uncertainty != nil {
			t.Fatal("pass contains a negative verdict")
		}
		return nil
	case "fail":
		p = got.Failure
	case "inconclusive":
		if got.Failure != nil {
			t.Fatal("uncertain evidence was promoted to definite failure")
		}
		p = got.Uncertainty
	}
	if p == nil || reason != "" && p.Reason != reason {
		t.Fatal("publication reason missing or incorrect")
	}
	return p
}

func requirePublicationBounds(t *testing.T, p *publicationProblem, from, to time.Duration) {
	t.Helper()
	if p == nil || !p.From.Equal(publicationTestTime(from)) || !p.To.Equal(publicationTestTime(to)) || p.Gap != to-from {
		t.Fatal("publication gap bounds do not match the evaluated window")
	}
}

func TestApplicationContinuityPublicationOldPassBlindSpot(t *testing.T) {
	base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
	late := publicationTestSample(1, 9*time.Second, 10300*time.Millisecond, 10500*time.Millisecond)
	// The old checker sees a 9-second proof gap and accepts both polls.
	old := continuityTrace(publicationTestTime(0))[:2]
	old[0].FinishedAt, old[1].FinishedAt = base.Record.FinishedAt, late.Record.FinishedAt
	old[1].Selection.Candidates[0].ObservedAt = late.Record.Candidate.ObservedAt
	if _, _, err := evaluateApplicationContinuity(old[:1], 1, publicationTestTime(2*time.Second)); err != nil {
		t.Fatal("old baseline control unexpectedly rejected")
	}
	if cycles, gap, err := evaluateApplicationContinuity(old, 1, publicationTestTime(11*time.Second)); err != nil || cycles != 1 || gap != 9*time.Second {
		t.Fatal("old completed-record blind spot control changed")
	}
	got := evaluatePublicationContinuity(publicationTestInput(11*time.Second, base, late), 1, publicationTestTime(2*time.Second))
	p := requirePublicationVerdict(t, got, "fail", "completion_gap")
	requirePublicationBounds(t, p, 10*time.Second, 10300*time.Millisecond)
	if p.Previous == nil || p.Record == nil || p.Previous.Record.Index != 0 || p.Record.Record.Index != 1 {
		t.Fatal("completion gap operands were not preserved")
	}
	if got.Baseline != 1 || !got.StartedAt.Equal(publicationTestTime(2*time.Second)) || !got.EndedAt.Equal(publicationTestTime(11*time.Second)) {
		t.Fatal("qualification window was not preserved")
	}
}

func TestApplicationContinuityPublicationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, status, reason string
		finished, received   time.Duration
	}{
		{"early", "pass", "", 9100 * time.Millisecond, 9200 * time.Millisecond},
		{"exact", "pass", "", 10 * time.Second, 10 * time.Second},
		{"completion-one-nanosecond-late", "fail", "completion_gap", 10*time.Second + 1, 10*time.Second + 1},
		{"receipt-one-nanosecond-late", "inconclusive", "receipt_gap", 10 * time.Second, 10*time.Second + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
			next := publicationTestSample(1, 9*time.Second, tc.finished, tc.received)
			got := evaluatePublicationContinuity(publicationTestInput(11*time.Second, base, next), 1, publicationTestTime(2*time.Second))
			p := requirePublicationVerdict(t, got, tc.status, tc.reason)
			if tc.status != "pass" {
				requirePublicationBounds(t, p, 10*time.Second, 10*time.Second+1)
			}
		})
	}
}

func TestApplicationContinuityPublicationWindow(t *testing.T) {
	base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
	late := publicationTestSample(1, 9*time.Second, 10300*time.Millisecond, 10500*time.Millisecond)
	t.Run("clip-start", func(t *testing.T) {
		got := evaluatePublicationContinuity(publicationTestInput(11*time.Second, base, late), 1, publicationTestTime(10100*time.Millisecond))
		p := requirePublicationVerdict(t, got, "fail", "completion_gap")
		requirePublicationBounds(t, p, 10100*time.Millisecond, 10300*time.Millisecond)
	})
	t.Run("pre-window-gap-ignored", func(t *testing.T) {
		got := evaluatePublicationContinuity(publicationTestInput(12*time.Second, base, late), 2, publicationTestTime(11*time.Second))
		requirePublicationVerdict(t, got, "pass", "")
	})
	t.Run("post-end-recovery-does-not-erase-missing-coverage", func(t *testing.T) {
		got := evaluatePublicationContinuity(publicationTestInput(10200*time.Millisecond, base, late), 1, publicationTestTime(2*time.Second))
		p := requirePublicationVerdict(t, got, "inconclusive", "receipt_gap")
		requirePublicationBounds(t, p, 10*time.Second, 10200*time.Millisecond)
	})
	t.Run("post-end-record-does-not-invalidate-covered-window", func(t *testing.T) {
		got := evaluatePublicationContinuity(publicationTestInput(10*time.Second, base, late), 1, publicationTestTime(2*time.Second))
		requirePublicationVerdict(t, got, "pass", "")
	})
	t.Run("recovery-inside-window-does-not-erase-first-gap", func(t *testing.T) {
		recovered := publicationTestSample(2, 18*time.Second, 18100*time.Millisecond, 18200*time.Millisecond)
		got := evaluatePublicationContinuity(publicationTestInput(19*time.Second, base, late, recovered), 1, publicationTestTime(2*time.Second))
		p := requirePublicationVerdict(t, got, "fail", "completion_gap")
		requirePublicationBounds(t, p, 10*time.Second, 10300*time.Millisecond)
	})
}

func TestApplicationContinuityPublicationStoppedOrPartial(t *testing.T) {
	for _, pending := range []int{0, 17} {
		for _, elapsed := range []time.Duration{5 * time.Second, 10 * time.Second, 10*time.Second + 1} {
			base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
			input := publicationTestInput(elapsed, base)
			input.PendingBytes = pending
			got := evaluatePublicationContinuity(input, 1, publicationTestTime(2*time.Second))
			if got.Input.PendingBytes != pending {
				t.Fatal("partial record byte count was hidden")
			}
			if elapsed <= 10*time.Second {
				requirePublicationVerdict(t, got, "pass", "")
				continue
			}
			p := requirePublicationVerdict(t, got, "inconclusive", "receipt_gap")
			requirePublicationBounds(t, p, 10*time.Second, elapsed)
		}
	}
}

func TestApplicationContinuityPublicationInputProblems(t *testing.T) {
	base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
	for _, problem := range []string{"malformed_json", "record_limit", "line_limit"} {
		input := publicationTestInput(3*time.Second, base)
		input.Problem = problem
		got := evaluatePublicationContinuity(input, 1, publicationTestTime(2*time.Second))
		requirePublicationVerdict(t, got, "inconclusive", "")
	}
	for _, baseline := range []int{-1, 0, 2} {
		got := evaluatePublicationContinuity(publicationTestInput(3*time.Second, base), baseline, publicationTestTime(2*time.Second))
		requirePublicationVerdict(t, got, "inconclusive", "")
	}
}

func TestApplicationContinuityPublicationTimestampBeforeGap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*publicationSample)
	}{
		{"start-zero", func(s *publicationSample) { s.StartedAt = time.Time{} }},
		{"finish-zero", func(s *publicationSample) { s.Record.FinishedAt = time.Time{} }},
		{"receive-zero", func(s *publicationSample) { s.ReceivedAt = time.Time{} }},
		{"start-after-finish", func(s *publicationSample) { s.StartedAt = s.Record.FinishedAt.Add(1) }},
		{"finish-after-receipt", func(s *publicationSample) { s.Record.FinishedAt = s.ReceivedAt.Add(1) }},
		{"observation-after-finish", func(s *publicationSample) { s.Record.Candidate.ObservedAt = s.Record.FinishedAt.Add(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
			late := publicationTestSample(1, 9*time.Second, 10300*time.Millisecond, 10500*time.Millisecond)
			tc.change(&late)
			got := evaluatePublicationContinuity(publicationTestInput(11*time.Second, base, late), 1, publicationTestTime(2*time.Second))
			requirePublicationVerdict(t, got, "inconclusive", "timestamp_invalid")
		})
	}
}

func TestApplicationContinuityPublicationRecordValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*publicationSample)
	}{
		{"not-applied", func(s *publicationSample) { s.Record.Applied = false }},
		{"policy-age", func(s *publicationSample) { s.Record.PolicyMaxAge++ }},
		{"policy-successes", func(s *publicationSample) { s.Record.PolicySuccesses = 3 }},
		{"selected-ineligible", func(s *publicationSample) { s.Record.Candidate.Eligible = false }},
		{"selected-unreachable", func(s *publicationSample) { s.Record.Candidate.State = "unreachable" }},
		{"selected-missing", func(s *publicationSample) { s.Record.Candidate = nil; s.SelectedMatches = 0 }},
		{"selected-ambiguous", func(s *publicationSample) { s.SelectedMatches = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
			next := publicationTestSample(1, 9*time.Second, 9100*time.Millisecond, 9200*time.Millisecond)
			tc.change(&next)
			got := evaluatePublicationContinuity(publicationTestInput(10*time.Second, base, next), 1, publicationTestTime(2*time.Second))
			requirePublicationVerdict(t, got, "fail", "record_invalid")
		})
	}
	base := publicationTestSample(0, 0, time.Second, 1100*time.Millisecond)
	wrongIndex := publicationTestSample(2, 9*time.Second, 9100*time.Millisecond, 9200*time.Millisecond)
	got := evaluatePublicationContinuity(publicationTestInput(10*time.Second, base, wrongIndex), 1, publicationTestTime(2*time.Second))
	requirePublicationVerdict(t, got, "inconclusive", "record_sequence")
}

func TestApplicationContinuityPublicationCompletionStaleVersusReceiptDelay(t *testing.T) {
	// No preceding row can prove a completion gap here: baseline itself is late.
	for _, tc := range []struct {
		name, status, reason string
		finished, received   time.Duration
	}{
		{"stale-completion-before-window", "inconclusive", "receipt_gap", 10*time.Second + 1, 11 * time.Second},
		{"fresh-at-completion-late-receipt", "inconclusive", "receipt_gap", 9 * time.Second, 11 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := publicationTestSample(0, 0, tc.finished, tc.received)
			got := evaluatePublicationContinuity(publicationTestInput(13*time.Second, base), 1, publicationTestTime(12*time.Second))
			requirePublicationVerdict(t, got, tc.status, tc.reason)
		})
	}
}

func TestApplicationContinuityPublicationPrewindowCompletion(t *testing.T) {
	old := publicationTestSample(0, 0, 11*time.Second, 11100*time.Millisecond)
	replacement := publicationTestSample(1, 11500*time.Millisecond, 11800*time.Millisecond, 12500*time.Millisecond)
	got := evaluatePublicationContinuity(publicationTestInput(13*time.Second, old, replacement), 1, publicationTestTime(12*time.Second))
	p := requirePublicationVerdict(t, got, "inconclusive", "receipt_gap")
	requirePublicationBounds(t, p, 12*time.Second, 12500*time.Millisecond)
	// A stale replacement completed within the window remains a real failure.
	base := publicationTestSample(0, 5*time.Second, 6*time.Second, 6100*time.Millisecond)
	stale := publicationTestSample(1, time.Second, 12*time.Second, 12500*time.Millisecond)
	got = evaluatePublicationContinuity(publicationTestInput(13*time.Second, base, stale), 1, publicationTestTime(7*time.Second))
	p = requirePublicationVerdict(t, got, "fail", "completion_stale")
	requirePublicationBounds(t, p, 11*time.Second, 12*time.Second)
}
