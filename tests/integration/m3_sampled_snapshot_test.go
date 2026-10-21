//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampledJSON(t *testing.T, observed, finished time.Duration) []byte {
	t.Helper()
	r := continuityTrace(publicationTestTime(observed))[0]
	r.SchemaVersion = 1
	r.StartedAt, r.FinishedAt = publicationTestTime(observed), publicationTestTime(finished)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	return append(b, '\n')
}

func TestApplicationContinuitySampledSnapshotClosesReadRace(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(time.Second)
	s.now = func() time.Time { return clock }
	old := sampledJSON(t, 0, 900*time.Millisecond)
	s.Write(old)
	begin := s.snapshot()
	path := filepath.Join(t.TempDir(), "app.jsonl")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal("fixture write failed")
	}
	clock = publicationTestTime(9800 * time.Millisecond)
	// Reproduce the legacy file read/clock split deterministically. While the
	// reader retains these bytes, a new complete row arrives before expiry.
	read := applicationResults(path)
	clock = publicationTestTime(9900 * time.Millisecond)
	s.Write(sampledJSON(t, 9700*time.Millisecond, 9850*time.Millisecond))
	clock = publicationTestTime(10100 * time.Millisecond)
	if _, _, err := evaluateApplicationContinuity(read, 1, clock); err == nil {
		t.Fatal("legacy read race was not reproduced")
	}
	cycles, gap, err := s.checkContinuity(1, "app", map[string]any{})
	if err != nil || cycles != 1 || gap != 9700*time.Millisecond {
		t.Fatal("timely received replacement was ignored at the sampled boundary")
	}
	requirePublicationVerdict(t, evaluatePublicationContinuity(s.snapshot(), 1, begin.CapturedAt), "pass", "")
}

func TestApplicationContinuitySampledSnapshotKeepsExpiryAndFirstFailure(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(time.Second)
	s.now = func() time.Time { return clock }
	s.Write(sampledJSON(t, 0, 900*time.Millisecond))
	report := map[string]any{}
	clock = publicationTestTime(10 * time.Second)
	if _, _, err := s.checkContinuity(1, "app", report); err != nil {
		t.Fatal("exact expiry boundary rejected")
	}
	// A complete JSON value without its newline is not received evidence.
	next := sampledJSON(t, 9*time.Second, 9500*time.Millisecond)
	s.Write(next[:len(next)-1])
	clock = clock.Add(time.Nanosecond)
	_, _, err := s.checkContinuity(1, "private-role-marker", report)
	f, ok := err.(*continuityFailure)
	if !ok || f.Reason != "observation_stale" || f.SchemaVersion != 2 || f.Read != nil || !f.CheckedAt.Equal(clock) || f.RecordCount != 1 || f.Role != "other" {
		t.Fatal("expired snapshot was accepted or misidentified")
	}
	frozen, _ := json.Marshal(report["continuity_failure"])
	if bytes.Contains(frozen, []byte("private-")) || bytes.Contains(frozen, []byte("p00")) {
		t.Fatal("snapshot failure leaked an identifier")
	}
	s.Write([]byte{'\n'})
	if cycles, _, err := s.checkContinuity(1, "app", report); err != nil || cycles != 1 {
		t.Fatal("complete recovery was not available to the next snapshot")
	}
	clock = clock.Add(20 * time.Second)
	s.checkContinuity(1, "app2", report)
	after, _ := json.Marshal(report["continuity_failure"])
	if !bytes.Equal(frozen, after) {
		t.Fatal("recovery or a later failure replaced the original failure")
	}
}

func TestApplicationContinuitySampledSnapshotKeepsAllCandidateHistory(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(12 * time.Second)
	s.now = func() time.Time { return clock }
	rows := continuityTrace(publicationTestTime(0))[:2]
	for i := range rows {
		rows[i].SchemaVersion = 1
		rows[i].Selection.Candidates[0].ObservedAt = publicationTestTime(time.Duration(i+1) * time.Second)
		other := rows[i].Selection.Candidates[0]
		other.PathID = "private-other-path"
		other.ObservedAt = publicationTestTime(time.Duration(i) * 11 * time.Second)
		rows[i].Selection.Candidates = append(rows[i].Selection.Candidates, other)
		b, _ := json.Marshal(rows[i])
		s.Write(append(b, '\n'))
	}
	_, _, err := s.checkContinuity(1, "app", map[string]any{})
	f, ok := err.(*continuityFailure)
	if !ok || f.Reason != "freshness_gap" || f.Gap != 11*time.Second || f.Record.CandidateIndex != 1 || f.Previous.CandidateIndex != 1 {
		t.Fatal("non-selected candidate history was lost")
	}
	// The retained inputs must be independent of the decoder's source slices.
	copy := sampledContinuityInput(rows[0])
	rows[0].Selection.Candidates[0].ObservedAt = time.Time{}
	if copy.Selection.Candidates[0].ObservedAt.IsZero() {
		t.Fatal("sampled input aliases decoder memory")
	}
}

func TestApplicationContinuitySampledSnapshotRejectsInvalidStream(t *testing.T) {
	for _, problem := range []string{"invalid_record", "stream_limit", "record_limit", "record_count_limit"} {
		s := newPublicationStream()
		s.now = func() time.Time { return publicationTestTime(time.Second) }
		s.Write(sampledJSON(t, 0, 900*time.Millisecond))
		s.input.Problem = problem // Stream boundary behavior is tested separately.
		_, _, err := s.checkContinuity(1, "app", map[string]any{})
		if f, ok := err.(*continuityFailure); !ok || f.Reason != "input_invalid" {
			t.Fatal("invalid stream was promoted to sampled success")
		}
	}
}

func TestApplicationContinuitySampledSnapshotConcurrentWriter(t *testing.T) {
	s := newPublicationStream()
	s.now = func() time.Time { return publicationTestTime(time.Second) }
	s.Write(sampledJSON(t, 0, time.Millisecond))
	lines := make([][]byte, 200)
	for i := range lines {
		at := time.Duration(i+1) * time.Millisecond
		lines[i] = sampledJSON(t, at, at+time.Nanosecond)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, line := range lines {
			s.Write(line)
		}
	}()
	for i := 0; i < 300; i++ {
		if _, _, err := s.checkContinuity(1, "app", map[string]any{}); err != nil {
			t.Error("concurrent complete rows produced inconsistent sampled evidence")
			break
		}
	}
	<-done
	if cycles, gap, err := s.checkContinuity(1, "app", map[string]any{}); err != nil || cycles != len(lines) || gap != time.Millisecond {
		t.Fatal("concurrent sampling lost complete records")
	}
}
