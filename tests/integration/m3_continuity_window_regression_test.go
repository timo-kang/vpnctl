//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestApplicationContinuityWindowsOutliveLifetimeLimits(t *testing.T) {
	s := newPublicationStream()
	at := time.Duration(0)
	s.now = func() time.Time { return publicationTestTime(at + time.Millisecond) }
	s.Write(sampledJSON(t, at, at))
	report := map[string]any{}
	padding := append([]byte(`,"padding":"`), bytes.Repeat([]byte{'x'}, 32*1024)...)
	padding = append(padding, []byte("\"}\n")...)
	totalBytes := 0
	for stage := 1; stage <= 7; stage++ {
		if window, err := s.beginContinuityWindow("app2", report); err != nil || window != stage {
			t.Fatal("valid prior stage prevented rotation")
		}
		if len(s.rows) != 1 || len(s.input.Records) != 1 {
			t.Fatal("prior history retained beyond its validated window")
		}
		for i := 0; i < 180; i++ { // 90 seconds per stage, below its 120s watchdog.
			at += 500 * time.Millisecond
			line := sampledJSON(t, at, at)
			line = append(line[:len(line)-2], padding...)
			totalBytes += len(line)
			s.Write(line)
		}
		cycles, gap, err := s.checkContinuity(1, "app2", report)
		if err != nil || cycles != 180 || gap != 500*time.Millisecond || s.input.Problem != "" || s.input.Bytes > publicationByteLimit {
			t.Fatal("lifetime traffic was charged to a single stage")
		}
	}
	if totalBytes <= publicationByteLimit || 7*180 <= publicationRecordLimit {
		t.Fatal("fixture did not exceed both old lifetime limits")
	}
}

func TestApplicationContinuityWindowCarriesPartialAndOriginalTimes(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(2 * time.Second)
	s.now = func() time.Time { return clock }
	s.Write(sampledJSON(t, 0, time.Millisecond))
	last := sampledJSON(t, time.Second, 1100*time.Millisecond)
	s.Write(last)
	next := sampledJSON(t, 1500*time.Millisecond, 1600*time.Millisecond)
	half := len(next) / 2
	s.Write(next[:half])
	before := s.snapshot().Records[1]
	before.Record.Index = 0
	if _, err := s.beginContinuityWindow("app2", map[string]any{}); err != nil {
		t.Fatal("valid initial window rejected")
	}
	after := s.snapshot()
	if !reflect.DeepEqual(before, after.Records[0]) || after.PendingBytes != half || after.Bytes != int64(len(last)+half) || !bytes.Equal(s.pending, next[:half]) {
		t.Fatal("rotation refreshed or discarded carried evidence")
	}
	clock = publicationTestTime(3 * time.Second)
	s.Write(next[half:])
	if cycles, gap, err := s.checkContinuity(1, "app2", map[string]any{}); err != nil || cycles != 1 || gap != 500*time.Millisecond || s.input.Bytes != int64(len(last)+len(next)) {
		t.Fatal("partial row did not complete across the window boundary")
	}
}

func TestApplicationContinuityWindowRejectsHistoryBeforeReclaim(t *testing.T) {
	s := newPublicationStream()
	s.now = func() time.Time { return publicationTestTime(4 * time.Second) }
	// Only the first boundary can omit activation's non-applied warmup rows.
	bad := func(at time.Duration) []byte {
		return bytes.Replace(sampledJSON(t, at, at), []byte(`"applied":true`), []byte(`"applied":false`), 1)
	}
	s.Write(bad(0))
	s.Write(sampledJSON(t, time.Second, time.Second))
	report := map[string]any{}
	if _, err := s.beginContinuityWindow("app2", report); err != nil {
		t.Fatal("initial warmup was counted as an active window")
	}
	s.Write(bad(2 * time.Second))
	s.Write(sampledJSON(t, 3*time.Second, 3*time.Second))
	before, _ := json.Marshal(s.snapshot())
	_, err := s.beginContinuityWindow("app2", report)
	f, ok := err.(*continuityFailure)
	if !ok || f.Reason != "continuity_not_applied" || f.Record.Index != 1 || s.sampledWindow != 1 {
		t.Fatal("rotation reused the startup exception to hide an active failure")
	}
	after, _ := json.Marshal(s.snapshot())
	if !bytes.Equal(before, after) {
		t.Fatal("failed rotation changed retained evidence")
	}
	if _, err := s.beginContinuityWindow("app2", report); err != f || report["continuity_failure"] != f {
		t.Fatal("retry discarded the first sampled failure")
	}
}

func TestApplicationContinuityWindowCannotExtendStoppedEvidence(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(time.Second)
	s.now = func() time.Time { return clock }
	s.Write(sampledJSON(t, 0, 0))
	report := map[string]any{}
	s.beginContinuityWindow("app2", report)
	clock = publicationTestTime(10 * time.Second)
	if _, err := s.beginContinuityWindow("app2", report); err != nil {
		t.Fatal("exact expiry boundary rejected")
	}
	clock = clock.Add(time.Nanosecond)
	_, err := s.beginContinuityWindow("app2", report)
	f, ok := err.(*continuityFailure)
	if !ok || f.Reason != "observation_stale" || s.sampledWindow != 2 {
		t.Fatal("rotation extended a stopped observer's proof lifetime")
	}
	// Even a later healthy row cannot erase a failure sampled before rotation.
	s.Write(sampledJSON(t, 9*time.Second, 9*time.Second))
	if _, err := s.beginContinuityWindow("app2", report); err != f || s.sampledWindow != 2 {
		t.Fatal("later recovery reopened a failed window")
	}
}

func TestApplicationContinuityWindowRejectsClockBeforeProof(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(time.Second)
	s.now = func() time.Time { return clock }
	s.Write(sampledJSON(t, 0, 0))
	report := map[string]any{}
	s.beginContinuityWindow("app2", report)
	clock = publicationTestTime(-time.Nanosecond)
	_, err := s.beginContinuityWindow("app2", report)
	if f, ok := err.(*continuityFailure); !ok || f.Reason != "observation_future" || s.sampledWindow != 1 {
		t.Fatal("rotation accepted a future proof after a simulated clock step")
	}
}

func TestApplicationContinuityWindowCarriesNonSelectedHistory(t *testing.T) {
	s := newPublicationStream()
	clock := publicationTestTime(8 * time.Second)
	s.now = func() time.Time { return clock }
	r := continuityTrace(clock)[0]
	r.SchemaVersion = 1
	other := r.Selection.Candidates[0]
	other.PathID, other.ObservedAt = "private-other", publicationTestTime(0)
	r.Selection.Candidates = append(r.Selection.Candidates, other)
	line, _ := json.Marshal(r)
	s.Write(append(line, '\n'))
	report := map[string]any{}
	if _, err := s.beginContinuityWindow("app2", report); err != nil {
		t.Fatal("initial candidate fixture failed")
	}
	r.Selection.Candidates[0].ObservedAt = publicationTestTime(9 * time.Second)
	r.Selection.Candidates[1].ObservedAt = publicationTestTime(11 * time.Second)
	clock = publicationTestTime(11 * time.Second)
	line, _ = json.Marshal(r)
	s.Write(append(line, '\n'))
	_, _, err := s.checkContinuity(1, "app2", report)
	if f, ok := err.(*continuityFailure); !ok || f.Reason != "freshness_gap" || f.Record.CandidateIndex != 1 || f.Gap != 11*time.Second {
		t.Fatal("rotation dropped a non-selected candidate's gap history")
	}
}

func TestApplicationContinuityWindowRejectsInputErrorWithoutReset(t *testing.T) {
	for _, problem := range []string{"invalid_record", "stream_limit", "record_limit", "record_count_limit"} {
		s := newPublicationStream()
		s.now = func() time.Time { return publicationTestTime(time.Second) }
		s.Write(sampledJSON(t, 0, 0))
		s.input.Problem = problem
		_, err := s.beginContinuityWindow("app2", map[string]any{})
		if err == nil || s.sampledWindow != 0 || s.input.Problem != problem {
			t.Fatal("window reset healed a sticky input error")
		}
	}
}

func TestApplicationContinuityWindowChecksLastStageAfterRecovery(t *testing.T) {
	s := newPublicationStream()
	s.now = func() time.Time { return publicationTestTime(time.Second) }
	s.Write(sampledJSON(t, 0, 0))
	report := map[string]any{}
	s.beginContinuityWindow("app2", report)
	if _, _, err := s.checkContinuity(1, "app2", report); err != nil {
		t.Fatal("pre-recovery check failed")
	}
	// This completed row arrives while the final recovery payload is checked.
	bad := bytes.Replace(sampledJSON(t, time.Millisecond, time.Millisecond), []byte(`"applied":true`), []byte(`"applied":false`), 1)
	s.Write(bad)
	_, _, err := s.checkContinuity(1, "app2", report)
	if f, ok := err.(*continuityFailure); !ok || f.Reason != "continuity_not_applied" {
		t.Fatal("final stage required another rotation to detect its last failure")
	}
}

func TestApplicationContinuityWindowConcurrentRotation(t *testing.T) {
	s := newPublicationStream()
	s.now = func() time.Time { return publicationTestTime(time.Second) }
	s.Write(sampledJSON(t, 0, 0))
	lines := make([][]byte, 200)
	for i := range lines {
		at := time.Duration(i+1) * time.Millisecond
		lines[i] = sampledJSON(t, at, at)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, line := range lines {
			s.Write(line)
		}
	}()
	report := map[string]any{}
	for i := 0; i < 30; i++ {
		if _, err := s.beginContinuityWindow("app2", report); err != nil {
			t.Error("concurrent valid receipt and rotation failed")
			break
		}
	}
	<-done
	if _, _, err := s.checkContinuity(1, "app2", report); err != nil {
		t.Fatal("concurrent rotation invalidated the final history")
	}
	last := s.snapshot().Records
	if !last[len(last)-1].Record.Candidate.ObservedAt.Equal(publicationTestTime(200 * time.Millisecond)) {
		t.Fatal("rotation lost the final complete row")
	}
}
