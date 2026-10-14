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

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayselect"
)

func TestApplicationContinuityFailureEvidenceSurvivesLogRecovery(t *testing.T) {
	old := continuityTrace(time.Now().Add(-11 * time.Second))[0]
	old.SchemaVersion = 1
	old.FinishedAt = old.Selection.Candidates[0].ObservedAt.Add(time.Millisecond)
	old.Selection.Reason, old.Application.State = "selected_path_verified", "active"
	path := filepath.Join(t.TempDir(), "app.jsonl")
	write := func(row relayapply.TargetReconcileResult, newline bool) {
		t.Helper()
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal("fixture marshal failed")
		}
		if newline {
			b = append(b, '\n')
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("fixture open failed")
		}
		_, writeErr := f.Write(b)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("fixture append failed")
		}
	}
	write(old, true)
	report := map[string]any{}
	before := time.Now()
	_, _, err := checkApplicationContinuity(path, 1, "app2", report)
	failure, ok := err.(*continuityFailure)
	if !ok || report["continuity_failure"] != failure || failure.Role != "app2" || failure.Reason != "observation_stale" || failure.RecordCount != 1 {
		t.Fatal("actual failed read was not preserved")
	}
	if failure.Read == nil || failure.Read.StartedAt.Before(before) || failure.Read.FinishedAt.Before(failure.Read.StartedAt) || failure.CheckedAt.Before(failure.Read.FinishedAt) || failure.CheckedAt.After(time.Now()) || failure.Read.Elapsed < 0 {
		t.Fatal("read/check timing was not measured in order")
	}
	// JSON timestamps carry wall time only; compare the logged value rather
	// than the fixture timestamp's original monotonic clock component.
	if failure.Read.Elapsed != failure.Read.FinishedAt.Sub(failure.Read.StartedAt) || failure.Record.Candidate.Age == nil || *failure.Record.Candidate.Age != failure.CheckedAt.Sub(old.Selection.Candidates[0].ObservedAt.Round(0)) {
		t.Fatal("timing does not describe the evaluated record")
	}
	frozen, err := json.Marshal(report["continuity_failure"])
	if err != nil {
		t.Fatal("failure snapshot cannot be persisted")
	}
	// This newer row has been completed by the producer but is not visible as
	// a complete log record yet. Its FinishedAt cannot stand in for receipt.
	fresh := continuityTrace(old.Selection.Candidates[0].ObservedAt.Add(9 * time.Second))[0]
	fresh.SchemaVersion = 1
	fresh.FinishedAt = time.Now()
	write(fresh, false)
	if _, _, err := checkApplicationContinuity(path, 1, "app", report); err == nil {
		t.Fatal("partial row replaced the actual failed input")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("fixture open failed")
	}
	_, writeErr := f.WriteString("\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("fixture completion failed")
	}
	if cycles, gap, err := checkApplicationContinuity(path, 1, "app", report); err != nil || cycles != 1 || gap != 9*time.Second {
		t.Fatal("completed recovery fixture did not recover")
	}
	// Cleanup adds later diagnostics without replacing failure-point evidence.
	report["failure_diagnostics"] = map[string]any{"app": fresh}
	after, err := json.Marshal(report["continuity_failure"])
	if err != nil || !bytes.Equal(frozen, after) {
		t.Fatal("later failure or recovery overwrote the first failed input")
	}
}

func TestApplicationContinuityFailureEvidenceEmptyOrPartialLog(t *testing.T) {
	for _, input := range []string{"", "{\"schema_version\":1}", "{broken\n{\"schema_version\":2}\n"} {
		path := filepath.Join(t.TempDir(), "app.jsonl")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal("fixture write failed")
		}
		report := map[string]any{}
		_, _, err := checkApplicationContinuity(path, 1, "private-role-marker", report)
		failure, ok := err.(*continuityFailure)
		if !ok || failure.Reason != "baseline_missing" || failure.RecordCount != 0 || failure.Record != nil || failure.Role != "other" || failure.Read == nil {
			t.Fatal("empty/partial input evidence was fabricated or omitted")
		}
		b, marshalErr := json.Marshal(failure)
		if marshalErr != nil || bytes.Contains(b, []byte("private-role-marker")) {
			t.Fatal("arbitrary role was exposed")
		}
	}
}

func TestApplicationContinuityFailureEvidenceKeepsLatestLoopSemantics(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	fresh := continuityTrace(at)[0].Selection.Candidates[0]
	stale := fresh
	stale.ObservedAt = at.Add(-11 * time.Second)
	ineligible := fresh
	ineligible.Eligible = false
	for _, tc := range []struct {
		candidates []relayselect.Candidate
		fail       bool
		index      int
	}{
		{[]relayselect.Candidate{stale, fresh}, false, -1},
		{[]relayselect.Candidate{fresh, stale}, true, 1},
		{[]relayselect.Candidate{fresh, ineligible}, false, -1},
		{[]relayselect.Candidate{stale, ineligible}, true, 0},
	} {
		rows := continuityTrace(at)[:1]
		rows[0].Selection.Candidates = tc.candidates
		_, _, err := evaluateApplicationContinuity(rows, 1, at)
		if (err != nil) != tc.fail {
			t.Fatal("reason classification changed the existing latest loop")
		}
		if tc.fail {
			f := err.(*continuityFailure)
			if f.Reason != "observation_stale" || f.Record.CandidateIndex != tc.index {
				t.Fatal("snapshot does not identify the last evaluated age")
			}
		}
	}
}
