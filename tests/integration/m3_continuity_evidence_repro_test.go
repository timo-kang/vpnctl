//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
)

// Decode the artifact contract instead of relying on its implementation type.
type continuityEvidenceCandidate struct {
	Eligible   bool      `json:"eligible"`
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
	Age        int64     `json:"age_ns"`
}
type continuityEvidenceRecord struct {
	Index          int                          `json:"index"`
	Applied        bool                         `json:"applied"`
	FinishedAt     time.Time                    `json:"finished_at"`
	MaxAge         int64                        `json:"policy_max_age_ns"`
	Successes      int                          `json:"policy_successes"`
	Reason         string                       `json:"selection_reason"`
	State          string                       `json:"application_state"`
	Count          int                          `json:"candidate_count"`
	CandidateIndex int                          `json:"candidate_index"`
	Candidate      *continuityEvidenceCandidate `json:"candidate"`
}
type continuityEvidenceJSON struct {
	Schema    int                       `json:"schema_version"`
	Reason    string                    `json:"reason"`
	CheckedAt time.Time                 `json:"checked_at"`
	Baseline  int                       `json:"baseline"`
	Count     int                       `json:"record_count"`
	Record    *continuityEvidenceRecord `json:"record"`
	Previous  *continuityEvidenceRecord `json:"previous"`
	Gap       int64                     `json:"gap_ns"`
}

func decodeContinuityEvidence(t *testing.T, err error) (continuityEvidenceJSON, []byte) {
	t.Helper()
	if err == nil {
		t.Fatal("failure unexpectedly accepted")
	}
	b, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal("failure evidence cannot be marshaled")
	}
	var got continuityEvidenceJSON
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&got) != nil {
		t.Fatal("failure evidence violates the allowlisted JSON schema")
	}
	if got.Schema != 1 {
		t.Fatal("failure evidence schema missing")
	}
	return got, b
}

func TestApplicationContinuityFailureEvidenceReasons(t *testing.T) {
	at := time.Unix(1000, 123).UTC()
	cases := []struct {
		name, reason                string
		baseline, record, candidate int
		change                      func([]relayapply.TargetReconcileResult)
	}{
		{"baseline", "baseline_missing", 0, -1, -1, nil},
		{"baseline-beyond-end", "baseline_missing", 5, -1, -1, nil},
		{"missing", "selected_missing", 1, 3, -1, func(r []relayapply.TargetReconcileResult) { r[3].Selection.Candidates = nil }},
		{"unmatched", "selected_missing", 1, 3, -1, func(r []relayapply.TargetReconcileResult) { r[3].Selection.DesiredPathID = "absent" }},
		{"ineligible", "selected_ineligible", 1, 3, 0, func(r []relayapply.TargetReconcileResult) { r[3].Selection.Candidates[0].Eligible = false }},
		{"unreachable", "selected_unreachable", 1, 3, 0, func(r []relayapply.TargetReconcileResult) { r[3].Selection.Candidates[0].State = "unreachable" }},
		{"zero", "observation_zero", 1, 3, 0, func(r []relayapply.TargetReconcileResult) { r[3].Selection.Candidates[0].ObservedAt = time.Time{} }},
		{"future", "observation_future", 1, 3, 0, func(r []relayapply.TargetReconcileResult) {
			r[3].Selection.Candidates[0].ObservedAt = at.Add(4*time.Second + 1)
		}},
		{"stale", "observation_stale", 1, 3, 0, func(r []relayapply.TargetReconcileResult) {
			r[3].Selection.Candidates[0].ObservedAt = at.Add(-6*time.Second - 1)
		}},
		{"not-applied", "continuity_not_applied", 1, 1, 0, func(r []relayapply.TargetReconcileResult) { r[1].Applied = false }},
		{"policy-age", "continuity_policy", 1, 1, 0, func(r []relayapply.TargetReconcileResult) { r[1].Selection.Policy.MaxAge++ }},
		{"policy-successes", "continuity_policy", 1, 1, 0, func(r []relayapply.TargetReconcileResult) { r[1].Selection.Policy.Successes = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := continuityTrace(at)
			for i := range rows {
				rows[i].FinishedAt = at.Add(time.Duration(i)*time.Second + 20*time.Millisecond)
			}
			if tc.change != nil {
				tc.change(rows)
			}
			checked := at.Add(4 * time.Second)
			_, _, err := evaluateApplicationContinuity(rows, tc.baseline, checked)
			got, _ := decodeContinuityEvidence(t, err)
			if got.Reason != tc.reason || !got.CheckedAt.Equal(checked) || got.Baseline != tc.baseline || got.Count != len(rows) {
				t.Fatal("failure reason or exact check context was not preserved")
			}
			if got.Previous != nil || got.Gap != 0 {
				t.Fatal("non-gap failure includes gap evidence")
			}
			if tc.record < 0 {
				return
			}
			r := got.Record
			if r == nil || r.Index != tc.record || r.CandidateIndex != tc.candidate {
				t.Fatal("wrong failing record or candidate index")
			}
			want := rows[tc.record]
			if r.Applied != want.Applied || !r.FinishedAt.Equal(want.FinishedAt) || r.MaxAge != int64(want.Selection.Policy.MaxAge) || r.Successes != want.Selection.Policy.Successes || r.Count != len(want.Selection.Candidates) {
				t.Fatal("failure record fields do not match the evaluated input")
			}
			if tc.candidate < 0 {
				if r.Candidate != nil {
					t.Fatal("missing candidate fabricated")
				}
				return
			}
			c := want.Selection.Candidates[tc.candidate]
			if r.Candidate == nil || r.Candidate.Eligible != c.Eligible || r.Candidate.State != c.State || !r.Candidate.ObservedAt.Equal(c.ObservedAt) {
				t.Fatal("evaluated candidate was not retained")
			}
			if !c.ObservedAt.IsZero() && r.Candidate.Age != int64(checked.Sub(c.ObservedAt)) {
				t.Fatal("exact observation age was not retained")
			}
		})
	}
}

func TestApplicationContinuityFailureEvidenceFreshnessBoundary(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	rows := continuityTrace(at)
	for _, age := range []time.Duration{10 * time.Second, 10*time.Second + 1} {
		checked := rows[3].Selection.Candidates[0].ObservedAt.Add(age)
		cycles, gap, err := evaluateApplicationContinuity(rows, 1, checked)
		if age == 10*time.Second {
			if err != nil || cycles != 3 || gap != time.Second {
				t.Fatal("inclusive 10-second boundary changed")
			}
			continue
		}
		got, _ := decodeContinuityEvidence(t, err)
		if got.Reason != "observation_stale" || got.Record == nil || got.Record.Candidate == nil || got.Record.Candidate.Age != int64(age) {
			t.Fatal("one-nanosecond expiry evidence lost")
		}
	}
}

func TestApplicationContinuityFailureEvidenceHistoricalGap(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	for _, gap := range []time.Duration{-1, 0, 10 * time.Second, 10*time.Second + 1} {
		rows := continuityTrace(at)
		for i := 1; i < len(rows); i++ {
			rows[i].Selection.Candidates[0].ObservedAt = at.Add(gap + time.Duration(i-1)*time.Second)
		}
		checked := rows[3].Selection.Candidates[0].ObservedAt.Add(time.Second)
		cycles, maxGap, err := evaluateApplicationContinuity(rows, 1, checked)
		if gap == 10*time.Second {
			if err != nil || cycles != 3 || maxGap != gap {
				t.Fatal("inclusive gap boundary changed")
			}
			continue
		}
		got, _ := decodeContinuityEvidence(t, err)
		if got.Reason != "freshness_gap" || got.Gap != int64(gap) || got.Record == nil || got.Previous == nil || got.Record.Index != 1 || got.Previous.Index != 0 || got.Record.CandidateIndex != 0 || got.Previous.CandidateIndex != 0 {
			t.Fatal("historical gap operands were not retained")
		}
		if got.Record.Candidate == nil || got.Previous.Candidate == nil || !got.Record.Candidate.ObservedAt.Equal(at.Add(gap)) || !got.Previous.Candidate.ObservedAt.Equal(at) {
			t.Fatal("gap candidate times missing")
		}
		if cycles != 1 || maxGap != max(time.Duration(0), gap) {
			t.Fatal("failure counters changed")
		}
	}
}

func TestApplicationContinuityFailureEvidenceImmutableAndPrivate(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	rows := continuityTrace(at)
	const marker = "private-evidence-marker"
	r := &rows[3]
	r.FinishedAt = at.Add(3500 * time.Millisecond)
	r.Selection.TargetID, r.Selection.ControllerID, r.Selection.NodeID = marker, marker, marker
	r.Selection.DesiredPathID, r.Selection.PreviousPathID = marker, marker
	r.Selection.Reason, r.Application.State = marker, marker
	r.Application.TargetID, r.Application.Reason = marker, marker
	r.Application.Proof = &relayapply.ApplicationProof{Interface: marker, Source: marker, Evidence: marker}
	r.Diagnostics = &relayobserve.Diagnostics{Phases: map[string]relayobserve.PhaseCost{marker: {Calls: 1}}}
	r.Selection.ObservationDiagnostics = r.Diagnostics
	c := &r.Selection.Candidates[0]
	c.PathID, c.RelayID, c.UnderlayID = marker, marker, marker
	c.Fingerprint, c.UnderlayGeneration, c.Reason, c.Exclusion = marker, marker, marker, marker
	checked := at.Add(14 * time.Second)
	_, _, err := evaluateApplicationContinuity(rows, 1, checked)
	got, before := decodeContinuityEvidence(t, err)
	if bytes.Contains(before, []byte(marker)) || bytes.Contains([]byte(err.Error()), []byte(marker)) {
		t.Fatal("sensitive identifier leaked")
	}
	if got.Record == nil || got.Record.Reason != "other" || got.Record.State != "other" {
		t.Fatal("unknown enum values were not sanitized")
	}
	// Recovery and cleanup can mutate the source slice after the verdict.
	r.Applied = false
	r.FinishedAt = checked.Add(time.Second)
	r.Selection.Policy.MaxAge = time.Hour
	c.ObservedAt, c.Eligible, c.State = checked, false, "unreachable"
	r.Selection.Candidates = nil
	after, marshalErr := json.Marshal(err)
	if marshalErr != nil || !bytes.Equal(before, after) {
		t.Fatal("later source changes overwrote failure evidence")
	}
}

func TestApplicationContinuityFailureEvidenceCandidateIndexAndOrder(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	rows := continuityTrace(at)
	rows[0].Applied = false // A later latest-proof failure is evaluated first.
	r := &rows[3]
	selected := r.Selection.Candidates[0]
	distractor := selected
	distractor.PathID = "unselected"
	r.Selection.Candidates = append(r.Selection.Candidates, selected)
	r.Selection.Candidates[0] = distractor
	r.Selection.Candidates[1].State = "private-candidate-state"
	checked := at.Add(4 * time.Second)
	_, _, err := evaluateApplicationContinuity(rows, 1, checked)
	got, b := decodeContinuityEvidence(t, err)
	if got.Reason != "selected_unreachable" || got.Record == nil || got.Record.Index != 3 || got.Record.CandidateIndex != 1 || got.Record.Count != 2 || got.Record.Candidate == nil || got.Record.Candidate.State != "other" {
		t.Fatal("selected candidate position, enum sanitization, or failure precedence changed")
	}
	if bytes.Contains(b, []byte("private-candidate-state")) {
		t.Fatal("unknown candidate state leaked")
	}
	_, _, err = evaluateApplicationContinuity(nil, 1, checked)
	got, _ = decodeContinuityEvidence(t, err)
	if got.Reason != "baseline_missing" || got.Count != 0 || !got.CheckedAt.Equal(checked) {
		t.Fatal("empty-trace failure context missing")
	}
}
