//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"time"

	"vpnctl/internal/relayapply"
)

// These value snapshots deliberately exclude identifiers, proof/configuration,
// and arbitrary diagnostic strings. They never retain the source record slice.
type continuityCandidate struct {
	Eligible   bool           `json:"eligible"`
	State      string         `json:"state"`
	ObservedAt time.Time      `json:"observed_at"`
	Age        *time.Duration `json:"age_ns,omitempty"`
}

type continuityRecord struct {
	Index            int                  `json:"index"`
	Applied          bool                 `json:"applied"`
	FinishedAt       time.Time            `json:"finished_at"`
	PolicyMaxAge     time.Duration        `json:"policy_max_age_ns"`
	PolicySuccesses  int                  `json:"policy_successes"`
	SelectionReason  string               `json:"selection_reason"`
	ApplicationState string               `json:"application_state"`
	CandidateCount   int                  `json:"candidate_count"`
	CandidateIndex   int                  `json:"candidate_index"`
	Candidate        *continuityCandidate `json:"candidate,omitempty"`
}

type continuityRead struct {
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Elapsed    time.Duration `json:"elapsed_ns"`
}

type continuityFailure struct {
	SchemaVersion int               `json:"schema_version"`
	Reason        string            `json:"reason"`
	CheckedAt     time.Time         `json:"checked_at"`
	Baseline      int               `json:"baseline"`
	RecordCount   int               `json:"record_count"`
	Record        *continuityRecord `json:"record,omitempty"`
	Previous      *continuityRecord `json:"previous,omitempty"`
	Gap           time.Duration     `json:"gap_ns"`
	Role          string            `json:"role,omitempty"`
	Read          *continuityRead   `json:"read,omitempty"`
}

func (f *continuityFailure) Error() string { return "application continuity failed: " + f.Reason }

func continuityEnum(value string, allowed ...string) string {
	for _, v := range allowed {
		if value == v {
			return v
		}
	}
	return "other"
}

func selectedContinuityCandidate(r relayapply.TargetReconcileResult) int {
	for i, c := range r.Selection.Candidates {
		if c.PathID == r.Selection.DesiredPathID {
			return i
		}
	}
	return -1
}

func snapshotContinuityRecord(r relayapply.TargetReconcileResult, index, candidate int, now time.Time) *continuityRecord {
	out := &continuityRecord{
		Index: index, Applied: r.Applied, FinishedAt: r.FinishedAt,
		PolicyMaxAge: r.Selection.Policy.MaxAge, PolicySuccesses: r.Selection.Policy.Successes,
		SelectionReason: continuityEnum(r.Selection.Reason, "", "observation_unavailable",
			"invalid_or_stale_observation", "identity_changed_restart_required", "generation_regressed",
			"observation_replayed", "approval_changed_without_generation", "approval_expired",
			"invalid_candidate_observation", "invalid_candidate_evidence", "manual_pin_unavailable",
			"observation_budget_exhausted", "candidate_evidence_incomplete", "target_connect_failed",
			"no_permitted_candidate", "initial_selection", "selected_path_unavailable",
			"selected_path_verified", "minimum_dwell", "recovery_hold_down", "preferred_path_recovered"),
		ApplicationState: continuityEnum(r.Application.State, "", "active", "blocked", "rolled_back", "guarded", "released"),
		CandidateCount:   len(r.Selection.Candidates), CandidateIndex: candidate,
	}
	if candidate >= 0 && candidate < len(r.Selection.Candidates) {
		c := r.Selection.Candidates[candidate]
		out.Candidate = &continuityCandidate{Eligible: c.Eligible,
			State:      continuityEnum(c.State, "", "reachable", "unreachable", "unknown", "excluded"),
			ObservedAt: c.ObservedAt}
		if !c.ObservedAt.IsZero() {
			age := now.Sub(c.ObservedAt)
			out.Candidate.Age = &age
		}
	}
	return out
}

// Read/parse timing belongs to the input actually evaluated, not a later tail
// read during cleanup. FinishedAt in Record is not stdout publication time.
func checkApplicationContinuity(path string, baseline int, role string, report map[string]any) (int, time.Duration, error) {
	started := time.Now()
	rows := applicationResults(path)
	finished := time.Now()
	cycles, gap, err := evaluateApplicationContinuity(rows, baseline, time.Now())
	if failure, ok := err.(*continuityFailure); ok {
		failure.Role = continuityEnum(role, "app", "app2")
		failure.Read = &continuityRead{StartedAt: started, FinishedAt: finished, Elapsed: finished.Sub(started)}
		// A later failure or recovery must not replace the first failed input.
		if report["continuity_failure"] == nil {
			report["continuity_failure"] = failure
		}
	}
	return cycles, gap, err
}
