//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

func continuityTrace(at time.Time) []relayapply.TargetReconcileResult {
	var rows []relayapply.TargetReconcileResult
	for i := 0; i < 4; i++ {
		rows = append(rows, relayapply.TargetReconcileResult{Applied: true,
			Selection: relayselect.Decision{Policy: relayselect.DefaultPolicy(), DesiredPathID: "p00",
				Candidates: []relayselect.Candidate{{Eligible: true, TargetObservation: relayobserve.TargetObservation{
					PathID: "p00", State: "reachable", ObservedAt: at.Add(time.Duration(i) * time.Second)}}}}})
	}
	return rows
}

func TestApplicationContinuityRejectsStoppedObserver(t *testing.T) {
	at := time.Unix(1000, 0)
	rows := continuityTrace(at)
	// Payloads and lease refresh can continue even after this trace stops.
	for _, elapsed := range []time.Duration{4 * time.Second, 13 * time.Second, 13*time.Second + 1, 60 * time.Second} {
		cycles, gap, err := evaluateApplicationContinuity(rows, 1, at.Add(elapsed))
		stale := elapsed > 13*time.Second
		if (err != nil) != stale || !stale && (cycles != 3 || gap != time.Second) {
			t.Fatalf("elapsed=%s cycles=%d gap=%s err=%v", elapsed, cycles, gap, err)
		}
	}
}

func TestApplicationContinuityRejectsMissingSelectedProof(t *testing.T) {
	at := time.Unix(1000, 0)
	for _, change := range []func(*relayapply.TargetReconcileResult){
		func(r *relayapply.TargetReconcileResult) { r.Selection.Candidates = nil },
		func(r *relayapply.TargetReconcileResult) { r.Selection.DesiredPathID = "other" },
		func(r *relayapply.TargetReconcileResult) { r.Selection.Candidates[0].Eligible = false },
		func(r *relayapply.TargetReconcileResult) { r.Selection.Candidates[0].ObservedAt = at.Add(time.Minute) },
	} {
		rows := continuityTrace(at)
		change(&rows[len(rows)-1])
		if _, _, err := evaluateApplicationContinuity(rows, 1, at.Add(4*time.Second)); err == nil {
			t.Fatal("missing or invalid current selected-path evidence accepted")
		}
	}
}

func TestApplicationContinuityRejectsMissingBaseline(t *testing.T) {
	at := time.Unix(1000, 0)
	for _, baseline := range []int{-1, 0, 5} {
		if _, _, err := evaluateApplicationContinuity(continuityTrace(at), baseline, at.Add(4*time.Second)); err == nil {
			t.Fatal("invalid baseline accepted", baseline)
		}
	}
	if _, _, err := evaluateApplicationContinuity(nil, 1, at); err == nil {
		t.Fatal("empty trace accepted")
	}
}

func TestApplicationContinuityRecoveryDoesNotEraseEarlierFailure(t *testing.T) {
	at := time.Unix(1000, 0)
	for _, fault := range []string{"gap", "duplicate", "not-applied", "policy"} {
		rows := continuityTrace(at)
		switch fault {
		case "gap":
			for i := 1; i < len(rows); i++ {
				rows[i].Selection.Candidates[0].ObservedAt = at.Add(time.Duration(i+10) * time.Second)
			}
		case "duplicate":
			rows[1].Selection.Candidates[0].ObservedAt = at
		case "not-applied":
			rows[1].Applied = false
		case "policy":
			rows[1].Selection.Policy.MaxAge = 30 * time.Second
		}
		now := rows[3].Selection.Candidates[0].ObservedAt.Add(time.Second)
		if _, _, err := evaluateApplicationContinuity(rows, 1, now); err == nil {
			t.Fatal("later fresh sample masked earlier failure", fault)
		}
	}
}
