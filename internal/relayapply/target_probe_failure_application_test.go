// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func TestTargetProbeFailureSurvivesApplicationJSONAndRecovery(t *testing.T) {
	e, _, _, _ := appFixture(t)
	s := activateApp(t, e)
	k := kernel{targetLookup: func(context.Context, Entry, relaycatalog.Target) error {
		return errors.New("private route error")
	}}
	e.probe = func(ctx context.Context, entry Entry, target relaycatalog.Target) (targetProof, error) {
		return k.probeTargetWithDial(ctx, entry, target, func(context.Context, Entry, relaycatalog.Target) (net.Conn, error) {
			t.Error("connected without route evidence")
			return nil, errors.New("unexpected dial")
		})
	}
	out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
	if err == nil || out.Applied || !out.Application.Guarded || out.Selection.Reason != "candidate_evidence_incomplete" {
		t.Fatal("missing proof did not quarantine the application")
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal("could not encode application result")
	}
	var decoded TargetReconcileResult
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal("could not decode application result")
	}
	failures := 0
	for _, candidate := range decoded.Selection.Candidates {
		if candidate.ProbeFailure == nil {
			continue // Unprepared candidates never reached the probe.
		}
		failures++
		f := candidate.ProbeFailure
		if candidate.State != "unknown" || candidate.Eligible || candidate.ConsecutiveSuccesses != 0 || candidate.ConfirmationGap != 0 ||
			f.Stage != "route_before" || f.Cause != "unavailable" || f.ContextState != "active" {
			t.Fatal("application JSON changed the probe evidence or its decision")
		}
	}
	if failures != 3 {
		t.Fatal("application JSON lost a prepared candidate's failure")
	}
	appProbes(e)
	for i := 0; i < 2; i++ {
		out, err = e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
		if i == 0 && (err == nil || out.Applied || !out.Application.Guarded) {
			t.Fatal("recovery bypassed consecutive confirmation")
		}
		if i == 1 && (err != nil || !out.Applied || !out.Application.Activated) {
			t.Fatal("fresh confirmed recovery was rejected")
		}
		for _, c := range out.Selection.Candidates {
			if c.ProbeFailure != nil {
				t.Fatal("old probe failure leaked into a later observation")
			}
		}
	}
}
