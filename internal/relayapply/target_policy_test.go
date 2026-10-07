// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayselect"
)

func TestManualReconcileSkipsUnselectableProofsButEnforcesEveryLease(t *testing.T) {
	e, _, k, _ := appFixture(t)
	for i := 3; i < 8; i++ {
		if _, err := e.PrepareApplication(context.Background(), fmt.Sprint("p", i), ""); err != nil {
			t.Fatal(err)
		}
	}
	policy := relayselect.DefaultPolicy()
	policy.Mode, policy.ManualPin = "manual", "p7"
	s, err := relayselect.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	var unwanted, pinned atomic.Int32
	pinDown := false
	e.probe = func(_ context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
		if entry.Candidate.PathID != "p7" {
			unwanted.Add(1)
			return targetProof{}, errors.New("unselectable candidate unavailable")
		}
		pinned.Add(1)
		if pinDown {
			return targetProof{}, errors.New("pinned candidate unavailable")
		}
		return targetProof{handshake: 1, rx: 1, tx: 1}, nil
	}
	k.failPath = "p0" // An excluded candidate still has to be blocked.
	for cycle := 0; cycle < 3; cycle++ {
		before := k.renewals
		out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
		if cycle == 0 && (err == nil || out.Applied || !out.Application.Guarded) {
			t.Fatal("manual pin skipped fresh confirmation", out, err)
		}
		if cycle > 0 && (err != nil || !out.Applied || out.Selection.DesiredPathID != "p7") {
			t.Fatal("unselectable candidate interrupted healthy pin", out, err)
		}
		if k.renewals-before != 7 || k.active["p0"] || !k.active["p1"] || k.blocks == 0 {
			t.Fatal("policy filtering bypassed independent lease enforcement", k.renewals-before, k.active)
		}
		if len(out.Selection.Candidates) != 8 {
			t.Fatal("policy filtering lost diagnostic rows", out.Selection)
		}
		for _, c := range out.Selection.Candidates {
			if c.PathID != "p7" && (c.State != "excluded" || c.Exclusion != "manual_pin" || c.Eligible || c.Samples != 0 || c.Handshake != 0 || c.Fingerprint != "") {
				t.Fatal("skipped proof fabricated health or loss", c)
			}
		}
	}
	if unwanted.Load() != 0 || pinned.Load() == 0 {
		t.Fatal("manual policy still probes other seven paths", unwanted.Load(), pinned.Load())
	}
	pinDown = true
	if out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second); err == nil || out.Applied || !out.Application.Guarded || out.Selection.DesiredPathID != "" {
		t.Fatal("failed pin fell back to an excluded candidate", out, err)
	}
}

func TestPolicyExclusionsDoNotChangeFullDiagnosticObservation(t *testing.T) {
	e, _ := waveFixture(t)
	policy := relayselect.DefaultPolicy()
	policy.Mode, policy.ManualPin, policy.MaxCost = "manual", "p7", 0
	s, err := relayselect.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	probe := func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		calls.Add(1)
		return targetProof{handshake: 1, rx: 1, tx: 1}, nil
	}
	filtered, err := e.observeTargetFiltered(context.Background(), "app", "", time.Second, probe, s.ObservationExclusion)
	if err != nil || !filtered.Valid {
		t.Fatal(filtered, err)
	}
	for _, p := range filtered.Paths {
		if reason := s.ObservationExclusion(p.PathID, p.Cost); reason != "" && (p.State != "excluded" || p.Reason != reason) {
			t.Fatal("missing policy exclusion", p)
		}
	}
	calls.Store(0)
	full, err := e.observeTarget(context.Background(), "app", "", time.Second, probe)
	if err != nil || !full.Valid || calls.Load() != 8 {
		t.Fatal("selection filter leaked into unrestricted diagnostics", full, err, calls.Load())
	}
}
