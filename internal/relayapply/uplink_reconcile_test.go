// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

func TestUplinkReconcileUsesCommittedEvidenceAndWithholdsReplay(t *testing.T) {
	e, _, _, _ := uplinkAppFixture(t)
	s := appSelector(t)
	p, err := NewUplinkPublisher("app")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := e.ReconcileTargetObserved(context.Background(), "app", "", s, time.Second, p)
	if first.Applied || p.Snapshot().Availability != "unknown" {
		t.Fatal("desired/unconfirmed state became reachable")
	}
	out, err := e.ReconcileTargetObserved(context.Background(), "app", "", s, time.Second, p)
	if err != nil || !out.Applied || p.Snapshot().Availability != "reachable" {
		t.Fatal("committed proof not published", err, p.Snapshot())
	}
	snap := p.Snapshot()
	if snap.PathID != "p0" || snap.SessionContinuity != "not_established" || snap.Evidence != "unbound_tcp_connect" {
		t.Fatal("incorrect proof semantics", snap)
	}
	wire, _ := json.Marshal(out)
	var decoded TargetReconcileResult
	if json.Unmarshal(wire, &decoded) != nil {
		t.Fatal("decode result")
	}
	if decoded.Application.Proof.leaseDeadlineNS != 0 {
		t.Fatal("serialized result retained live proof authority")
	}
	if o := e.uplinkObservation(decoded, statusObservation{}); o.kind == statusReachable {
		t.Fatal("JSON replay became live reachable evidence")
	}
	if b, _ := json.Marshal(snap); strings.Contains(string(b), "vpnctl:") || strings.Contains(string(b), "controller_id") || strings.Contains(string(b), "private_key") {
		t.Fatal("private state escaped snapshot")
	}
	p.Unavailable()
	if p.Snapshot().Availability != "unknown" || p.Snapshot().Freshness != "unknown" {
		t.Fatal("admission failure retained old reachable state")
	}
}

func TestUplinkReconcilePathRevisionSurvivesReturnRollbackAndQuarantine(t *testing.T) {
	e, m, _, _ := uplinkAppFixture(t)
	s := activateApp(t, e)
	p, _ := NewUplinkPublisher("app")
	ctx := context.Background()
	reconcile := func() UplinkSnapshot {
		t.Helper()
		if _, err := e.ReconcileTargetObserved(ctx, "app", "", s, time.Second, p); err != nil {
			t.Fatal(err)
		}
		return p.Snapshot()
	}
	a := reconcile()
	e.journal.Targets[0].Generation++
	if steady := reconcile(); steady.PathRevision != a.PathRevision || steady.Revision <= a.Revision {
		t.Fatal("catalog/steady observation created a path transition")
	}
	s.RecordApplied("p1", time.Now())
	b := reconcile()
	s.RecordApplied("p0", time.Now())
	back := reconcile()
	if a.PathID != "p0" || b.PathID != "p1" || back.PathID != "p0" || b.PathRevision <= a.PathRevision || back.PathRevision <= b.PathRevision {
		t.Fatal("A-B-A lost route transitions")
	}
	s.RecordApplied("p1", time.Now())
	m.mutations, m.failAt, m.mode = 0, 1, "after"
	if out, err := e.ReconcileTargetObserved(ctx, "app", "", s, time.Second, p); err == nil || out.Application.State != "rolled_back" {
		t.Fatal("rollback fault was not exercised")
	}
	rolled := p.Snapshot()
	if rolled.Availability != "unknown" || rolled.PathRevision <= back.PathRevision {
		t.Fatal("failed operation claimed current reachability or hid rollback")
	}
	m.failAt = 0
	if live := reconcile(); live.Availability != "reachable" || live.PathRevision != rolled.PathRevision {
		t.Fatal("fresh confirmation after rollback changed route revision")
	}
	if _, err := e.quarantineTarget(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	s = activateApp(t, e) // Same path, but a real quarantine/reactivation in between.
	reactivated := reconcile()
	if reactivated.PathID != a.PathID || reactivated.PathRevision <= rolled.PathRevision {
		t.Fatal("quarantine/reactivation to same path was lost")
	}
	if _, err := e.ReleaseTarget(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReserveTarget(ctx, "app", ""); err != nil {
		t.Fatal(err)
	}
	s = activateApp(t, e)
	if reinstalled := reconcile(); reinstalled.PathID != a.PathID || reinstalled.PathRevision <= reactivated.PathRevision {
		t.Fatal("replacement installation with reset journal revision was lost")
	}
}

func TestUplinkReconcileNegativeEvidenceAndDenialAreDistinct(t *testing.T) {
	for _, fault := range []string{"unreachable", "unknown", "denied", "uncertain", "persistence", "canceled"} {
		t.Run(fault, func(t *testing.T) {
			e, _, _, _ := uplinkAppFixture(t)
			s := activateApp(t, e)
			p, _ := NewUplinkPublisher("app")
			expected := "unknown"
			switch fault {
			case "unreachable":
				expected = "unreachable"
				for i := 3; i < 8; i++ {
					if _, err := e.PrepareApplication(context.Background(), fmt.Sprintf("p%d", i), ""); err != nil {
						t.Fatal(err)
					}
				}
				e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
					return targetProof{}, &targetConnectError{"unreachable"}
				}
			case "unknown":
				e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
					return targetProof{}, errors.New("inventory unavailable")
				}
			case "denied":
				expected = "blocked"
				e.cache.Refresh(context.Background(), &rejectTargetApproval{})
			case "uncertain":
				e.uncertain = true
			case "persistence":
				e.save = func([]byte) error { return errors.New("write acknowledgement lost") }
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "canceled" {
				cancel()
			}
			e.ReconcileTargetObserved(ctx, "app", "", s, time.Second, p)
			if got := p.Snapshot().Availability; got != expected {
				t.Fatal("incorrect negative mapping", fault, got, expected)
			}
		})
	}
}

func TestUplinkReconcileRejectsDifferentTargetAndSaturatedRevision(t *testing.T) {
	e, _, _, _ := uplinkAppFixture(t)
	s := activateApp(t, e)
	p, _ := NewUplinkPublisher("another-target")
	before := e.journal.Targets[0].RouteRevision
	if _, err := e.ReconcileTargetObserved(context.Background(), "app", "", s, time.Second, p); err == nil {
		t.Fatal("publisher target mismatch accepted")
	}
	if e.journal.Targets[0].RouteRevision != before || p.Snapshot().Availability != "unknown" {
		t.Fatal("mismatched request published/changed target")
	}
	p, _ = NewUplinkPublisher("app")
	e.journal.Targets[0].RouteRevision = ^uint64(0)
	e.ReconcileTargetObserved(context.Background(), "app", "", s, time.Second, p)
	if p.Snapshot().Availability != "unknown" {
		t.Fatal("exhausted path revision claimed current route")
	}
}

func TestUplinkSaturationWithdrawsPriorReachabilityAndPreventsNewProofs(t *testing.T) {
	e, _, _, _ := uplinkAppFixture(t)
	s := activateApp(t, e)
	p, err := NewUplinkPublisher("app")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := e.ReconcileTargetObserved(ctx, "app", "", s, time.Second, p); err != nil {
		t.Fatal(err)
	}
	before := p.Snapshot()
	if before.Availability != "reachable" {
		t.Fatal("reachable baseline missing")
	}
	var candidateCalls, applicationCalls atomic.Int32
	e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		candidateCalls.Add(1)
		return targetProof{}, nil
	}
	probe := e.appProbe
	e.appProbe = func(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
		applicationCalls.Add(1)
		return probe(ctx, g, entry, target)
	}
	e.journal.Targets[0].RouteRevision = ^uint64(0)
	out, err := e.ReconcileTargetObserved(ctx, "app", "", s, time.Second, p)
	if !errors.Is(err, ErrRecovery) || out.Applied || !out.Application.Guarded || candidateCalls.Load() != 0 || applicationCalls.Load() != 0 {
		t.Fatal("saturated route accepted new work or lost safety quarantine")
	}
	g := e.journal.Targets[0]
	if g.RouteRevision != ^uint64(0) || g.Phase != "guarded" || g.Active != nil || g.Pending != nil {
		t.Fatal("saturation wrapped or retained an active route")
	}
	after := p.Snapshot()
	if after.Availability != "unknown" || after.Freshness != "unknown" || after.ValidUntilBootNS != 0 || after.PathID != "" || after.Revision <= before.Revision {
		t.Fatal("saturation retained prior reachable evidence")
	}
}

func uplinkAppFixture(t *testing.T) (*Engine, *targetMachine, *fakeNodeLease, string) {
	e, m, k, dir := appFixture(t)
	probe := e.appProbe
	e.appProbe = func(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
		p, err := probe(ctx, g, entry, target)
		p.Evidence = "unbound_tcp_connect"
		return p, err
	}
	return e, m, k, dir
}

func TestUplinkNegativeMappingPreservesSelectorRejections(t *testing.T) {
	good := relayselect.Decision{SchemaVersion: 1, State: "no_verified_path", Reason: "target_connect_failed", Policy: relayselect.DefaultPolicy(), Candidates: []relayselect.Candidate{{TargetObservation: relayobserve.TargetObservation{State: "unreachable", Reason: "unreachable"}, Exclusion: "unreachable"}}}
	if !allPermittedCandidatesUnreachable(good) {
		t.Fatal("fresh failed scope rejected")
	}
	for _, fault := range []string{"stale", "partial-invalid", "partial-duplicate", "wrong-policy"} {
		t.Run(fault, func(t *testing.T) {
			d := good
			d.Candidates = append([]relayselect.Candidate(nil), good.Candidates...)
			switch fault {
			case "stale":
				d.Candidates[0].Exclusion = "stale_observation"
			case "partial-invalid":
				d.State = "blocked"
				d.Reason = "invalid_candidate_evidence"
			case "partial-duplicate":
				d.State = "blocked"
				d.Reason = "invalid_candidate_observation"
			case "wrong-policy":
				d.Policy.Version = 99
			}
			if allPermittedCandidatesUnreachable(d) {
				t.Fatal("selector rejection was reinterpreted as current network failure")
			}
		})
	}
}
