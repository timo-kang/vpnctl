// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

func TestUplinkHandoffPublishesFromReturnedEngineAndOriginalStart(t *testing.T) {
	e, m, k, dir := uplinkAppFixture(t)
	selector, ctx := prepareUplinkHandoffApp(t, e)
	current := e
	t.Cleanup(func() { current.Close(); current.cache.Close() })
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k}
	domain, now, err := LocalUplinkClock()
	if err != nil {
		t.Fatal(err)
	}
	start := now
	p, err := newUplinkPublisher("app", func() (statusStamp, error) { return statusStamp{domain, now}, nil })
	if err != nil {
		t.Fatal(err)
	}
	// Advance only the injectable publisher clock. No host clock or network
	// changes are needed to expose a restart of the observation lifetime.
	owner.beforeRelease = func() { now += uint64(2 * time.Second) }
	out, fresh, err := e.ReconcileTargetObservedWithHandoff(ctx, "app", "", selector, time.Second, p, owner)
	if fresh != nil {
		current = fresh
	}
	if err != nil || fresh == nil || fresh == e || !out.Applied || !out.Application.Activated {
		t.Fatalf("successful fresh reconciliation missing: fresh=%t applied=%t err=%v", fresh != nil && fresh != e, out.Applied, err)
	}
	if !e.closed || owner.released != 1 || owner.reacquired != 1 {
		t.Fatal("fixture did not close and reopen real ownership")
	}
	if _, err := e.cache.Status(); err == nil {
		t.Fatal("source cache remained readable after ownership release")
	}
	snapshot := p.Snapshot()
	if snapshot.Availability != "reachable" || snapshot.PathID != "p0" || snapshot.Evidence != "unbound_tcp_connect" {
		t.Fatalf("committed proof was not published from the returned Engine: %+v", snapshot)
	}
	approval, _, _, err := fresh.cache.LeaseApproval()
	if err != nil || out.Application.Proof == nil {
		t.Fatal("live approval/proof missing", err)
	}
	wantUntil := min(start+uint64(out.Selection.Policy.MaxAge), approval.UntilBootNS, out.Application.Proof.leaseDeadlineNS)
	if snapshot.ObservedBootNS != start || snapshot.ValidUntilBootNS != wantUntil || snapshot.ObservedAgeMS == nil || *snapshot.ObservedAgeMS != 2000 {
		t.Fatalf("ownership return renewed or retimed evidence: start=%d until=%d snapshot=%+v", start, wantUntil, snapshot)
	}
}

func TestUplinkHandoffCannotRefreshExpiredPublicationBudget(t *testing.T) {
	e, m, k, dir := uplinkAppFixture(t)
	selector, ctx := prepareUplinkHandoffApp(t, e)
	current := e
	t.Cleanup(func() { current.Close(); current.cache.Close() })
	domain, now, err := LocalUplinkClock()
	if err != nil {
		t.Fatal(err)
	}
	start := now
	p, err := newUplinkPublisher("app", func() (statusStamp, error) { return statusStamp{domain, now}, nil })
	if err != nil {
		t.Fatal(err)
	}
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k,
		beforeRelease: func() { now += uint64(31 * time.Second) }}
	out, fresh, err := e.ReconcileTargetObservedWithHandoff(ctx, "app", "", selector, time.Second, p, owner)
	if fresh != nil {
		current = fresh
	}
	if err != nil || !out.Applied || fresh == nil || fresh == e {
		t.Fatalf("fixture did not complete valid reconciliation: applied=%t err=%v", out.Applied, err)
	}
	snapshot := p.Snapshot()
	if snapshot.Availability != "unknown" || snapshot.Freshness != "stale" || snapshot.PathID != "" || snapshot.ObservedBootNS != start || snapshot.ValidUntilBootNS > start+uint64(out.Selection.Policy.MaxAge) {
		t.Fatalf("elapsed publication lifetime was renewed on reentry: %+v", snapshot)
	}
}

func TestUplinkHandoffInvalidInputsWithdrawBeforeOwnershipRelease(t *testing.T) {
	for _, fault := range []string{"nil_publisher", "nil_ownership", "target_mismatch"} {
		t.Run(fault, func(t *testing.T) {
			e, m, k, dir := uplinkAppFixture(t)
			selector, ctx := prepareUplinkHandoffApp(t, e)
			current := e
			t.Cleanup(func() { current.Close(); current.cache.Close() })
			p, err := NewUplinkPublisher("app")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.ReconcileTargetObserved(ctx, "app", "", selector, time.Second, p); err != nil || p.Snapshot().Availability != "reachable" {
				t.Fatal("reachable baseline missing", err)
			}
			before := p.Snapshot().Revision
			owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k}
			var ownership TargetObservationOwnership = owner
			publisher, id := p, "app"
			switch fault {
			case "nil_publisher":
				publisher = nil
			case "nil_ownership":
				ownership = nil
			case "target_mismatch":
				id = "different-target"
			}
			beforeRoutes, beforeRenewals, beforeBlocks := m.mutations, k.renewals, k.blocks
			out, fresh, err := e.ReconcileTargetObservedWithHandoff(ctx, id, "", selector, time.Second, publisher, ownership)
			if fresh != nil {
				current = fresh
			}
			if err == nil || out.Applied || fresh != e || e.closed || owner.released != 0 || owner.reacquired != 0 {
				t.Fatalf("invalid input reached ownership handoff: applied=%t released=%d reacquired=%d err=%v", out.Applied, owner.released, owner.reacquired, err)
			}
			if m.mutations != beforeRoutes || k.renewals != beforeRenewals || k.blocks != beforeBlocks {
				t.Fatal("invalid producer request mutated route or lease state")
			}
			if publisher != nil {
				snapshot := p.Snapshot()
				if snapshot.Availability != "unknown" || snapshot.ValidUntilBootNS != 0 || snapshot.Revision <= before {
					t.Fatal("rejected input retained prior reachable evidence", snapshot)
				}
			}
		})
	}
}

func TestUplinkHandoffFailureWithdrawsPriorReachabilityAndReturnsOwnership(t *testing.T) {
	for _, fault := range []string{"release", "reentry", "reentry_with_engine", "canceled", "cancel_during_release", "changed_reservation"} {
		t.Run(fault, func(t *testing.T) {
			e, m, k, dir := uplinkAppFixture(t)
			selector, ctx := prepareUplinkHandoffApp(t, e)
			current := e
			t.Cleanup(func() { current.Close(); current.cache.Close() })
			p, err := NewUplinkPublisher("app")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.ReconcileTargetObserved(ctx, "app", "", selector, time.Second, p); err != nil || p.Snapshot().Availability != "reachable" {
				t.Fatal("reachable baseline missing", err)
			}
			before := p.Snapshot().Revision
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k}
			switch fault {
			case "release":
				owner.releaseErr = errors.New("release failed")
			case "reentry", "reentry_with_engine":
				owner.reacquireErr = errors.New("reentry failed")
				owner.returnEngineOnError = fault == "reentry_with_engine"
			case "canceled":
				cancel()
			case "cancel_during_release":
				owner.beforeRelease = cancel
			case "changed_reservation":
				owner.edit = func(fresh *Engine) { fresh.journal.Targets[0].RouteRevision++ }
			}
			out, fresh, err := e.ReconcileTargetObservedWithHandoff(ctx, "app", "", selector, time.Second, p, owner)
			if fresh != nil {
				current = fresh
			}
			if err == nil || out.Applied || out.Application.Activated || fresh == nil {
				t.Fatalf("failed handoff retained authority or lost resources: applied=%t engine=%p err=%v", out.Applied, fresh, err)
			}
			if fault == "reentry_with_engine" && (fresh == e || fresh.closed) {
				t.Fatal("Engine returned with reacquisition error was not retained for cleanup")
			}
			snapshot := p.Snapshot()
			if snapshot.Availability != "unknown" || snapshot.PathID != "" || snapshot.ValidUntilBootNS != 0 || snapshot.Revision <= before {
				t.Fatalf("failed/canceled reconciliation retained prior reachable proof: %+v", snapshot)
			}
		})
	}
}

func TestUplinkHandoffWithdrawalDuringReleaseCannotBeOverwritten(t *testing.T) {
	e, m, k, dir := uplinkAppFixture(t)
	selector, ctx := prepareUplinkHandoffApp(t, e)
	current := e
	t.Cleanup(func() { current.Close(); current.cache.Close() })
	p, err := NewUplinkPublisher("app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReconcileTargetObserved(ctx, "app", "", selector, time.Second, p); err != nil || p.Snapshot().Availability != "reachable" {
		t.Fatal("reachable baseline missing", err)
	}
	before := p.Snapshot().Revision
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k, beforeRelease: p.Unavailable}
	out, fresh, err := e.ReconcileTargetObservedWithHandoff(ctx, "app", "", selector, time.Second, p, owner)
	if fresh != nil {
		current = fresh
	}
	if err != nil || !out.Applied || fresh == nil || fresh == e {
		t.Fatalf("withdrawal fixture did not finish actual reconciliation: applied=%t err=%v", out.Applied, err)
	}
	snapshot := p.Snapshot()
	if snapshot.Availability != "unknown" || snapshot.ValidUntilBootNS != 0 || snapshot.Revision <= before {
		t.Fatal("delayed handoff result revived withdrawn publication", snapshot)
	}
}

// Confirmation and the handoff must observe the same event stream. Switching
// from the unmonitored fixture to a monitored stream deliberately resets the
// selector's evidence and would test confirmation instead of publication.
func prepareUplinkHandoffApp(t *testing.T, e *Engine) (*relayselect.Selector, context.Context) {
	t.Helper()
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	selector := appSelector(t)
	for i := 0; i < 2; i++ {
		out, err := e.ReconcileTarget(ctx, "app", "", selector, time.Second)
		if i == 0 && (err == nil || out.Applied || !out.Application.Guarded) {
			t.Fatal("initial confirmation was not required", err)
		}
		if i == 1 && (err != nil || !out.Applied || !out.Application.Activated) {
			t.Fatal("monitored target confirmation failed", err)
		}
	}
	return selector, ctx
}

type deniedUplinkReentry struct{ *testObservationOwner }

func (o *deniedUplinkReentry) Reacquire(ctx context.Context) (*Engine, error) {
	fresh, err := o.testObservationOwner.Reacquire(ctx)
	if fresh != nil {
		_, refreshErr := fresh.cache.Refresh(ctx, &rejectTargetApproval{})
		err = errors.Join(err, refreshErr)
	}
	return fresh, err
}

func TestUplinkHandoffFailedOwnerCannotPublishNegativePolicy(t *testing.T) {
	e, m, k, dir := uplinkAppFixture(t)
	selector, ctx := prepareUplinkHandoffApp(t, e)
	current := e
	t.Cleanup(func() { current.Close(); current.cache.Close() })
	p, err := NewUplinkPublisher("app")
	if err != nil {
		t.Fatal(err)
	}
	owner := &deniedUplinkReentry{&testObservationOwner{dir: dir, source: e, machine: m, kernel: k,
		reacquireErr: errors.New("ownership unavailable"), returnEngineOnError: true}}
	out, fresh, err := e.ReconcileTargetObservedWithHandoff(ctx, "app", "", selector, time.Second, p, owner)
	if fresh != nil {
		current = fresh
	}
	if err == nil || fresh == nil || fresh == e || out.Applied {
		t.Fatal("failed reacquisition did not return fresh cleanup ownership", err)
	}
	report, statusErr := fresh.cache.Status()
	if statusErr != nil || report.BlockedReason != "identity_denied" {
		t.Fatal("fixture did not invalidate the returned owner's approval", statusErr)
	}
	if got := p.Snapshot(); got.Availability != "unknown" || got.ValidUntilBootNS != 0 {
		t.Fatal("unaccepted owner supplied policy evidence", got)
	}
}
