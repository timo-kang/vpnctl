// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

func handoffFixture(t *testing.T) (*Engine, *targetMachine, *fakeNodeLease, string, *targetProbeHandoff) {
	t.Helper()
	e, m, k, dir := appFixture(t)
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	entry := e.journal.Entries[0]
	h, failure := e.prepareTargetProbeHandoff(ctx, entry, entry.Candidate.Targets[0], time.Second,
		TargetObservation{PathID: entry.Candidate.PathID}, leaseBootTime)
	if h == nil {
		t.Fatalf("handoff preparation: %s", failure.Reason)
	}
	t.Cleanup(func() { h.Close() })
	return e, m, k, dir, h
}

func TestProbeHandoffReopensAndConsumesOnce(t *testing.T) {
	e, m, k, dir, h := handoffFixture(t)
	e.Close()
	fresh := reopenTarget(t, e, m, dir)
	before := k.renewals
	h.run(successfulAttempt)
	observed := h.attempt.observation.ObservedAt
	out := fresh.finishTargetProbeHandoff(context.Background(), h)
	if out.State != "reachable" || !out.ObservedAt.Equal(observed) || observed.IsZero() || k.renewals != before {
		t.Fatalf("fresh ownership did not validate original evidence: %s", out.Reason)
	}
	if h.scope.Matches(fresh.cache) {
		t.Fatal("consumed handoff leaked scope descriptors")
	}
	if again := fresh.finishTargetProbeHandoff(context.Background(), h); again.State != "unknown" || again.Reason != "probe_attempt_unavailable" {
		t.Fatal("handoff replay accepted")
	}
}

func TestProbeHandoffRejectsChangedTargetBeforeLeaseMutation(t *testing.T) {
	for _, mode := range []string{"removed", "recreated", "revision_aba", "exhausted", "candidate", "domain", "closed", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			e, m, k, dir, h := handoffFixture(t)
			e.Close()
			fresh := reopenTarget(t, e, m, dir)
			switch mode {
			case "removed":
				fresh.journal.Targets = nil
			case "recreated":
				fresh.journal.Targets[0].Owner = "vpnctl:11111111111111111111111111111111"
			case "revision_aba":
				fresh.journal.Targets[0].RouteRevision += 2
			case "exhausted":
				fresh.journal.Targets[0].RouteRevision = ^uint64(0)
			case "candidate":
				fresh.journal.Entries[0].Metric++
			case "domain":
				fresh.journal.Domain += "-new"
			case "closed":
				fresh.Close()
			case "uncertain":
				fresh.uncertain = true
			}
			k.active["p0"] = false // A stale proof must not block a replacement.
			checks, blocks := 0, k.blocks
			k.onCheck = func() { checks++ }
			h.run(successfulAttempt)
			out := fresh.finishTargetProbeHandoff(context.Background(), h)
			if out.State != "unknown" || checks != 0 || k.blocks != blocks {
				t.Fatalf("changed ownership used old proof: %s", out.Reason)
			}
		})
	}
}

func TestProbeHandoffRejectsNewEngineWithOriginalStore(t *testing.T) {
	e, _, k, _, h := handoffFixture(t)
	e.Close()
	fresh, err := open(e.cache, e.underlays, e.journal.Domain, e.backend)
	if err != nil {
		t.Fatal(err)
	}
	fresh.collector = e.collector
	h.run(successfulAttempt)
	checks := 0
	k.onCheck = func() { checks++ }
	out := fresh.finishTargetProbeHandoff(context.Background(), h)
	if out.State != "unknown" || checks != 0 {
		t.Fatal("same cache lifetime was accepted")
	}
}

func prepareHandoffFor(t *testing.T, e *Engine, ctx context.Context, clock func() (time.Duration, error)) *targetProbeHandoff {
	t.Helper()
	entry := e.journal.Entries[0]
	h, failure := e.prepareTargetProbeHandoff(ctx, entry, entry.Candidate.Targets[0], time.Second, TargetObservation{PathID: entry.Candidate.PathID}, clock)
	if h == nil {
		t.Fatalf("handoff preparation: %s", failure.Reason)
	}
	t.Cleanup(h.Close)
	return h
}

func TestProbeHandoffOriginalMonitorCannotBeReplaced(t *testing.T) {
	for _, mode := range []string{"changed", "lost", "absent"} {
		t.Run(mode, func(t *testing.T) {
			e, m, k, dir := appFixture(t)
			events := &testUnderlayEvents{}
			ctx := relayobserve.WithUnderlayEvents(context.Background(), events)
			if mode == "absent" {
				ctx = context.Background()
			}
			entry := e.journal.Entries[0]
			h, failure := e.prepareTargetProbeHandoff(ctx, entry, entry.Candidate.Targets[0], time.Second, TargetObservation{}, leaseBootTime)
			if mode == "absent" {
				if h != nil {
					h.Close()
					t.Fatal("missing monitor accepted")
				}
				if failure.Reason != "underlay_events_unavailable" {
					t.Fatal(failure.Reason)
				}
				return
			}
			if h == nil {
				t.Fatal(failure.Reason)
			}
			defer h.Close()
			e.Close()
			fresh := reopenTarget(t, e, m, dir)
			h.run(successfulAttempt)
			if mode == "lost" {
				events.unavailable.Store(true)
			} else {
				events.version.Add(1)
			}
			k.active["p0"] = false
			before := k.blocks
			// A fresh provider starts at the old generation. It must not replace
			// the lost stream, even when the caller supplies it deliberately.
			caller := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
			out := fresh.finishTargetProbeHandoff(caller, h)
			if out.State != "unknown" || k.blocks != before {
				t.Fatal("original event history lost")
			}
		})
	}
}

func TestProbeHandoffRevalidatesAuthorityAndConsent(t *testing.T) {
	for _, mode := range []string{"revoked", "generation", "catalog", "consent", "intent_aba", "manual_to_intent"} {
		t.Run(mode, func(t *testing.T) {
			e, m, k, dir := appFixture(t)
			if mode == "consent" || mode == "intent_aba" {
				p := PreparationIntent{PathID: "p0", Controller: e.journal.Entries[0].Controller, Revision: strings.Repeat("a", 32), Phase: "ready", TerminalScope: terminalScope(e.journal.Entries[0])}
				e.journal.Preparations = append(e.journal.Preparations, p)
				if err := e.cache.AllowPreparation(p.PathID, p.Revision); err != nil {
					t.Fatal(err)
				}
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
			}
			h := prepareHandoffFor(t, e, relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{}), leaseBootTime)
			e.Close()
			fresh := reopenTarget(t, e, m, dir)
			switch mode {
			case "revoked":
				if _, err := fresh.cache.Refresh(context.Background(), deniedIssuer{}); err == nil {
					t.Fatal("revocation fixture failed")
				}
			case "generation", "catalog":
				r, err := fresh.cache.Status()
				if err != nil {
					t.Fatal(err)
				}
				v := *r.Catalog
				v.Generation++
				if mode == "catalog" {
					v.Spec.Relays[0].Site = "changed-site"
				}
				if _, err := fresh.cache.Refresh(context.Background(), observationIssuer{v}); err != nil {
					t.Fatal(err)
				}
			case "consent":
				if err := fresh.cache.RevokePreparation("p0"); err != nil {
					t.Fatal(err)
				}
			case "intent_aba":
				fresh.journal.Preparations[0].Revision = strings.Repeat("b", 32)
				if err := fresh.cache.AllowPreparation("p0", fresh.journal.Preparations[0].Revision); err != nil {
					t.Fatal(err)
				}
			case "manual_to_intent":
				fresh.journal.Preparations = append(fresh.journal.Preparations, PreparationIntent{PathID: "p0", Revision: strings.Repeat("a", 32)})
				if err := fresh.cache.AllowPreparation("p0", strings.Repeat("a", 32)); err != nil {
					t.Fatal(err)
				}
			}
			h.run(successfulAttempt)
			checks, blocks := 0, k.blocks
			k.onCheck = func() { checks++ }
			out := fresh.finishTargetProbeHandoff(context.Background(), h)
			if out.State != "unknown" || checks != 0 || k.blocks != blocks {
				t.Fatalf("changed authority used old proof: %s", out.Reason)
			}
		})
	}
}

func TestProbeHandoffFreshKernelInventoryAndLeaseChecks(t *testing.T) {
	for _, mode := range []string{"kernel", "inventory", "lease"} {
		t.Run(mode, func(t *testing.T) {
			e, m, k, dir, h := handoffFixture(t)
			// Even an old wave checker saying 'ready' cannot mask fresh state.
			h.attempt.ctx = context.WithValue(h.attempt.ctx, observationCheckerKey{}, ownedObservationChecker{owner: e, check: func(context.Context, Entry, bool) (bool, error) { return true, nil }})
			e.Close()
			fresh := reopenTarget(t, e, m, dir)
			h.run(successfulAttempt)
			before := k.renewals
			switch mode {
			case "kernel":
				k.foreign = true
			case "inventory":
				fresh.collector = &inventory{down: true}
			case "lease":
				k.active["p0"] = false
			}
			blocks := k.blocks
			out := fresh.finishTargetProbeHandoff(context.Background(), h)
			if out.State != "unknown" || k.renewals != before {
				t.Fatal("stale readiness accepted or renewed")
			}
			if mode == "lease" && k.blocks != blocks+1 {
				t.Fatal("inactive owned lease was not blocked")
			}
		})
	}
}

func TestProbeHandoffOriginalLifetimeIncludesReentryAndPostcheck(t *testing.T) {
	for _, mode := range []string{"cancel", "caller_cancel", "deadline", "suspend", "rollback", "clock_error", "postcheck_suspend", "postcheck_cancel"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, m, k, dir := appFixture(t)
				base := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
				ctx, cancel := context.WithCancel(base)
				defer cancel()
				if mode == "deadline" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 200*time.Millisecond)
					defer stop()
				}
				now := time.Hour
				var clockErr error
				h := prepareHandoffFor(t, e, ctx, func() (time.Duration, error) { return now, clockErr })
				e.Close()
				fresh := reopenTarget(t, e, m, dir)
				h.run(successfulAttempt)
				observed := h.attempt.observation.ObservedAt
				caller, callerCancel := context.WithCancel(context.Background())
				defer callerCancel()
				switch mode {
				case "cancel":
					cancel()
				case "caller_cancel":
					callerCancel()
				case "deadline":
					<-ctx.Done()
				case "suspend":
					now = h.untilBoot
				case "rollback":
					now = h.startedBoot - time.Nanosecond
				case "clock_error":
					clockErr = errors.New("clock unavailable")
				case "postcheck_suspend":
					k.onCheck = func() { now = h.untilBoot }
				case "postcheck_cancel":
					k.onCheck = cancel
				}
				out := fresh.finishTargetProbeHandoff(caller, h)
				if out.State != "unknown" || !out.ObservedAt.Equal(observed) {
					t.Fatalf("expired evidence refreshed or accepted: %s", out.Reason)
				}
				if h.scope.Matches(fresh.cache) {
					t.Fatal("failed handoff retained descriptors")
				}
			})
		})
	}
}

// Register cleanup before any fatal path; a refused/expired worker may never
// enter the callback. No scheduling or host-speed assumption controls progress.
func blockedHandoffWorker(t *testing.T, h *targetProbeHandoff) (func(), <-chan struct{}) {
	t.Helper()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseAndJoin := func() {
		once.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("worker failed to join")
		}
	}
	t.Cleanup(releaseAndJoin)
	go func() {
		defer close(done)
		h.run(func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
			close(started)
			<-release
			return successfulAttempt(context.Background(), Entry{}, relaycatalog.Target{})
		})
	}()
	select {
	case <-started:
	case <-done:
		t.Fatal("worker refused to start")
	case <-h.attempt.ctx.Done():
		t.Fatal("worker did not start before original deadline")
	}
	return releaseAndJoin, done
}

func TestProbeHandoffEarlyConsumerDoesNotRaceWorker(t *testing.T) {
	e, m, _, dir, h := handoffFixture(t)
	releaseAndJoin, _ := blockedHandoffWorker(t, h)
	e.Close()
	fresh := reopenTarget(t, e, m, dir)
	out := fresh.finishTargetProbeHandoff(context.Background(), h)
	releaseAndJoin()
	if out.Reason != "probe_attempt_unavailable" {
		t.Fatal("in-flight result consumed")
	}
	if fresh.finishTargetProbeHandoff(context.Background(), h).Reason != "probe_attempt_unavailable" {
		t.Fatal("late worker resurrected consumed proof")
	}
}

func TestProbeHandoffWorkerDoesNotRetainCacheAdmission(t *testing.T) {
	e, _, k, dir, h := handoffFixture(t)
	_, done := blockedHandoffWorker(t, h)
	e.Close()
	if err := e.cache.Close(); err != nil {
		t.Fatal(err)
	}
	// A separate cooperating job makes real durable/FIFO progress while TCP
	// remains blocked. Kernel operations are fakes; host networking is untouched.
	ctx, cancel := context.WithTimeout(h.attempt.ctx, time.Second)
	defer cancel()
	cache, err := relaycache.OpenQueued(ctx, dir, relaycache.Options{NodeID: e.journal.Node})
	if err != nil {
		t.Fatal("worker retained ownership", err)
	}
	defer cache.Close()
	other, err := open(cache, e.underlays, e.journal.Domain, k)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.collector = e.collector
	before := k.renewals
	if _, err := other.MaintainLeases(ctx); err != nil || k.renewals <= before {
		t.Fatal("other owner could not maintain candidates", err)
	}
	select {
	case <-done:
		t.Fatal("worker did not remain blocked")
	default:
	}
}

func TestProbeHandoffDoesNotStartAfterBootDeadline(t *testing.T) {
	e, _, _, _ := appFixture(t)
	now := time.Hour
	h := prepareHandoffFor(t, e, relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{}), func() (time.Duration, error) { return now, nil })
	now = h.untilBoot // Model suspend without changing this host's clocks/power.
	called := false
	h.run(func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		called = true
		return targetProof{}, nil
	})
	if called || h.attempt.state.Load() != 3 {
		t.Fatal("expired ticket started socket work or remained usable")
	}
}
