// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func probeAttemptFixture(t *testing.T, ctx context.Context) (*Engine, *fakeNodeLease, string, *targetProbeAttempt) {
	t.Helper()
	e, k, dir := nodeLeaseFixture(t)
	if _, err := e.PrepareProtected(context.Background(), "p0", "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.MaintainLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	a, out := e.prepareTargetProbe(ctx, entry, entry.Candidate.Targets[0], time.Second, TargetObservation{PathID: "p0"})
	if a == nil {
		t.Fatalf("prepare failed: %s", out.Reason)
	}
	return e, k, dir, a
}
func successfulAttempt(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
	return targetProof{duration: time.Millisecond, handshake: 1, rx: 1, tx: 1}, nil
}

func TestProbeAttemptOwnsNestedInputsAndPreservesProofTime(t *testing.T) {
	e, _, _, a := probeAttemptFixture(t, context.Background())
	originalEntry, originalTarget := entryFingerprint(a.entry), cloneProbeTarget(a.target)
	a.run(func(_ context.Context, entry Entry, target relaycatalog.Target) (targetProof, error) {
		// A worker must not be able to mutate either the ticket or current journal.
		entry.Candidate.Pin.Table++
		entry.Candidate.Targets[0].Prefixes[0] = "198.51.100.0/24"
		target.Prefixes[0] = "203.0.113.0/24"
		return successfulAttempt(context.Background(), Entry{}, relaycatalog.Target{})
	})
	if entryFingerprint(a.entry) != originalEntry || entryFingerprint(e.journal.Entries[0]) != originalEntry || a.target.Prefixes[0] != originalTarget.Prefixes[0] {
		t.Fatal("worker changed owned inputs")
	}
	observed := a.observation.ObservedAt
	out := e.finishTargetProbe(context.Background(), a)
	if out.State != "reachable" || observed.IsZero() || !out.ObservedAt.Equal(observed) {
		t.Fatalf("proof lost its original completion time/state: %s", out.Reason)
	}
	if got := e.finishTargetProbe(context.Background(), a); got.State != "unknown" || got.Reason != "probe_attempt_unavailable" || got.RXDelta != 0 {
		t.Fatal("proof replay accepted")
	}
}

func TestProbeAttemptSnapshotSurvivesSourceMutation(t *testing.T) {
	e, k, _, a := probeAttemptFixture(t, context.Background())
	originalEntry := entryFingerprint(a.entry)
	prefix := a.target.Prefixes[0]
	e.journal.Entries[0].Candidate.Pin.Table++
	e.journal.Entries[0].Candidate.Targets[0].Prefixes[0] = "203.0.113.0/24"
	a.run(func(_ context.Context, entry Entry, target relaycatalog.Target) (targetProof, error) {
		if entryFingerprint(entry) != originalEntry || target.Prefixes[0] != prefix {
			t.Error("source mutation changed socket inputs")
		}
		return successfulAttempt(context.Background(), Entry{}, relaycatalog.Target{})
	})
	before := k.blocks
	out := e.finishTargetProbe(context.Background(), a)
	if out.State != "unknown" || out.Reason != "candidate_changed_during_probe" || k.blocks != before {
		t.Fatal("changed journal proof accepted or new state blocked")
	}
}

func TestProbeAttemptCannotEscapeOwnershipLifetime(t *testing.T) {
	for _, mode := range []string{"reopened", "closed", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			e, k, dir, a := probeAttemptFixture(t, context.Background())
			a.run(successfulAttempt)
			fresh := e
			switch mode {
			case "reopened":
				fresh = reopen(t, e, dir)
			case "closed":
				e.Close()
			case "uncertain":
				e.uncertain = true
			}
			checks, blocks := 0, k.blocks
			k.onCheck = func() { checks++ }
			out := fresh.finishTargetProbe(context.Background(), a)
			if out.Reason != "candidate_changed_during_probe" || out.State != "unknown" || checks != 0 || k.blocks != blocks {
				t.Fatal("old ownership performed validation or mutation")
			}
			if got := fresh.finishTargetProbe(context.Background(), a); got.Reason != "probe_attempt_unavailable" {
				t.Fatal("failed attempt remained reusable")
			}
		})
	}
}

func TestProbeAttemptOriginalCancellationCannotBeReplaced(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, k, _, a := probeAttemptFixture(t, ctx)
	a.run(successfulAttempt)
	observed := a.observation.ObservedAt
	cancel()
	checks, blocks := 0, k.blocks
	k.onCheck = func() { checks++ }
	out := e.finishTargetProbe(context.Background(), a)
	if out.State != "unknown" || out.Reason != "observation_deadline" || !out.ObservedAt.Equal(observed) || checks != 0 || k.blocks != blocks {
		t.Fatal("replacement context extended proof authority")
	}
	if got := e.finishTargetProbe(context.Background(), a); got.Reason != "probe_attempt_unavailable" {
		t.Fatal("expired attempt remained reusable")
	}
}

func TestProbeAttemptCurrentLeaseFailureStillBlocks(t *testing.T) {
	e, k, _, a := probeAttemptFixture(t, context.Background())
	a.run(successfulAttempt)
	k.active["p0"] = false
	blocks := k.blocks
	out := e.finishTargetProbe(context.Background(), a)
	if out.State != "unknown" || out.Reason != "lease_expired_during_probe" || k.blocks != blocks+1 {
		t.Fatal("current lease enforcement bypassed")
	}
}

func TestProbeAttemptConcurrentUseRunsAndConsumesOnce(t *testing.T) {
	e, _, _, a := probeAttemptFixture(t, context.Background())
	var calls atomic.Int32
	var workers sync.WaitGroup
	entered, release := make(chan struct{}), make(chan struct{})
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			a.run(func(ctx context.Context, entry Entry, target relaycatalog.Target) (targetProof, error) {
				if calls.Add(1) != 1 {
					t.Error("duplicate socket proof")
				}
				close(entered)
				<-release
				return successfulAttempt(ctx, entry, target)
			})
		}()
	}
	<-entered
	close(release)
	workers.Wait()
	results := make(chan TargetObservation, 4)
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); results <- e.finishTargetProbe(context.Background(), a) }()
	}
	workers.Wait()
	close(results)
	successes := 0
	for out := range results {
		if out.State == "reachable" {
			successes++
		} else if out.Reason != "probe_attempt_unavailable" {
			t.Error("unexpected concurrent result")
		}
	}
	if calls.Load() != 1 || successes != 1 {
		t.Fatal("proof was not single use")
	}
}

func TestCanceledProbeGateDiscardsWithoutEngineAccess(t *testing.T) {
	_, _, _, a := probeAttemptFixture(t, context.Background())
	a.run(successfulAttempt)
	observed := a.observation.ObservedAt
	out := a.discard("observation_deadline")
	if out.State != "unknown" || out.Reason != "observation_deadline" || !out.ObservedAt.Equal(observed) {
		t.Fatal("discard changed evidence time")
	}
	if a.discard("observation_deadline").Reason != "probe_attempt_unavailable" {
		t.Fatal("discarded result reused")
	}
}

func TestWaveInventoryCheckerBelongsToCurrentEngine(t *testing.T) {
	old := &Engine{}
	fresh := &Engine{backend: &fakeKernel{foreign: true}}
	called := false
	ctx := context.WithValue(context.Background(), observationCheckerKey{}, ownedObservationChecker{old, func(context.Context, Entry, bool) (bool, error) { called = true; return true, nil }})
	if ready, err := fresh.targetProbeChecker(ctx)(ctx, Entry{}, false); ready || err == nil || called {
		t.Fatal("new engine reused old inventory checker")
	}
	if ready, err := old.targetProbeChecker(ctx)(ctx, Entry{}, false); !ready || err != nil || !called {
		t.Fatal("current wave lost its checker")
	}
}

func TestProbeAttemptEarlyConsumptionCannotLaterBecomeHealthy(t *testing.T) {
	e, _, _, a := probeAttemptFixture(t, context.Background())
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		a.run(func(ctx context.Context, entry Entry, target relaycatalog.Target) (targetProof, error) {
			close(entered)
			<-release
			return successfulAttempt(ctx, entry, target)
		})
	}()
	<-entered
	if out := e.finishTargetProbe(context.Background(), a); out.Reason != "probe_attempt_unavailable" {
		t.Error("unfinished proof accepted")
	}
	close(release)
	<-done
	if out := e.finishTargetProbe(context.Background(), a); out.Reason != "probe_attempt_unavailable" {
		t.Fatal("late completion revived an invalidated proof")
	}
}

func TestProbePreparationRejectsUnapprovedTargetDefinition(t *testing.T) {
	for _, mode := range []string{"id", "address", "port", "protocol", "prefix"} {
		t.Run(mode, func(t *testing.T) {
			e, k, _, a := probeAttemptFixture(t, context.Background())
			target := cloneProbeTarget(a.target)
			switch mode {
			case "id":
				target.ID += "-other"
			case "address":
				target.ProbeAddress = "203.0.113.1"
			case "port":
				target.Port++
			case "protocol":
				target.Protocol = "udp"
			case "prefix":
				target.Prefixes[0] = "203.0.113.0/24"
			}
			blocks := k.blocks
			checks := 0
			k.onCheck = func() { checks++ }
			attempt, out := e.prepareTargetProbe(context.Background(), a.entry, target, time.Second, TargetObservation{PathID: "p0"})
			if attempt != nil || out.Reason != "target_definition_changed" || checks != 0 || k.blocks != blocks {
				t.Fatal("unapproved target reached lease or kernel checks")
			}
		})
	}
}

type canceledBoundaryBackend struct {
	backend
	entered chan struct{}
}

func (b canceledBoundaryBackend) Check(ctx context.Context, _ Entry, _ bool) (bool, error) {
	close(b.entered)
	<-ctx.Done()
	return false, ctx.Err()
}
func TestProbeAttemptOriginalCancellationBoundsPostcheckWork(t *testing.T) {
	original, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, _, _, a := probeAttemptFixture(t, original)
	a.run(successfulAttempt)
	entered := make(chan struct{})
	e.backend = canceledBoundaryBackend{e.backend, entered}
	replacement, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan TargetObservation, 1)
	go func() { done <- e.finishTargetProbe(replacement, a) }()
	<-entered
	cancel()
	select {
	case out := <-done:
		if out.State != "unknown" {
			t.Fatal("canceled work produced health")
		}
	case <-time.After(time.Second):
		stop()
		<-done
		t.Fatal("original cancellation did not reach postcheck")
	}
}
