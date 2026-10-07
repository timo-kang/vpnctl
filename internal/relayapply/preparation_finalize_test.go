// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
)

// All creation runs through the normal durable one-unit path during setup.
// The measured quantum starts with complete, closed candidates awaiting only
// final ownership/inventory readback; its backend forbids any new add or lease.
type preparationFinalizeKernel struct {
	*preparationKernel
	t          *testing.T
	now        *time.Duration
	cost       time.Duration
	reads      []string
	deadlines  []time.Time
	after      func(Entry)
	readErr    error
	incomplete bool
}

func (k *preparationFinalizeKernel) Check(ctx context.Context, entry Entry, available bool) (bool, error) {
	k.t.Helper()
	if available {
		k.t.Fatal("finalization checked availability for new creation")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > NodeRebuildDuration {
		k.t.Fatal("finalization escaped the existing shared wall deadline")
	}
	k.reads = append(k.reads, entry.Candidate.PathID)
	k.deadlines = append(k.deadlines, deadline)
	ready, err := k.preparationKernel.Check(ctx, entry, available)
	*k.now += k.cost
	if k.after != nil {
		k.after(entry)
	}
	if k.readErr != nil {
		return false, k.readErr
	}
	return ready && !k.incomplete, err
}

func (k *preparationFinalizeKernel) Step(context.Context, Entry, string, string) error {
	k.t.Fatal("finalization invoked a creation step")
	return ErrConflict
}

func (k *preparationFinalizeKernel) Lease(context.Context, Entry, FreshApproval) (DeploymentLease, error) {
	k.t.Fatal("finalization attempted to grant or renew a lease")
	return DeploymentLease{}, ErrConflict
}

func preparationFinalizeFixture(t *testing.T, count int) (*Engine, *preparationFinalizeKernel, string) {
	t.Helper()
	e, original, dir, now := preparationFixture(t)
	for i := 0; i < count; i++ {
		if _, err := e.RequestPreparation(context.Background(), fmt.Sprintf("p%d", i), ""); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < count*(1+len(preparationSteps)); n++ {
		if _, err := e.rebuildCandidates(context.Background(), 1); err != nil {
			t.Fatal("durable setup failed", err)
		}
	}
	for _, intent := range e.journal.Preparations {
		if intent.Phase != "preparing" || intent.Step != len(preparationSteps) || intent.InFlight {
			t.Fatal("setup did not stop before final readback", intent)
		}
	}
	k := &preparationFinalizeKernel{preparationKernel: original, t: t, now: now, cost: 100 * time.Millisecond}
	e.backend = k
	return e, k, dir
}

func assertFinalizationClosed(t *testing.T, e *Engine, k *preparationFinalizeKernel, originalSteps int) {
	t.Helper()
	if k.steps != originalSteps || k.renewals != 0 {
		t.Fatal("finalization changed kernel resources or granted a lease", k.steps, k.renewals)
	}
	for path, active := range k.active {
		if active {
			t.Fatal("finalization opened a candidate lease", path)
		}
	}
	if err := validatePreparations(e.journal); err != nil {
		t.Fatal("invalid durable preparation state", err)
	}
}

func TestPreparationFinalizationsShareQuantumWithoutRecheckingCompleted(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			e, k, dir := preparationFinalizeFixture(t, count)
			start, steps := *k.now, k.steps
			_, err := e.RebuildCandidates(context.Background())
			assertFinalizationClosed(t, e, k, steps)
			if err != nil {
				t.Fatal("completed candidate was revisited or valid readback failed", err)
			}
			// Reopen the actual journal: advancing in-memory flags is insufficient.
			e = reopen(t, e, dir)
			for _, intent := range e.journal.Preparations {
				if intent.Phase != "ready" || intent.Step != 0 || intent.Failures != 0 || intent.RetryBootNS != 0 || intent.Reason != "awaiting_fresh_lease" {
					t.Fatalf("candidate waited for another admission with %s left: path=%s phase=%s step=%d failures=%d", NodeRebuildDuration-(*k.now-start), intent.PathID, intent.Phase, intent.Step, intent.Failures)
				}
				if e.journal.Entries[e.index(intent.PathID)].Phase != "prepared" {
					t.Fatal("intent became ready without a durable prepared entry")
				}
			}
			if len(k.reads) != count || *k.now-start != time.Duration(count)*k.cost {
				t.Fatal("completed candidate was rechecked in the same quantum", k.reads)
			}
			for _, deadline := range k.deadlines {
				if !deadline.Equal(k.deadlines[0]) {
					t.Fatal("finalizations used separate wall deadlines")
				}
			}
			assertFinalizationClosed(t, e, k, steps)
		})
	}
}

func TestPreparationFinalizationsRetainHeadroomAndUnitLimits(t *testing.T) {
	for _, mode := range []string{"boottime-reserve", "parent-wall-reserve", "one-unit-limit"} {
		t.Run(mode, func(t *testing.T) {
			e, k, dir := preparationFinalizeFixture(t, 2)
			ctx := context.Background()
			if mode == "boottime-reserve" {
				k.cost = 300 * time.Millisecond // 450ms left is below the unchanged reserve.
			}
			if mode == "parent-wall-reserve" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 400*time.Millisecond)
				defer cancel()
			}
			steps := k.steps
			var err error
			if mode == "one-unit-limit" {
				_, err = e.rebuildCandidates(ctx, 1)
			} else {
				_, err = e.RebuildCandidates(ctx)
			}
			if err != nil || !reflect.DeepEqual(k.reads, []string{"p0"}) {
				t.Fatal("existing headroom or unit boundary changed", k.reads, err)
			}
			e = reopen(t, e, dir)
			if e.journal.Preparations[0].Phase != "ready" || e.journal.Preparations[1].Phase != "preparing" || e.journal.Preparations[1].Step != len(preparationSteps) {
				t.Fatal("headroom-limited quantum lost durable progress", e.preparationStatus())
			}
			assertFinalizationClosed(t, e, k, steps)
		})
	}
}

func TestPreparationFinalizationRejectsFailedLiveReadback(t *testing.T) {
	for _, mode := range []string{"ownership-error", "kernel-incomplete", "underlay-changed", "approval-denied", "boottime-deadline", "parent-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			e, k, dir := preparationFinalizeFixture(t, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "ownership-error":
				k.readErr = ErrConflict
			case "kernel-incomplete":
				k.incomplete = true
			case "underlay-changed":
				k.after = func(Entry) { e.collector = &preparationInventory{source: "192.0.2.11"} }
			case "approval-denied":
				k.after = func(Entry) {
					if _, err := e.cache.Refresh(context.Background(), deniedIssuer{}); err == nil {
						t.Fatal("approval denial was not injected")
					}
				}
			case "boottime-deadline":
				k.cost = NodeRebuildDuration
			case "parent-cancelled":
				k.after = func(Entry) { cancel() }
			}
			steps := k.steps
			// Stop at the failed durable boundary, before later idempotent cleanup.
			e.rebuildCandidates(ctx, 1)
			if !reflect.DeepEqual(k.reads, []string{"p0"}) {
				t.Fatal("live final readback was not exercised", k.reads)
			}
			e = reopen(t, e, dir)
			intent := e.journal.Preparations[0]
			if intent.Phase != "removing" || intent.Reason != "prepare_readback_failed" || e.journal.Entries[0].Phase != "releasing" {
				t.Fatal("failed final readback became ready or lost cleanup ownership", intent)
			}
			assertFinalizationClosed(t, e, k, steps)
		})
	}
}

func TestPreparationFinalizationSaveFailureStopsFollowingCandidate(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			e, k, dir := preparationFinalizeFixture(t, 2)
			originalSave := e.save
			injected := errors.New("fixture: finalization save interrupted")
			calls := 0
			e.save = func(b []byte) error {
				calls++
				if committed {
					if err := originalSave(b); err != nil {
						return err
					}
				}
				return injected
			}
			steps := k.steps
			if _, err := e.RebuildCandidates(context.Background()); !errors.Is(err, injected) || !e.uncertain || calls != 1 || !reflect.DeepEqual(k.reads, []string{"p0"}) {
				t.Fatal("save failure allowed a following candidate", err, calls, k.reads)
			}
			if _, err := e.RebuildCandidates(context.Background()); !errors.Is(err, relaycache.ErrUncertain) || len(k.reads) != 1 {
				t.Fatal("uncertain journal continued finalization", err)
			}
			e = reopen(t, e, dir)
			want := "preparing"
			if committed {
				want = "ready"
			}
			if e.journal.Preparations[0].Phase != want || e.journal.Preparations[1].Phase != "preparing" {
				t.Fatal("save boundary was not preserved on reopen", e.preparationStatus())
			}
			assertFinalizationClosed(t, e, k, steps)
		})
	}
}

func TestPreparationCompletionSkipDoesNotSurviveQuantum(t *testing.T) {
	e, k, _ := preparationFinalizeFixture(t, 1)
	steps := k.steps
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Completion is scheduling state for one quantum, not lease evidence.
	// Without intervening fresh maintenance, a new admission must still reject
	// the closed prepared candidate through the existing expired-lease path.
	if _, err := e.RebuildCandidates(context.Background()); !errors.Is(err, ErrLeaseExpired) {
		t.Fatal("completion skip survived into another quantum", err)
	}
	if !reflect.DeepEqual(k.reads, []string{"p0", "p0"}) || e.journal.Preparations[0].Reason != "awaiting_fresh_lease" || e.journal.Preparations[0].Failures != 1 {
		t.Fatal("later admission did not check the closed ready candidate", k.reads, e.preparationStatus())
	}
	assertFinalizationClosed(t, e, k, steps)
}
