// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Advance only the injected BOOTTIME clock. The fake owns no host resources;
// every operation still uses the production scheduler and durable phase rules.
type preparationProgressKernel struct {
	*preparationKernel
	now     *time.Duration
	elapsed time.Duration
	after   func()
}

func (k *preparationProgressKernel) RemoveStep(ctx context.Context, entry Entry, step string) error {
	err := k.preparationKernel.RemoveStep(ctx, entry, step)
	*k.now += k.elapsed
	if k.after != nil {
		k.after()
	}
	return err
}

func preparationRemovalProgressFixture(t *testing.T) (*Engine, *preparationProgressKernel, *time.Duration) {
	t.Helper()
	e, backend, _, now := preparationFixture(t)
	ctx := context.Background()
	if _, err := e.PrepareApplication(ctx, "p0", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RequestPreparation(ctx, "p0", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.startPreparationRemoval(e.preparationIndex("p0"), e.index("p0"), "candidate_inventory_changed"); err != nil {
		t.Fatal(err)
	}
	k := &preparationProgressKernel{preparationKernel: backend, now: now}
	e.backend = k
	// Isolate scheduling from disk latency. Adjacent crash/fault tests verify
	// the real journal writes; no durability behavior is replaced in production.
	e.save = func([]byte) error { return nil }
	return e, k, now
}

func TestPreparationRemovalUsesRemainingSharedBudget(t *testing.T) {
	e, k, now := preparationRemovalProgressFixture(t)
	k.elapsed = 50 * time.Millisecond
	start, creations := *now, k.steps
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	// All eight idempotent cleanup stages fit in 400ms of the existing 750ms
	// quantum. Yielding at 300ms leaves owned cleanup waiting for admission
	// even though no creation operation needs the remaining 500ms reserve.
	p := e.journal.Preparations[e.preparationIndex("p0")]
	if p.Phase != "waiting" || e.index("p0") >= 0 || len(k.objects["p0"]) != 0 {
		t.Fatalf("owned cleanup yielded with %s remaining: phase=%s step=%d", NodeRebuildDuration-(*now-start), p.Phase, p.Step)
	}
	if *now-start >= NodeRebuildDuration || k.steps != creations || k.active["p0"] {
		t.Fatal("cleanup exceeded the quantum or created/opened a candidate")
	}
	if err := validatePreparations(e.journal); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationRemovalDoesNotSpendCreationReserve(t *testing.T) {
	e, k, _ := preparationRemovalProgressFixture(t)
	// Stop at the final idempotent readback so this call completes removal and
	// encounters a new preparation with only 450ms of the shared budget left.
	for n := 0; n < len(preparationRemovalSteps)-1; n++ {
		if _, err := e.rebuildCandidates(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	}
	k.elapsed = 300 * time.Millisecond
	creations := k.steps
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.steps != creations || len(k.objects["p0"]) != 0 || k.active["p0"] {
		t.Fatal("creation used the cleanup remainder without its own headroom")
	}
	if err := validatePreparations(e.journal); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationRemovalBudgetExhaustionRemainsRetryable(t *testing.T) {
	e, k, now := preparationRemovalProgressFixture(t)
	k.elapsed = NodeRebuildDuration
	creations := k.steps
	if _, err := e.RebuildCandidates(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shared cleanup BOOTTIME deadline ignored", err)
	}
	p := e.journal.Preparations[e.preparationIndex("p0")]
	if p.Phase != "removing" || p.Step != 0 || p.InFlight || k.steps != creations || k.active["p0"] {
		t.Fatal("interrupted cleanup was committed, opened traffic, or lost retryability", p)
	}
	*now += 31 * time.Second
	k.elapsed = 0
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	p = e.journal.Preparations[e.preparationIndex("p0")]
	if p.Phase != "waiting" || e.index("p0") >= 0 || k.active["p0"] {
		t.Fatal("idempotent cleanup did not recover within the next quantum", p)
	}
}

func TestPreparationRemovalContinuesCheckingOwnershipPastCreationReserve(t *testing.T) {
	e, k, _ := preparationRemovalProgressFixture(t)
	k.elapsed = 50 * time.Millisecond
	k.after = func() {
		if len(k.removals) == 6 {
			k.foreign = true
		}
	}
	if _, err := e.RebuildCandidates(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal("cleanup stopped before rechecking the next owned resource or ignored foreign ownership", err)
	}
	p := e.journal.Preparations[e.preparationIndex("p0")]
	if p.Phase != "removing" || p.Step != 6 || p.Reason != "owned_cleanup_conflict_or_unavailable" || len(k.removals) != 6 || k.active["p0"] {
		t.Fatal("foreign resource was accepted or removal cursor advanced", p)
	}
}
