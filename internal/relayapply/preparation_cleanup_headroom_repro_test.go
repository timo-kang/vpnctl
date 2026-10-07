// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Advance only fake BOOTTIME after real ownership checks in the fake backend.
// The journal remains the normal durable temporary-file journal throughout.
type preparationCleanupHeadroomKernel struct {
	*preparationKernel
	t         *testing.T
	now       *time.Duration
	paths     []string
	deadlines []time.Time
	firstCost time.Duration
	laterCost time.Duration
	after     func()
}

func (k *preparationCleanupHeadroomKernel) RemoveStep(ctx context.Context, entry Entry, step string) error {
	k.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > NodeRebuildDuration {
		k.t.Fatal("cleanup escaped the existing shared wall deadline")
	}
	k.paths = append(k.paths, entry.Candidate.PathID)
	k.deadlines = append(k.deadlines, deadline)
	err := k.preparationKernel.RemoveStep(ctx, entry, step)
	cost := k.laterCost
	if len(k.paths) == 1 {
		cost = k.firstCost
	}
	*k.now += cost
	if k.after != nil {
		k.after()
	}
	return err
}

func preparationCleanupHeadroomFixture(t *testing.T, skippedPhase string, laterRemoval bool) (*Engine, *preparationCleanupHeadroomKernel, string) {
	t.Helper()
	e, original, dir, now := preparationFixture(t)
	ctx := context.Background()
	for _, path := range []string{"p0", "p2"} {
		if path == "p2" && !laterRemoval {
			continue
		}
		if _, err := e.PrepareApplication(ctx, path, ""); err != nil {
			t.Fatal(err)
		}
	}
	if skippedPhase == "ready" {
		if _, err := e.PrepareApplication(ctx, "p1", ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"p0", "p1", "p2"} {
		if path == "p2" && !laterRemoval {
			continue
		}
		if _, err := e.RequestPreparation(ctx, path, ""); err != nil {
			t.Fatal(err)
		}
	}
	if skippedPhase == "preparing" {
		e.journal.RebuildCursor = "p0"
		if err := e.persist(); err != nil {
			t.Fatal(err)
		}
		if _, err := e.rebuildCandidates(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"p0", "p2"} {
		if path == "p2" && !laterRemoval {
			continue
		}
		if err := e.startPreparationRemoval(e.preparationIndex(path), e.index(path), "candidate_inventory_changed"); err != nil {
			t.Fatal(err)
		}
	}
	// The next admission starts p0, then encounters the skipped p1 candidate.
	e.journal.RebuildCursor = "p1"
	if laterRemoval {
		e.journal.RebuildCursor = "p2"
	}
	if err := e.persist(); err != nil {
		t.Fatal(err)
	}
	if got := e.journal.Preparations[e.preparationIndex("p1")].Phase; got != skippedPhase {
		t.Fatal("wrong blocked-candidate fixture phase", got)
	}
	k := &preparationCleanupHeadroomKernel{
		preparationKernel: original, t: t, now: now,
		firstCost: 300 * time.Millisecond, laterCost: 50 * time.Millisecond,
	}
	e.backend = k
	return e, k, dir
}

func assertHeadroomCleanupClosed(t *testing.T, e *Engine, k *preparationCleanupHeadroomKernel, steps int) {
	t.Helper()
	if k.steps != steps || k.renewals != 0 {
		t.Fatal("cleanup spent creation reserve or renewed a lease", k.steps, k.renewals)
	}
	for path, active := range k.active {
		if active {
			t.Fatal("cleanup opened a lease", path)
		}
	}
	if len(k.paths) > nodeRebuildMaxUnits {
		t.Fatal("cleanup exceeded the existing eight-unit cap", len(k.paths))
	}
	for _, deadline := range k.deadlines {
		if !deadline.Equal(k.deadlines[0]) {
			t.Fatal("cleanup started a new wall budget")
		}
	}
	if err := validatePreparations(e.journal); err != nil {
		t.Fatal("invalid durable cleanup progress", err)
	}
}

func TestPreparationCleanupPassesCandidatesWithoutCreationHeadroom(t *testing.T) {
	for _, phase := range []string{"waiting", "preparing", "ready"} {
		t.Run(phase, func(t *testing.T) {
			e, k, dir := preparationCleanupHeadroomFixture(t, phase, true)
			before := e.journal.Preparations[e.preparationIndex("p1")]
			start, steps := *k.now, k.steps
			if _, err := e.RebuildCandidates(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertHeadroomCleanupClosed(t, e, k, steps)
			e = reopen(t, e, dir)
			if !reflect.DeepEqual(before, e.journal.Preparations[e.preparationIndex("p1")]) {
				t.Fatal("candidate without creation headroom was processed")
			}
			if len(k.paths) < 2 || k.paths[0] != "p0" || k.paths[1] != "p2" {
				t.Fatalf("candidate in phase %s blocked later owned cleanup with %s left: cleanup paths=%v", phase, NodeRebuildDuration-(*k.now-start), k.paths)
			}
			if *k.now-start >= NodeRebuildDuration || e.journal.Preparations[e.preparationIndex("p2")].Step == 0 {
				t.Fatal("cleanup did not durably advance inside the shared quantum")
			}
		})
	}
}

func TestPreparationCleanupRetainsFirstSkippedCreationAcrossRestart(t *testing.T) {
	for _, phase := range []string{"waiting", "preparing"} {
		t.Run(phase, func(t *testing.T) {
			e, k, dir := preparationCleanupHeadroomFixture(t, phase, true)
			if _, err := e.RebuildCandidates(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(k.paths) < 2 || k.paths[1] != "p2" {
				t.Fatal("later cleanup was not exercised before restart", k.paths)
			}
			e = reopen(t, e, dir)
			e.rebuildClock = func() (time.Duration, error) { return *k.now, nil }
			*k.now += time.Second
			removals := len(k.paths)
			out, err := e.rebuildCandidates(context.Background(), 1)
			if err != nil || out.PathID != "p1" || len(k.paths) != removals {
				t.Fatal("opportunistic cleanup stole the skipped creation's next admission", out.PathID, k.paths, err)
			}
			intent := e.journal.Preparations[e.preparationIndex("p1")]
			wantStep := 0
			if phase == "preparing" {
				wantStep = 1
			}
			if intent.Phase != "preparing" || intent.Step != wantStep || k.active["p1"] {
				t.Fatal("restored creation reserve did not advance the skipped candidate safely", intent)
			}
		})
	}
}

func TestPreparationCleanupSkipHonorsOwnershipAndSharedBudget(t *testing.T) {
	for _, failure := range []string{"ownership", "boottime", "wall-cancel"} {
		t.Run(failure, func(t *testing.T) {
			e, k, dir := preparationCleanupHeadroomFixture(t, "waiting", true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch failure {
			case "ownership":
				k.after = func() { k.foreign = true }
			case "boottime":
				k.laterCost = 500 * time.Millisecond
			case "wall-cancel":
				k.after = cancel
			}
			steps := k.steps
			_, err := e.RebuildCandidates(ctx)
			if failure == "ownership" && !errors.Is(err, ErrConflict) || failure == "boottime" && !errors.Is(err, context.DeadlineExceeded) || failure == "wall-cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("remaining-budget cleanup ignored a live safety boundary", err)
			}
			assertHeadroomCleanupClosed(t, e, k, steps)
			e = reopen(t, e, dir)
			intent := e.journal.Preparations[e.preparationIndex("p2")]
			if intent.Phase != "removing" || intent.Step != 0 {
				t.Fatal("failed later cleanup was committed", intent)
			}
		})
	}
}

func TestPreparationCleanupSkipsBackoffAndTerminatesWithoutRunnableRemoval(t *testing.T) {
	for _, backoff := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-removal", true: "backoff-removal"}[backoff], func(t *testing.T) {
			e, k, dir := preparationCleanupHeadroomFixture(t, "waiting", backoff)
			// Leave just p0's final idempotent verify. It consumes 300ms and
			// becomes waiting, leaving only blocked creation or backed-off cleanup.
			for i := 0; i < len(preparationRemovalSteps)-1; i++ {
				e.journal.RebuildCursor = "p1"
				if backoff {
					e.journal.RebuildCursor = "p2"
				}
				if _, err := e.rebuildCandidates(context.Background(), 1); err != nil {
					t.Fatal(err)
				}
			}
			if backoff {
				e.journal.Preparations[e.preparationIndex("p2")].RetryBootNS = uint64(*k.now + 30*time.Second)
			}
			e.journal.RebuildCursor = "p1"
			if backoff {
				e.journal.RebuildCursor = "p2"
			}
			if err := e.persist(); err != nil {
				t.Fatal(err)
			}
			k.paths, k.deadlines = nil, nil
			before := e.journal.Preparations[e.preparationIndex("p1")]
			steps := k.steps
			if _, err := e.RebuildCandidates(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertHeadroomCleanupClosed(t, e, k, steps)
			e = reopen(t, e, dir)
			if !reflect.DeepEqual(k.paths, []string{"p0"}) || e.journal.Preparations[e.preparationIndex("p0")].Phase != "waiting" || !reflect.DeepEqual(before, e.journal.Preparations[e.preparationIndex("p1")]) {
				t.Fatal("queue without eligible cleanup did not stop safely", k.paths)
			}
			if backoff && e.journal.Preparations[e.preparationIndex("p2")].Step != 0 {
				t.Fatal("backed-off removal bypassed its retry deadline")
			}
		})
	}
}

func TestPreparationCleanupOnlyQueueRetainsRoundRobin(t *testing.T) {
	e, k, dir := preparationCleanupHeadroomFixture(t, "ready", true)
	if err := e.startPreparationRemoval(e.preparationIndex("p1"), e.index("p1"), "candidate_inventory_changed"); err != nil {
		t.Fatal(err)
	}
	steps := k.steps
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertHeadroomCleanupClosed(t, e, k, steps)
	want := []string{"p0", "p1", "p2", "p0", "p1", "p2", "p0", "p1"}
	if !reflect.DeepEqual(k.paths, want) {
		t.Fatal("cleanup-only queue lost its existing round-robin or eight-unit bound", k.paths)
	}
	e = reopen(t, e, dir)
	if e.journal.RebuildCursor != "p1" {
		t.Fatal("cleanup-only cursor did not survive restart", e.journal.RebuildCursor)
	}
}
