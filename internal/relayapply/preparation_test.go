// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayplan"
)

type preparationKernel struct {
	*fakeNodeLease
	removals []string
}

func (k *preparationKernel) Step(ctx context.Context, e Entry, step, key string) error {
	if k.foreign {
		return ErrConflict
	}
	return k.fakeKernel.Step(ctx, e, step, key)
}

func (k *preparationKernel) RemoveStep(ctx context.Context, e Entry, step string) error {
	if k.foreign || k.removeFail {
		return ErrConflict
	}
	k.removals = append(k.removals, step)
	if step == "link" {
		return k.Remove(ctx, e)
	}
	if step == "verify" && len(k.objects[e.Candidate.PathID]) != 0 {
		return ErrConflict
	}
	return ctx.Err()
}

type preparationInventory struct {
	source, gateway, state string
	ifindex                int
	only                   string
}

func (c *preparationInventory) Collect(ctx context.Context, u relayplan.Underlay, eps []string) relayplan.Inventory {
	v := (&inventory{}).Collect(ctx, u, eps)
	if c.only != "" && c.only != u.ID {
		return v
	}
	if c.source != "" {
		v.Addresses = []string{c.source}
		for i := range v.Routes {
			v.Routes[i].Source = c.source
		}
	}
	if c.gateway != "" {
		for i := range v.Routes {
			v.Routes[i].Gateway = c.gateway
		}
	}
	if c.ifindex != 0 {
		v.IfIndex = c.ifindex
	}
	if c.state != "" {
		v.State, v.Reason = c.state, map[string]string{"down": "link_down", "unknown": "collector_unavailable"}[c.state]
	}
	return v
}
func preparationFixture(t *testing.T) (*Engine, *preparationKernel, string, *time.Duration) {
	t.Helper()
	e, k, dir := nodeLeaseFixture(t)
	b := &preparationKernel{fakeNodeLease: k}
	e.backend = b
	now := time.Hour
	e.rebuildClock = func() (time.Duration, error) { return now, nil }
	return e, b, dir, &now
}
func tickPreparation(t *testing.T, e *Engine, now *time.Duration) Result {
	t.Helper()
	*now += 31 * time.Second
	e.MaintainLeases(context.Background())
	r, _ := e.rebuildCandidates(context.Background(), 1)
	if err := validatePreparations(e.journal); err != nil {
		t.Fatal("invalid durable phase", err, e.journal.Preparations)
	}
	return r
}
func readyPreparation(t *testing.T, e *Engine, now *time.Duration, path string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		tickPreparation(t, e, now)
		if p := e.preparationIndex(path); p >= 0 && e.journal.Preparations[p].Phase == "ready" {
			return
		}
	}
	t.Fatal("preparation did not converge", e.preparationStatus())
}

func TestPreparationExplicitIntentAndRelease(t *testing.T) {
	e, k, dir, now := preparationFixture(t)
	if _, err := e.PrepareApplication(context.Background(), "p1", ""); err != nil {
		t.Fatal(err)
	}
	if r, err := e.RebuildCandidates(context.Background()); err != nil || r.State != "idle" {
		t.Fatal(r, err)
	}
	if len(e.journal.Preparations) != 0 {
		t.Fatal("manual path implicitly adopted")
	}
	if r, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil || r.State != "scheduled" || k.steps != 10 {
		t.Fatal(r, err, k.steps)
	}
	if _, err := e.PrepareApplication(context.Background(), "p0", ""); !errors.Is(err, ErrConflict) {
		t.Fatal("manual prepare bypassed cursor", err)
	}
	readyPreparation(t, e, now, "p0")
	if k.active["p0"] {
		t.Fatal("preparation itself granted lease")
	}
	e = reopen(t, e, dir)
	if _, err := e.MaintainLeases(context.Background()); err == nil || k.active["p0"] {
		t.Fatal("disk approval rearmed rebuilt candidate", err)
	}
	if _, err := e.Release(context.Background(), "p0"); err != nil {
		t.Fatal(err)
	}
	e = reopen(t, e, dir)
	for i := 0; i < 5; i++ {
		if _, err := e.RebuildCandidates(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if e.index("p0") >= 0 || len(k.objects["p0"]) > 0 || len(e.journal.Preparations) > 0 || len(k.objects["p1"]) != 10 {
		t.Fatal("explicit release resurrected or affected manual path")
	}
}

func TestPreparationInventoryChangeAndForeignPreservation(t *testing.T) {
	for _, kind := range []string{"source", "gateway", "ifindex", "missing-route", "foreign", "explicit-source", "down", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			e, k, _, now := preparationFixture(t)
			if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
				t.Fatal(err)
			}
			readyPreparation(t, e, now, "p0")
			old := e.journal.Entries[e.index("p0")]
			c := &preparationInventory{}
			e.collector = c
			switch kind {
			case "source":
				c.source = "192.0.2.11"
			case "gateway":
				c.gateway = "192.0.2.1"
			case "ifindex":
				c.ifindex = 8
			case "missing-route":
				k.objects["p0"] = k.objects["p0"][:9]
			case "foreign":
				k.foreign = true
			case "explicit-source":
				e.underlays[0].SourceIPv4 = "192.0.2.10"
				c.source = "192.0.2.11"
			case "down":
				c.state = "down"
			case "unknown":
				c.state = "unknown"
			}
			for i := 0; i < 45; i++ {
				tickPreparation(t, e, now)
			}
			current := e.journal.Entries[e.index("p0")]
			if kind == "foreign" || kind == "explicit-source" || kind == "down" || kind == "unknown" {
				if old.Alias != current.Alias || len(k.removals) > 0 || k.active["p0"] {
					t.Fatal("unavailable/foreign path repaired or granted", e.preparationStatus())
				}
				want := map[string]string{"foreign": "ownership_or_kernel_unavailable", "explicit-source": "route_unknown_or_invalid", "down": "link_down", "unknown": "collector_unavailable"}[kind]
				if e.journal.Preparations[0].Reason != want {
					t.Fatal("lost diagnostic distinction", kind, e.preparationStatus())
				}
				return
			}
			if old.Alias == current.Alias || old.LinkIndex == current.LinkIndex || old.Metric != current.Metric || current.Phase != "prepared" || len(k.removals) != len(preparationRemovalSteps) {
				t.Fatal("owned path did not rebuild", e.preparationStatus(), k.removals)
			}
			if p := e.journal.Preparations[0]; p.Previous == nil || p.Previous.Owner != old.Alias {
				t.Fatal("missing prior identity", p)
			}
		})
	}
}

func TestPreparationRevocationDuringEveryStage(t *testing.T) {
	for steps := 0; steps <= len(preparationSteps); steps++ {
		t.Run(fmt.Sprint(steps), func(t *testing.T) {
			e, k, dir, now := preparationFixture(t)
			if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < steps+1; i++ {
				tickPreparation(t, e, now)
			}
			if _, err := e.cache.Refresh(context.Background(), deniedIssuer{}); err == nil {
				t.Fatal("denial missing")
			}
			before := k.steps
			for i := 0; i < 3; i++ {
				tickPreparation(t, e, now)
			}
			e = reopen(t, e, dir)
			e.rebuildClock = func() (time.Duration, error) { return *now, nil }
			for i := 0; i < 3; i++ {
				tickPreparation(t, e, now)
			}
			if k.steps != before || k.active["p0"] {
				t.Fatal("denial allowed creation/activation", e.preparationStatus())
			}
		})
	}
}

func TestPreparationCleanupJournalFailures(t *testing.T) {
	for point := 1; point <= 16; point++ {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("write%d/committed%v", point, committed), func(t *testing.T) {
				e, k, dir, now := preparationFixture(t)
				if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
					t.Fatal(err)
				}
				readyPreparation(t, e, now, "p0")
				k.objects["p0"] = k.objects["p0"][:9]
				tickPreparation(t, e, now)
				if e.journal.Preparations[0].Phase != "removing" {
					t.Fatal("cleanup not entered")
				}
				save := e.save
				writes := 0
				e.save = func(b []byte) error {
					writes++
					if writes == point {
						if committed {
							if err := save(b); err != nil {
								return err
							}
						}
						return syscall.ENOSPC
					}
					return save(b)
				}
				for i := 0; i < 9 && !e.uncertain; i++ {
					tickPreparation(t, e, now)
				}
				if !e.uncertain {
					t.Fatal("cleanup boundary not reached", point, writes)
				}
				e = reopen(t, e, dir)
				e.rebuildClock = func() (time.Duration, error) { return *now, nil }
				readyPreparation(t, e, now, "p0")
				if len(k.objects["p0"]) != 10 || k.active["p0"] {
					t.Fatal("cleanup replay granted or duplicated candidate")
				}
			})
		}
	}
}

func TestPreparationInterruptedAddsCleanBeforeRetry(t *testing.T) {
	for _, step := range preparationSteps {
		for _, mode := range []string{"before", "after", "crash"} {
			t.Run(step+"/"+mode, func(t *testing.T) {
				e, k, dir, now := preparationFixture(t)
				if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
					t.Fatal(err)
				}
				k.fail, k.after, k.crash = step, mode != "before", mode == "crash"
				for i := 0; i < 13; i++ {
					crashed := false
					func() {
						defer func() {
							if recover() != nil {
								crashed = true
							}
						}()
						tickPreparation(t, e, now)
					}()
					if crashed || e.journal.Preparations[0].Phase == "removing" {
						break
					}
				}
				if k.active["p0"] {
					t.Fatal("partial prepare granted")
				}
				e = reopen(t, e, dir)
				e.rebuildClock = func() (time.Duration, error) { return *now, nil }
				k.fail, k.crash = "", false
				readyPreparation(t, e, now, "p0")
				if len(k.objects["p0"]) != 10 || len(k.removals) != len(preparationRemovalSteps) {
					t.Fatal("partial add replayed", k.objects, k.removals)
				}
				if k.active["p0"] {
					t.Fatal("recovered disk approval rearmed")
				}
			})
		}
	}
}

func TestPreparationReleaseStorageFailureCannotResurrect(t *testing.T) {
	for _, phase := range []int{0, 1, 2, 6, 10, 12} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("phase%d/durable%v", phase, after), func(t *testing.T) {
				e, k, dir, now := preparationFixture(t)
				if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < phase; i++ {
					tickPreparation(t, e, now)
				}
				save := e.save
				e.save = func(b []byte) error {
					if after {
						if err := save(b); err != nil {
							return err
						}
					}
					return syscall.ENOSPC
				}
				if _, err := e.Release(context.Background(), "p0"); err == nil {
					t.Fatal("storage failure hidden")
				}
				e = reopen(t, e, dir)
				e.rebuildClock = func() (time.Duration, error) { return *now, nil }
				steps := k.steps
				for i := 0; i < 20; i++ {
					tickPreparation(t, e, now)
				}
				// A committed release leaves any remaining cleanup to recover;
				// an older intent with no consent is automatically cleaned closed.
				if k.steps != steps || k.active["p0"] {
					t.Fatal("revoked consent resurrected", e.preparationStatus())
				}
				if _, err := e.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
				if e.index("p0") >= 0 || len(k.objects["p0"]) > 0 {
					t.Fatal("disabled cleanup incomplete")
				}
			})
		}
	}
}

func TestPreparationJournalFailureEveryBoundary(t *testing.T) {
	// Initial cursor, before/after each add, and final readback commits. Both
	// pre-rename and committed-but-uncertain outcomes must reopen consistently.
	for point := 1; point <= 34; point++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("write%d/committed%v", point, after), func(t *testing.T) {
				e, k, dir, now := preparationFixture(t)
				if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
					t.Fatal(err)
				}
				save := e.save
				writes := 0
				e.save = func(b []byte) error {
					writes++
					if writes == point {
						if after {
							if err := save(b); err != nil {
								return err
							}
						}
						return syscall.ENOSPC
					}
					return save(b)
				}
				for i := 0; i < 15 && !e.uncertain; i++ {
					tickPreparation(t, e, now)
				}
				if !e.uncertain {
					t.Fatalf("write boundary %d not reached (%d)", point, writes)
				}
				steps := k.steps
				if _, err := e.RebuildCandidates(context.Background()); !errors.Is(err, relaycache.ErrUncertain) || k.steps != steps {
					t.Fatal("uncertain state mutated", err)
				}
				e = reopen(t, e, dir)
				e.rebuildClock = func() (time.Duration, error) { return *now, nil }
				readyPreparation(t, e, now, "p0")
				if len(k.objects["p0"]) != 10 || k.active["p0"] {
					t.Fatal("incomplete or unapproved rebuild", k.objects)
				}
			})
		}
	}
}

func TestPreparationRoundRobinBackoffAndBootBudget(t *testing.T) {
	e, k, _, now := preparationFixture(t)
	for i := 0; i < 8; i++ {
		if _, err := e.RequestPreparation(context.Background(), fmt.Sprint("p", i), ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		tickPreparation(t, e, now)
	}
	for _, p := range e.journal.Preparations {
		if p.Phase != "preparing" {
			t.Fatal("intent starved", p)
		}
	}
	before := k.steps
	clockCalls := 0
	e.rebuildClock = func() (time.Duration, error) {
		clockCalls++
		if clockCalls > 1 {
			return *now + time.Second, nil
		}
		return *now, nil
	}
	if _, err := e.RebuildCandidates(context.Background()); err == nil {
		t.Fatal("BOOTTIME overrun accepted")
	}
	if k.steps != before {
		t.Fatal("mutation after BOOTTIME budget")
	}
	e.rebuildClock = func() (time.Duration, error) { return *now, nil }
	// Persistent cursor and backoff prevent one failing path monopolizing work.
	k.foreign = true
	for i := 0; i < 8; i++ {
		e.RebuildCandidates(context.Background())
	}
	for _, p := range e.journal.Preparations {
		if p.RetryBootNS == 0 {
			t.Fatal("missing bounded retry", p)
		}
	}
	copy := append([]PreparationIntent(nil), e.journal.Preparations...)
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(copy, e.journal.Preparations) {
		t.Fatal("backoff ignored")
	}
}

func TestPreparationExpiryAndOfflineCannotRearm(t *testing.T) {
	for _, steps := range []int{0, 5, 10} {
		t.Run(fmt.Sprint(steps), func(t *testing.T) {
			e, k, dir, now := preparationFixture(t)
			if _, err := e.RequestPreparation(context.Background(), "p0", ""); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < steps+1; i++ {
				tickPreparation(t, e, now)
			}
			r, err := e.cache.Status()
			if err != nil {
				t.Fatal(err)
			}
			grant := *r.Catalog
			grant.Generation++
			// Match the controller's UTC / JSON wire timestamps. In-process
			// monotonic components are not part of an authenticated response.
			grant.ExpiresAt = time.Now().UTC().Add(time.Second)
			grant.IssuedAt = grant.ExpiresAt.Add(-time.Minute)
			if _, err := e.cache.Refresh(context.Background(), observationIssuer{grant}); err != nil {
				t.Fatal(err)
			}
			// Real expiry, without changing a host clock or relying on fake lease
			// timers. Partial creation must stop even when its journal is reopened.
			time.Sleep(time.Until(grant.ExpiresAt.Add(20 * time.Millisecond)))
			before := k.steps
			for i := 0; i < 3; i++ {
				tickPreparation(t, e, now)
			}
			e = reopen(t, e, dir)
			e.rebuildClock = func() (time.Duration, error) { return *now, nil }
			for i := 0; i < 3; i++ {
				tickPreparation(t, e, now)
			}
			if k.steps != before || k.active["p0"] {
				t.Fatal("expired approval advanced creation or lease")
			}
			grant.Generation++
			grant.IssuedAt = time.Now().UTC()
			grant.ExpiresAt = grant.IssuedAt.Add(time.Hour)
			if _, err := e.cache.Refresh(context.Background(), observationIssuer{grant}); err != nil {
				t.Fatal(err)
			}
			readyPreparation(t, e, now, "p0")
			if k.active["p0"] {
				t.Fatal("rebuild itself rearmed")
			}
			// Reopen drops the in-process authenticated response, as with a
			// controller outage after preparation. Disk authority cannot rearm.
			e = reopen(t, e, dir)
			if _, err := e.MaintainLeases(context.Background()); err == nil || k.active["p0"] {
				t.Fatal("offline cached rearm", err)
			}
			if _, err := e.cache.Refresh(context.Background(), observationIssuer{grant}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.MaintainLeases(context.Background()); err != nil || !k.active["p0"] {
				t.Fatal("fresh authenticated rearm failed", err)
			}
		})
	}
}

func TestPreparationFastUnitsShareOneBudgetAndKeepFairness(t *testing.T) {
	for _, elapsed := range []time.Duration{0, 300 * time.Millisecond, time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			e, k, _, now := preparationFixture(t)
			for _, path := range []string{"p0", "p1"} {
				if _, err := e.RequestPreparation(context.Background(), path, ""); err != nil {
					t.Fatal(err)
				}
			}
			// First admission journals both candidates without kernel mutation.
			if _, err := e.rebuildCandidates(context.Background(), 2); err != nil {
				t.Fatal(err)
			}
			for _, p := range e.journal.Preparations {
				if p.Phase != "preparing" {
					t.Fatal("second path starved", p)
				}
			}
			// Isolate scheduling from fsync latency. Durable writes and crashes
			// are covered by the fault matrix; a slow disk legitimately yields
			// before the maximum count and must not fail this fast-work case.
			e.save = func([]byte) error { return nil }
			start := *now
			e.rebuildClock = func() (time.Duration, error) {
				if k.steps > 0 {
					return start + elapsed, nil
				}
				return start, nil
			}
			wallStart := time.Now()
			_, err := e.RebuildCandidates(context.Background())
			wallElapsed := time.Since(wallStart)
			want := nodeRebuildMaxUnits
			if elapsed > 250*time.Millisecond {
				want = 1
			}
			if k.steps < 1 || k.steps > want || wallElapsed < NodeRebuildDuration-500*time.Millisecond && k.steps != want {
				t.Fatal("wrong bounded units", k.steps, want)
			}
			if elapsed == 0 {
				for i, p := range e.journal.Preparations {
					if p.Step != (k.steps+1-i)/2 {
						t.Fatal("fast work starved a candidate", p)
					}
				}
			}
			if (err != nil) != (elapsed >= NodeRebuildDuration) {
				t.Fatal("shared BOOTTIME budget", elapsed, err)
			}
			if k.active["p0"] || k.active["p1"] {
				t.Fatal("work quantum granted lease")
			}
			if err := validatePreparations(e.journal); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreparationFastUnitsDoNotResetCumulativeBudget(t *testing.T) {
	e, k, _, now := preparationFixture(t)
	for _, path := range []string{"p0", "p1"} {
		if _, err := e.RequestPreparation(context.Background(), path, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.rebuildCandidates(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	e.save = func([]byte) error { return nil }
	start := *now
	e.rebuildClock = func() (time.Duration, error) {
		return start + time.Duration(k.steps)*100*time.Millisecond, nil
	}
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Three quick operations consume 300ms. The fourth must not begin with
	// only 450ms left, even though the maximum work count has not been reached.
	if k.steps != 3 || k.active["p0"] || k.active["p1"] {
		t.Fatal("cumulative reserve lost or rebuild opened lease", k.steps, k.active)
	}
	if e.journal.Preparations[0].Step != 2 || e.journal.Preparations[1].Step != 1 {
		t.Fatal("cumulative budget lost round-robin progress", e.preparationStatus())
	}
}

func TestPreparationSlowJournalYieldsBeforeNextUnit(t *testing.T) {
	e, k, _, _ := preparationFixture(t)
	for _, path := range []string{"p0", "p1"} {
		if _, err := e.RequestPreparation(context.Background(), path, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.rebuildCandidates(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	delayed := false
	e.save = func([]byte) error {
		if !delayed {
			delayed = true
			time.Sleep(300 * time.Millisecond)
		}
		return nil
	}
	if _, err := e.RebuildCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	// BOOTTIME is deliberately frozen in this fixture. Wall time consumed by
	// a slow journal still prevents a second unit from taking a fresh budget.
	if k.steps != 1 || k.active["p0"] || k.active["p1"] {
		t.Fatal("slow persistence did not yield or opened lease", k.steps, k.active)
	}
}

func TestPreparationSecondUnitRequiresWallDeadlineHeadroom(t *testing.T) {
	e, k, _, _ := preparationFixture(t)
	for _, path := range []string{"p0", "p1"} {
		if _, err := e.RequestPreparation(context.Background(), path, ""); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := e.RebuildCandidates(ctx); err != nil {
		t.Fatal(err)
	}
	// The test BOOTTIME clock did not advance, but the parent's remaining wall
	// deadline is below the second-unit reserve. Only the first intent advances.
	if e.journal.Preparations[0].Phase != "preparing" || e.journal.Preparations[1].Phase != "waiting" || k.steps != 0 {
		t.Fatal("parent deadline was reset or second unit started", e.preparationStatus(), k.steps)
	}
}

// A separate observer can drain queued notifications before acquiring the next
// journal. Its terminal tuple must remain valid even if it misses the entire
// remove/wait/recreate interval. No generation freshness requirement is relaxed.
type preparationScopeCapture struct{ scopes []relayobserve.TerminalScope }

func (s *preparationScopeCapture) Generation(context.Context, string) (string, error) { return "", nil }
func (s *preparationScopeCapture) SetTerminalScopes(_ context.Context, scopes []relayobserve.TerminalScope) error {
	s.scopes = append([]relayobserve.TerminalScope(nil), scopes...)
	return nil
}
func TestPreparationTerminalIdentitySurvivesMissingEntryAndRestart(t *testing.T) {
	e, k, dir, now := preparationFixture(t)
	ctx := context.Background()
	if _, err := e.PrepareApplication(ctx, "p0", ""); err != nil {
		t.Fatal(err)
	}
	old := e.journal.Entries[e.index("p0")]
	if _, err := e.RequestPreparation(ctx, "p0", ""); err != nil {
		t.Fatal(err)
	}
	capture := &preparationScopeCapture{}
	observed := relayobserve.WithUnderlayEvents(ctx, capture)
	assertScope := func() {
		t.Helper()
		if err := e.syncTerminalScopes(observed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(capture.scopes, []relayobserve.TerminalScope{terminalScope(old)}) {
			t.Fatal("observer lost or changed exact event identity", capture.scopes, terminalScope(old))
		}
	}
	assertScope()
	k.objects["p0"] = k.objects["p0"][:9]
	for i := 0; i < 20 && e.index("p0") >= 0; i++ {
		tickPreparation(t, e, now)
		assertScope()
	}
	if e.index("p0") >= 0 || e.journal.Preparations[0].Phase != "waiting" {
		t.Fatal("missing-entry interval not reached")
	}
	e = reopen(t, e, dir)
	e.rebuildClock = func() (time.Duration, error) { return *now, nil }
	assertScope()
	readyPreparation(t, e, now, "p0")
	current := e.journal.Entries[e.index("p0")]
	if current.Metric != old.Metric || current.Alias == old.Alias || current.LinkIndex == old.LinkIndex {
		t.Fatal("event identity changed or installation identity reused")
	}
	assertScope()
	// Reject malformed scope/entry binding instead of weakening foreign checks.
	e.journal.Preparations[0].TerminalScope.Metric++
	if validatePreparations(e.journal) == nil {
		t.Fatal("mismatched scope accepted")
	}
	e.journal.Preparations[0].TerminalScope.Metric--
	if _, err := e.Release(ctx, "p0"); err != nil {
		t.Fatal(err)
	}
	if err := e.syncTerminalScopes(observed); err != nil || len(capture.scopes) != 0 {
		t.Fatal("released scope survived", err, capture.scopes)
	}
}

func TestPreparationAmbiguousWaitingScopeDoesNotDeadlockReplan(t *testing.T) {
	e, _, _, now := preparationFixture(t)
	ctx := context.Background()
	if _, err := e.RequestPreparation(ctx, "p0", ""); err != nil {
		t.Fatal(err)
	}
	readyPreparation(t, e, now, "p0")
	if _, err := e.PrepareApplication(ctx, "p1", ""); err != nil {
		t.Fatal(err)
	}
	// During catalog slot migration, p0 has been removed while its old table
	// has become p1's current table. Its retained tuple cannot classify events
	// affecting the new binding, nor may it stop cleanup/replanning forever.
	i := e.index("p0")
	e.journal.Entries = append(e.journal.Entries[:i], e.journal.Entries[i+1:]...)
	p := &e.journal.Preparations[0]
	p.Phase = "waiting"
	live := terminalScope(e.journal.Entries[e.index("p1")])
	p.TerminalScope.Table = live.Table
	p.TerminalScope.Metric = live.Metric ^ 1
	if err := validatePreparations(e.journal); err != nil {
		t.Fatal(err)
	}
	capture := &preparationScopeCapture{}
	observed := relayobserve.WithUnderlayEvents(ctx, capture)
	if err := e.syncTerminalScopes(observed); err != nil {
		t.Fatal("replanning blocked by stale event scope", err)
	}
	if len(capture.scopes) != 0 {
		t.Fatal("ambiguous table scoped as one underlay", capture.scopes)
	}
	// Once the waiting intention is explicitly released, current ownership is
	// unambiguous again. No new approval or route is granted by this operation.
	e.journal.Preparations = nil
	if err := e.syncTerminalScopes(observed); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(capture.scopes, []relayobserve.TerminalScope{live}) {
		t.Fatal("current scope not restored", capture.scopes)
	}
}

// A partial collector view must not renumber catalog slots or hide a change
// to the requested candidate. Repeated full-fleet collection previously spent
// the rebuild quantum querying unrelated networks at every installation step.
type preparationCollectFunc func(context.Context, relayplan.Underlay, []string) relayplan.Inventory

func (f preparationCollectFunc) Collect(ctx context.Context, u relayplan.Underlay, endpoints []string) relayplan.Inventory {
	return f(ctx, u, endpoints)
}

func TestPreparationInventoryIsLocalAndRetainsCatalogSlots(t *testing.T) {
	e, _, _, _ := preparationFixture(t)
	r, err := e.cache.Status()
	if err != nil {
		t.Fatal(err)
	}
	full, err := relayplan.Build(context.Background(), r.NodeID, r.ControllerID, r, e.underlays, e.collector)
	if err != nil || len(full.Paths) != 8 {
		t.Fatal(full, err)
	}
	for _, want := range full.Paths {
		calls := 0
		e.collector = preparationCollectFunc(func(ctx context.Context, u relayplan.Underlay, eps []string) relayplan.Inventory {
			calls++
			if u.ID != want.UnderlayID {
				t.Fatal("unrelated underlay collected", u.ID, want.PathID)
			}
			return (&inventory{}).Collect(ctx, u, eps)
		})
		got, until, reason, err := e.preparationApproval(context.Background(), PreparationIntent{PathID: want.PathID, Controller: r.ControllerID})
		if err != nil || reason != "" || !time.Now().Before(until) || !reflect.DeepEqual(got.Candidate, want) || calls != 1 {
			t.Fatal("candidate identity, freshness or collection scope changed", want.PathID, got, until, reason, err, calls)
		}
	}
	// Collect again on every unit; a changed current source must not reuse
	// the previous unit's eligible pin or another candidate's inventory.
	e.collector = &preparationInventory{source: "192.0.2.11"}
	got, _, _, err := e.preparationApproval(context.Background(), PreparationIntent{PathID: "p7", Controller: r.ControllerID})
	if err != nil || got.Candidate.Pin.Source != "192.0.2.11" || got.Candidate.Pin.Table != full.Paths[7].Pin.Table {
		t.Fatal("stale inventory or catalog slot", got, err)
	}
	e.collector = &preparationInventory{state: "down"}
	if _, _, reason, err := e.preparationApproval(context.Background(), PreparationIntent{PathID: "p7", Controller: r.ControllerID}); err == nil || reason != "link_down" {
		t.Fatal("current underlay failure ignored", reason, err)
	}
}

func TestPreparationScopedInventoryPreservesFailClosedValidation(t *testing.T) {
	for _, kind := range []string{"denied", "missing-path", "unmapped", "invalid-unrelated-config", "foreign-controller"} {
		t.Run(kind, func(t *testing.T) {
			e, _, _, _ := preparationFixture(t)
			r, err := e.cache.Status()
			if err != nil {
				t.Fatal(err)
			}
			p := PreparationIntent{PathID: "p0", Controller: r.ControllerID}
			switch kind {
			case "denied":
				if _, err := e.cache.Refresh(context.Background(), deniedIssuer{}); err == nil {
					t.Fatal("denial missing")
				}
			case "missing-path":
				p.PathID = "missing"
			case "unmapped":
				e.underlays = e.underlays[1:]
			case "invalid-unrelated-config":
				e.underlays[3].Interface = e.underlays[2].Interface
			case "foreign-controller":
				p.Controller = "foreign"
			}
			e.collector = preparationCollectFunc(func(context.Context, relayplan.Underlay, []string) relayplan.Inventory {
				t.Fatal("invalid input triggered inventory collection", kind)
				return relayplan.Inventory{}
			})
			got, _, _, err := e.preparationApproval(context.Background(), p)
			if err == nil || got.Candidate.Pin != nil {
				t.Fatal("invalid authority/configuration produced a candidate", got, err)
			}
		})
	}
}
