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
	r, _ := e.RebuildCandidates(context.Background())
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
			if old.Alias == current.Alias || current.Phase != "prepared" || len(k.removals) != len(preparationRemovalSteps) {
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
			grant.ExpiresAt = time.Now().Add(time.Second)
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
			grant.IssuedAt = time.Now()
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
