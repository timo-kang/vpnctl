// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

type testObservationOwner struct {
	t                    *testing.T
	dir                  string
	source               *Engine
	machine              *targetMachine
	kernel               *fakeNodeLease
	released, reacquired int
	edit                 func(*Engine)
	reacquireErr         error
	returnEngineOnError  bool
	reacquireDelay       time.Duration
	releaseErr           error
	beforeRelease        func()
	keepStore            bool
	cloneDir             string
}

func (o *testObservationOwner) Release(_ context.Context, e *Engine) error {
	o.released++
	if o.releaseErr != nil {
		return o.releaseErr
	}
	if o.beforeRelease != nil {
		o.beforeRelease()
	}
	e.Close()
	if o.keepStore {
		return nil
	}
	if o.cloneDir != "" {
		if err := clonePrivateCache(o.dir, o.cloneDir); err != nil {
			return err
		}
	}
	return e.cache.Close()
}
func (o *testObservationOwner) Reacquire(ctx context.Context) (*Engine, error) {
	o.reacquired++
	if o.reacquireDelay > 0 {
		timer := time.NewTimer(o.reacquireDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if o.reacquireErr != nil {
		if o.returnEngineOnError {
			c, err := relaycache.OpenQueued(ctx, o.dir, relaycache.Options{NodeID: o.source.journal.Node})
			if err != nil {
				return nil, o.reacquireErr
			}
			fresh, err := open(c, o.source.underlays, o.source.journal.Domain, o.kernel)
			if err != nil {
				c.Close()
				return nil, o.reacquireErr
			}
			return fresh, o.reacquireErr
		}
		return nil, o.reacquireErr
	}
	var c *relaycache.Store
	var err error
	if o.keepStore {
		c = o.source.cache
	} else {
		cacheDir := o.dir
		if o.cloneDir != "" {
			cacheDir = o.cloneDir
		}
		c, err = relaycache.OpenQueued(ctx, cacheDir, relaycache.Options{NodeID: o.source.journal.Node})
		if err != nil {
			return nil, err
		}
	}
	e, err := open(c, o.source.underlays, o.source.journal.Domain, o.kernel)
	if err != nil {
		c.Close()
		return nil, err
	}
	e.backend = o.source.backend
	e.collector = o.source.collector
	e.targets = targetKernel{kernel{run: o.machine.run}}
	e.probe = o.source.probe
	e.appProbe = o.source.appProbe
	if o.edit != nil {
		o.edit(e)
	}
	return e, nil
}

type delayedNodeObservationBackend struct {
	*fakeNodeLease
	delay time.Duration
}

func (b *delayedNodeObservationBackend) Check(ctx context.Context, entry Entry, fresh bool) (bool, error) {
	if b.delay > 0 {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return b.fakeNodeLease.Check(ctx, entry, fresh)
}

func clonePrivateCache(from, to string) error {
	if err := os.Mkdir(to, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), data, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func TestReconcileTargetYieldsOwnershipAndAppliesOnFreshEngine(t *testing.T) {
	e, m, k, dir := appFixture(t)
	t.Cleanup(func() {
		if e != nil {
			e.Close()
			e.cache.Close()
		}
	})
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k}
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	selector := appSelector(t)
	var last TargetReconcileResult
	for n := 0; n < 2; n++ {
		var fresh *Engine
		var err error
		last, fresh, err = e.ReconcileTargetWithHandoff(ctx, "app", "", selector, time.Second, owner)
		if fresh == nil || fresh == e {
			t.Fatalf("fresh owner missing: %v", err)
		}
		if n == 0 && (last.Applied || last.Application.Activated) {
			t.Fatal("single observation applied")
		}
		if n == 1 && (err != nil || !last.Applied || !last.Application.Activated) {
			t.Fatalf("fresh owner did not apply decision: %+v %v", last, err)
		}
		if last.Diagnostics == nil || last.Diagnostics.Phases["precheck"].Calls == 0 || last.Diagnostics.Phases["postcheck"].Calls == 0 {
			t.Fatalf("handoff lost probe boundary diagnostics: %+v", last.Diagnostics)
		}
		e = fresh
	}
	if owner.released != 2 || owner.reacquired != 2 {
		t.Fatalf("ownership handoff count %d/%d", owner.released, owner.reacquired)
	}
}

func TestReconcileTargetHandoffSeparatesPreparationProbeAndReentryBudgets(t *testing.T) {
	e, m, k, dir := appFixture(t)
	delayed := &delayedNodeObservationBackend{fakeNodeLease: k, delay: 1100 * time.Millisecond}
	e.backend = delayed
	t.Cleanup(func() {
		e.Close()
		e.cache.Close()
	})
	owner := &testObservationOwner{
		dir: dir, source: e, machine: m, kernel: k,
		reacquireDelay: 3100 * time.Millisecond,
		beforeRelease:  func() { delayed.delay = 0 },
	}
	ctx, cancel := context.WithTimeout(relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{}), 18*time.Second)
	defer cancel()
	out, fresh, err := e.ReconcileTargetWithHandoff(ctx, "app", "", appSelector(t), time.Second, owner)
	if fresh != nil {
		t.Cleanup(func() {
			fresh.Close()
			fresh.cache.Close()
		})
	}
	if fresh == nil || fresh == e || len(out.Selection.Candidates) != 8 {
		t.Fatalf("serial precheck or >3s FIFO reentry consumed the probe deadline: candidates=%d fresh=%t err=%v", len(out.Selection.Candidates), fresh != nil && fresh != e, err)
	}
	prepared := map[string]bool{"p0": true, "p1": true, "p2": true}
	seen := 0
	for _, candidate := range out.Selection.Candidates {
		if !prepared[candidate.PathID] {
			continue
		}
		seen++
		if candidate.State != "reachable" || candidate.Reason != "tcp_connect_verified" {
			t.Fatalf("candidate lost eligibility to precheck/reentry delay: %+v", candidate)
		}
	}
	if err == nil || seen != len(prepared) {
		t.Fatalf("expected only fixture candidates to be complete, err=%v prepared=%d", err, seen)
	}
}

func TestReconcileTargetHandoffRejectsChangedReservationBeforeRoutes(t *testing.T) {
	e, m, k, dir := appFixture(t)
	var fresh *Engine
	t.Cleanup(func() {
		if fresh != nil {
			fresh.Close()
			fresh.cache.Close()
		} else if e != nil {
			e.Close()
			e.cache.Close()
		}
	})
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k, edit: func(fresh *Engine) { fresh.journal.Targets[0].RouteRevision++ }}
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	selector := appSelector(t)
	before := m.mutations
	var out TargetReconcileResult
	var err error
	out, fresh, err = e.ReconcileTargetWithHandoff(ctx, "app", "", selector, time.Second, owner)
	if fresh == nil || err == nil || out.Applied || out.Application.Activated || out.Selection.Reason != "target_changed_during_observation" {
		t.Fatalf("changed reservation consumed stale proof: %+v %v", out, err)
	}
	if m.mutations != before || k.blocks > 0 {
		t.Fatal("stale decision changed routes or blocked a replacement")
	}
}

func TestReconcileTargetHandoffWorkerAllowsCompetingLeaseMaintenance(t *testing.T) {
	e, m, k, dir := appFixture(t)
	maintenance := make(chan struct{})
	owner := &testObservationOwner{t: t, dir: dir, source: e, machine: m, kernel: k}
	// Start a real private-cache FIFO waiter before ownership is returned. Its
	// first job must complete while the TCP worker is deliberately held open.
	type queuedResult struct{ err error }
	acquired := make(chan queuedResult, 1)
	ctx, cancel := context.WithTimeout(relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{}), 5*time.Second)
	defer cancel()
	cacheDone := make(chan struct{})
	probeStarted := make(chan struct{}, 1)
	go func() {
		defer close(cacheDone)
		c, err := relaycache.OpenQueued(ctx, dir, relaycache.Options{NodeID: e.journal.Node})
		if err != nil {
			acquired <- queuedResult{err}
			return
		}
		defer c.Close()
		other, err := open(c, e.underlays, e.journal.Domain, k)
		if err == nil {
			other.collector = e.collector
			select {
			case <-probeStarted:
			case <-ctx.Done():
				err = ctx.Err()
			}
			if err == nil {
				_, err = other.MaintainLeases(ctx)
			}
			other.Close()
		}
		acquired <- queuedResult{err}
		if err == nil {
			close(maintenance)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-cacheDone:
		case <-time.After(2 * time.Second):
			t.Error("competing owner failed to join")
		}
	})
	// Existing Store owns cache.lock. Confirm the competitor is queued before
	// reconciliation without inspecting host processes or network state.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("competitor failed to enter the admission wait")
		default:
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		queued := false
		for _, entry := range entries {
			queued = queued || strings.HasPrefix(entry.Name(), "admission-")
		}
		if queued {
			break
		}
		time.Sleep(time.Millisecond)
	}
	original := e.probe
	e.probe = func(ctx context.Context, en Entry, target relaycatalog.Target) (targetProof, error) {
		select {
		case probeStarted <- struct{}{}:
		default:
		}
		select {
		case <-maintenance:
		case <-ctx.Done():
			return targetProof{}, ctx.Err()
		}
		return original(ctx, en, target)
	}
	selector := appSelector(t)
	fresh := e
	t.Cleanup(func() {
		if fresh != nil {
			fresh.Close()
			fresh.cache.Close()
		}
	})
	var out TargetReconcileResult
	for n := 0; n < 2; n++ {
		var resumed *Engine
		var err error
		out, resumed, err = fresh.ReconcileTargetWithHandoff(ctx, "app", "", selector, time.Second, owner)
		if resumed == nil {
			t.Fatalf("reconcile did not reacquire owner: %v", err)
		}
		fresh = resumed
		if n == 0 && (out.Applied || out.Application.Activated) {
			t.Fatal("single observation applied")
		}
		if n == 1 && (err != nil || !out.Applied || !out.Application.Activated) {
			t.Fatalf("reconcile failed after maintenance and confirmation: %+v %v", out, err)
		}
	}
	select {
	case result := <-acquired:
		if result.err != nil {
			t.Fatal("competing maintenance failed", result.err)
		}
	case <-ctx.Done():
		t.Fatal("competing maintenance did not run")
	}
	<-cacheDone
}

func TestReconcileTargetHandoffReentryFailureCannotMutateRoutes(t *testing.T) {
	e, m, k, dir := appFixture(t)
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k, reacquireErr: context.DeadlineExceeded}
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	before := m.mutations
	out, closed, err := e.ReconcileTargetWithHandoff(ctx, "app", "", appSelector(t), time.Second, owner)
	if err == nil || closed != e || !closed.closed || out.Applied || out.Application.Activated {
		t.Fatalf("failed reentry retained decision authority: %+v %v", out, err)
	}
	if m.mutations != before || k.blocks != 0 {
		t.Fatal("failed reentry mutated routes or leases")
	}
	closed.Close()
	closed.cache.Close()
}

func TestReconcileTargetHandoffReturnsEngineFromFailedReacquire(t *testing.T) {
	e, m, k, dir := appFixture(t)
	var acquired *Engine
	t.Cleanup(func() {
		if acquired != nil {
			acquired.Close()
			acquired.cache.Close()
		} else {
			e.Close()
			e.cache.Close()
		}
	})
	owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k, reacquireErr: errors.New("reentry reported failure"), returnEngineOnError: true}
	out, current, err := e.ReconcileTargetWithHandoff(relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{}), "app", "", appSelector(t), time.Second, owner)
	acquired = current
	if err == nil || acquired == nil || acquired == e || !errors.Is(err, errTargetObservationOwnership) || out.Applied {
		t.Fatalf("failed reacquire resources were not returned: engine=%p output=%+v error=%v", acquired, out, err)
	}
}

func TestReconcileTargetHandoffRejectsReplacementCacheBeforeDecision(t *testing.T) {
	for _, mode := range []string{"same_store", "cloned_cache"} {
		t.Run(mode, func(t *testing.T) {
			e, m, k, dir := appFixture(t)
			owner := &testObservationOwner{dir: dir, source: e, machine: m, kernel: k}
			if mode == "same_store" {
				owner.keepStore = true
			} else {
				owner.cloneDir = filepath.Join(t.TempDir(), "replacement-cache")
			}
			ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
			beforeRoutes, beforeBlocks := m.mutations, k.blocks
			out, fresh, err := e.ReconcileTargetWithHandoff(ctx, "app", "", appSelector(t), time.Second, owner)
			if fresh == nil {
				t.Fatalf("rejected fresh ownership was lost: %v", err)
			}
			t.Cleanup(func() {
				fresh.Close()
				fresh.cache.Close()
			})
			if !errors.Is(err, errTargetObservationOwnership) || out.Selection.Reason != "observation_ownership_changed" || out.Applied || out.Application.Activated {
				t.Fatalf("replacement cache was accepted: %+v %v", out, err)
			}
			if m.mutations != beforeRoutes || k.blocks != beforeBlocks {
				t.Fatalf("replacement cache reached route/lease mutation: routes %d->%d blocks %d->%d", beforeRoutes, m.mutations, beforeBlocks, k.blocks)
			}
		})
	}
}

func TestReconcileTargetReleaseFailureStopsBeforeRouteMutation(t *testing.T) {
	e, m, k, _ := appFixture(t)
	t.Cleanup(func() {
		e.Close()
		e.cache.Close()
	})
	owner := &testObservationOwner{source: e, machine: m, kernel: k, releaseErr: errors.New("store close failed")}
	beforeRoutes, beforeBlocks := m.mutations, k.blocks
	out, current, err := e.ReconcileTargetWithHandoff(relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{}), "app", "", appSelector(t), time.Second, owner)
	if err == nil || current != e || out.Selection.Reason != "observation_ownership_changed" || out.Application.Activated {
		t.Fatalf("release failure continued reconciliation: %+v %v", out, err)
	}
	if m.mutations != beforeRoutes || k.blocks != beforeBlocks {
		t.Fatal("release failure mutated routes or leases")
	}
}
