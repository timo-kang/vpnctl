// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayguard"
)

// Only the independent lease operations may overlap. The inherited fake kernel
// is used during serialized preparation/checks and never mutated by Lease.
type overlapLeaseBackend struct {
	*fakeKernel
	mu                 sync.Mutex
	active             map[string]bool
	grants, blocks     map[string]int
	inflight, peak     int
	started, finished  chan string
	gates              map[string]<-chan struct{}
	fail               map[string]error
	beforeGrant        func(Entry) error
	beforeCheck        func(context.Context, Entry) error
	onStart            func(Entry)
	canceled           chan string
	finishCancellation <-chan struct{}
}

func (b *overlapLeaseBackend) Lease(ctx context.Context, e Entry, _ FreshApproval) (DeploymentLease, error) {
	p := e.Candidate.PathID
	b.mu.Lock()
	b.inflight++
	if b.inflight > b.peak {
		b.peak = b.inflight
	}
	b.mu.Unlock()
	b.started <- p
	if b.onStart != nil {
		b.onStart(e)
	}
	defer func() {
		b.mu.Lock()
		b.inflight--
		b.mu.Unlock()
		b.finished <- p
	}()
	if gate := b.gates[p]; gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			if b.canceled != nil {
				b.canceled <- p
				<-b.finishCancellation
			}
			return DeploymentLease{}, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return DeploymentLease{}, err
	}
	if err := b.fail[p]; err != nil {
		return DeploymentLease{}, err
	}
	if b.beforeGrant != nil {
		if err := b.beforeGrant(e); err != nil {
			return DeploymentLease{}, err
		}
	}
	b.mu.Lock()
	b.active[p] = true
	b.grants[p]++
	b.mu.Unlock()
	return DeploymentLease{Active: true, Boot: &relayguard.State{Active: true, DeadlineNS: e.ApprovalBootNS}}, nil
}

func (b *overlapLeaseBackend) Check(ctx context.Context, e Entry, fresh bool) (bool, error) {
	if b.beforeCheck != nil {
		if err := b.beforeCheck(ctx, e); err != nil {
			return false, err
		}
	}
	return b.fakeKernel.Check(ctx, e, fresh)
}

func (b *overlapLeaseBackend) LeaseStatus(_ context.Context, e Entry) (DeploymentLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	active := b.active[e.Candidate.PathID]
	return DeploymentLease{Active: active, Boot: &relayguard.State{Active: active, DeadlineNS: e.ApprovalBootNS}}, nil
}

func (b *overlapLeaseBackend) Block(_ context.Context, e Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active[e.Candidate.PathID] = false
	b.blocks[e.Candidate.PathID]++
	return nil
}

func overlapLeaseFixture(t *testing.T, size int) (*Engine, *overlapLeaseBackend) {
	t.Helper()
	e, b, _ := overlapLeaseFixtureDirectory(t, size)
	return e, b
}

func overlapLeaseFixtureDirectory(t *testing.T, size int) (*Engine, *overlapLeaseBackend, string) {
	t.Helper()
	e, k, dir := nodeLeaseFixture(t)
	for i := 0; i < size; i++ {
		if _, err := e.PrepareProtected(context.Background(), fmt.Sprint("p", i), "", true); err != nil {
			t.Fatal(err)
		}
	}
	b := &overlapLeaseBackend{
		fakeKernel: k.fakeKernel,
		active:     map[string]bool{}, grants: map[string]int{}, blocks: map[string]int{},
		started: make(chan string, 32), finished: make(chan string, 32),
		gates: map[string]<-chan struct{}{}, fail: map[string]error{},
	}
	e.backend = b
	return e, b, dir
}

type overlapMaintenanceResult struct {
	result Result
	err    error
}

func overlapMaintain(ctx context.Context, e *Engine) <-chan overlapMaintenanceResult {
	done := make(chan overlapMaintenanceResult, 1)
	go func() {
		r, err := e.MaintainLeases(ctx)
		done <- overlapMaintenanceResult{r, err}
	}()
	return done
}

func overlapWait(t *testing.T, done <-chan overlapMaintenanceResult) overlapMaintenanceResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not join its lease workers")
		return overlapMaintenanceResult{}
	}
}

func TestNodeLeaseOverlapSlowCandidateDoesNotHoldReadyCandidate(t *testing.T) {
	e, b := overlapLeaseFixture(t, 2)
	release := make(chan struct{})
	b.gates["p0"] = release
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := overlapMaintain(ctx, e)
	select {
	case p := <-b.finished:
		if p != "p1" {
			t.Errorf("first completed path = %s, want independent p1", p)
		}
	case <-time.After(time.Second):
		t.Error("ready p1 could not renew while independent p0 was blocked")
	}
	close(release)
	r := overlapWait(t, done)
	if r.err != nil || !r.result.KernelReady || !b.active["p0"] || !b.active["p1"] {
		t.Fatal("independent candidates did not both complete", r.err)
	}
}

func TestNodeLeaseOverlapHasTwoWorkerBoundAndStableResults(t *testing.T) {
	e, b := overlapLeaseFixture(t, 8)
	release := make(chan struct{})
	for i := 0; i < 8; i++ {
		b.gates[fmt.Sprint("p", i)] = release
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := overlapMaintain(ctx, e)
	started := 0
	watchdog := time.NewTimer(time.Second)
	defer watchdog.Stop()
wait:
	for started < 2 {
		select {
		case <-b.started:
			started++
		case <-watchdog.C:
			t.Errorf("only %d renewal workers started while first candidate was blocked", started)
			break wait
		}
	}
	if started == 2 {
		select {
		case <-b.started:
			t.Error("more than two simultaneous renewal workers were admitted")
		case <-time.After(50 * time.Millisecond):
		}
	}
	close(release)
	r := overlapWait(t, done)
	if r.err != nil || !r.result.KernelReady || len(r.result.Paths) != 8 || b.inflight != 0 || b.peak != 2 {
		t.Fatalf("renewal bound/result failed: paths=%d inflight=%d peak=%d err=%v", len(r.result.Paths), b.inflight, b.peak, r.err)
	}
	for i, p := range r.result.Paths {
		if p.PathID != fmt.Sprint("p", i) || !p.KernelReady || b.grants[p.PathID] != 1 {
			t.Error("result order or per-candidate completion changed")
		}
	}
}

func TestNodeLeaseOverlapCancellationJoinsBeforeReturn(t *testing.T) {
	e, b := overlapLeaseFixture(t, 8)
	gate, cleanup := make(chan struct{}), make(chan struct{})
	b.gates["p0"], b.gates["p1"] = gate, gate
	b.canceled, b.finishCancellation = make(chan string, 2), cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := overlapMaintain(ctx, e)
	started := 0
	watchdog := time.NewTimer(time.Second)
	defer watchdog.Stop()
wait:
	for started < 2 {
		select {
		case <-b.started:
			started++
		case <-watchdog.C:
			t.Errorf("only %d renewal workers started", started)
			break wait
		}
	}
	cancel()
	for i := 0; i < started; i++ {
		select {
		case <-b.canceled:
		case <-time.After(time.Second):
			t.Error("renewal worker did not observe cancellation")
		}
	}
	select {
	case <-done:
		close(cleanup)
		t.Fatal("maintenance returned before canceled workers completed cleanup")
	case <-time.After(50 * time.Millisecond):
	}
	close(cleanup)
	r := overlapWait(t, done)
	if !errors.Is(r.err, context.Canceled) || r.result.KernelReady || b.inflight != 0 || len(b.grants) != 0 {
		t.Fatal("cancellation granted a lease or failed to join", r.err)
	}
	if len(b.started) != 0 {
		t.Error("queued renewal started after cancellation")
	}
	for _, p := range r.result.Paths {
		if p.KernelReady || b.active[p.PathID] || b.blocks[p.PathID] == 0 {
			t.Error("canceled path was left usable")
		}
	}
}

func TestNodeLeaseOverlapFailureBlocksOnlyFailedPath(t *testing.T) {
	e, b := overlapLeaseFixture(t, 8)
	b.fail["p0"] = ErrConflict
	r, err := e.MaintainLeases(context.Background())
	if !errors.Is(err, ErrConflict) || r.KernelReady || len(r.Paths) != 8 {
		t.Fatal("failed candidate was not reported", err)
	}
	for _, p := range r.Paths {
		if p.PathID == "p0" {
			if p.KernelReady || b.active[p.PathID] || b.blocks[p.PathID] != 1 {
				t.Error("failed candidate remained active")
			}
		} else if !p.KernelReady || !b.active[p.PathID] || b.blocks[p.PathID] != 0 {
			t.Error("independent candidate was blocked by another candidate's failure")
		}
	}
}

func TestNodeLeaseOverlapChecksNextCandidateAfterFirstRenewalStarts(t *testing.T) {
	e, b := overlapLeaseFixture(t, 2)
	firstRenewing := make(chan struct{})
	b.onStart = func(entry Entry) {
		if entry.Candidate.PathID == "p0" {
			// An external manager changes the next candidate as the first
			// begins renewal. Its earlier preparation is no longer sufficient.
			close(firstRenewing)
		}
	}
	b.beforeCheck = func(ctx context.Context, entry Entry) error {
		if entry.Candidate.PathID != "p1" {
			return nil
		}
		select {
		case <-firstRenewing:
			return ErrConflict
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := e.MaintainLeases(ctx)
	if !errors.Is(err, ErrConflict) || len(r.Paths) != 2 || !b.active["p0"] || b.grants["p0"] != 1 || b.active["p1"] || b.grants["p1"] != 0 || b.blocks["p1"] != 1 {
		t.Fatal("candidate ownership was not checked at dispatch", err)
	}
}

func TestNodeLeaseOverlapGrantFollowsDurableAuthority(t *testing.T) {
	e, b := overlapLeaseFixture(t, 4)
	// Keep the authentic current approval, but require its longer deadline to
	// replace an older durable bound before the backend may grant it.
	for i := range e.journal.Entries {
		e.journal.Entries[i].ApprovalUntil = e.journal.Entries[i].ApprovalUntil.Add(-time.Second)
		e.journal.Entries[i].ApprovalBootNS -= uint64(time.Second)
	}
	if err := e.persist(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	durable := append([]Entry(nil), e.journal.Entries...)
	save := e.save
	e.save = func(raw []byte) error {
		if err := save(raw); err != nil {
			return err
		}
		var saved envelope
		if err := json.Unmarshal(raw, &saved); err != nil {
			return err
		}
		mu.Lock()
		durable = saved.Journal.Entries
		mu.Unlock()
		return nil
	}
	b.beforeGrant = func(entry Entry) error {
		mu.Lock()
		defer mu.Unlock()
		for _, saved := range durable {
			if saved.Candidate.PathID == entry.Candidate.PathID && saved.Generation == entry.Generation && saved.ApprovalUntil.Equal(entry.ApprovalUntil) && saved.ApprovalBootNS == entry.ApprovalBootNS {
				return nil
			}
		}
		return errors.New("lease attempted before matching durable authority")
	}
	r, err := e.MaintainLeases(context.Background())
	if err != nil || !r.KernelReady || len(b.grants) != 4 {
		t.Fatal("durable authority did not precede every grant", err)
	}
}

func TestNodeLeaseOverlapUncertainJournalNeverStartsRenewal(t *testing.T) {
	for _, mode := range []string{"already_uncertain", "authority_commit_failed", "later_authority_commit_failed"} {
		t.Run(mode, func(t *testing.T) {
			e, b := overlapLeaseFixture(t, 4)
			for _, entry := range e.journal.Entries {
				b.active[entry.Candidate.PathID] = true
			}
			if mode == "already_uncertain" {
				e.uncertain = true
			} else {
				for i := range e.journal.Entries {
					e.journal.Entries[i].ApprovalUntil = e.journal.Entries[i].ApprovalUntil.Add(-time.Second)
				}
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
				writes := 0
				save := e.save
				e.save = func(raw []byte) error {
					writes++
					if mode == "authority_commit_failed" || writes == 2 {
						return relaycache.ErrUncertain
					}
					return save(raw)
				}
			}
			r, err := e.MaintainLeases(context.Background())
			if err == nil || r.KernelReady || len(b.started) != 0 || len(b.grants) != 0 {
				t.Fatal("uncertain journal started or granted a renewal", err)
			}
			for _, p := range r.Paths {
				if b.active[p.PathID] || b.blocks[p.PathID] == 0 {
					t.Error("uncertain journal left a candidate usable")
				}
			}
		})
	}
}

var errOverlapExpiredCleanup = errors.New("test cleanup received an expired context")

// The production gates cannot be revoked with an already canceled context.
// Model that behavior, and record whether successful cleanup retained the
// existing deadline and happened only after all possible grants had joined.
type overlapRevocationBackend struct {
	*overlapLeaseBackend
	beforeBlock      func(context.Context, Entry)
	cleanupDeadlines []time.Time
	cleanupInflight  []int
}

func (b *overlapRevocationBackend) Block(ctx context.Context, entry Entry) error {
	if b.beforeBlock != nil {
		b.beforeBlock(ctx, entry)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(err, errOverlapExpiredCleanup)
		}
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("cleanup lost the maintenance deadline")
	}
	b.mu.Lock()
	b.cleanupDeadlines = append(b.cleanupDeadlines, deadline)
	b.cleanupInflight = append(b.cleanupInflight, b.inflight)
	b.mu.Unlock()
	return b.overlapLeaseBackend.Block(ctx, entry)
}

func assertOverlapRevoked(t *testing.T, e *Engine, b *overlapRevocationBackend, r Result, deadline time.Time) {
	t.Helper()
	if r.KernelReady || len(e.maintained) != 0 || b.inflight != 0 {
		t.Error("aborted sweep retained readiness or an unjoined renewal")
	}
	for _, p := range r.Paths {
		if p.KernelReady || p.Lease != nil && p.Lease.Active || b.active[p.PathID] || b.blocks[p.PathID] == 0 {
			t.Errorf("aborted path %s retained a live grant or readiness", p.PathID)
		}
	}
	for i, observed := range b.cleanupDeadlines {
		if !observed.Equal(deadline) || b.cleanupInflight[i] != 0 {
			t.Error("cleanup extended its deadline or ran before renewal workers joined")
		}
	}
	if len(b.cleanupDeadlines) == 0 {
		t.Error("no uncanceled bounded cleanup reached the gates")
	}
}

func TestNodeLeaseOverlapLateAuthorityFailureRevokesWholeSweep(t *testing.T) {
	for _, mode := range []string{"paused_renewal", "already_granted"} {
		t.Run(mode, func(t *testing.T) {
			e, base, dir := overlapLeaseFixtureDirectory(t, 4)
			b := &overlapRevocationBackend{overlapLeaseBackend: base}
			e.backend = b
			for _, entry := range e.journal.Entries {
				b.active[entry.Candidate.PathID] = true
			}
			first := make(chan struct{})
			b.onStart = func(entry Entry) {
				if entry.Candidate.PathID == "p0" {
					close(first)
				}
			}
			if mode == "paused_renewal" {
				release := make(chan struct{})
				b.gates["p0"] = release
				var once sync.Once
				// Keep the defective implementation finite: it attempts to
				// block p1 without canceling p0, which then incorrectly grants.
				b.beforeBlock = func(_ context.Context, entry Entry) {
					if entry.Candidate.PathID == "p1" {
						once.Do(func() { close(release) })
					}
				}
			}
			var deadline time.Time
			b.beforeCheck = func(ctx context.Context, entry Entry) error {
				if entry.Candidate.PathID == "p0" {
					deadline, _ = ctx.Deadline()
					return nil
				}
				if entry.Candidate.PathID != "p1" {
					return nil
				}
				if mode == "already_granted" {
					select {
					case <-b.finished:
					case <-ctx.Done():
						return ctx.Err()
					}
				} else {
					select {
					case <-first:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				// Status persists its clock checkpoint; deleting the backing
				// state file makes that authority checkpoint fail for real.
				return os.Remove(filepath.Join(dir, "state.json"))
			}
			r, err := e.MaintainLeases(context.Background())
			if err == nil {
				t.Fatal("missing durable authority checkpoint was accepted")
			}
			assertOverlapRevoked(t, e, b, r, deadline)
			if len(b.started) != 1 {
				t.Error("queued candidate started after global authority failure")
			}
			if mode == "paused_renewal" && b.grants["p0"] != 0 {
				t.Error("paused renewal granted after authority failure")
			}
			if mode == "already_granted" && b.grants["p0"] != 1 {
				t.Error("fixture did not exercise revocation of a completed grant")
			}
		})
	}
}

func TestNodeLeaseOverlapParentCancelUsesRemainingCleanupDeadline(t *testing.T) {
	e, base := overlapLeaseFixture(t, 4)
	b := &overlapRevocationBackend{overlapLeaseBackend: base}
	e.backend = b
	for _, entry := range e.journal.Entries {
		b.active[entry.Candidate.PathID] = true
	}
	first := make(chan struct{})
	b.gates["p0"] = make(chan struct{})
	b.onStart = func(entry Entry) {
		if entry.Candidate.PathID == "p0" {
			close(first)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var deadline time.Time
	b.beforeCheck = func(checkCtx context.Context, entry Entry) error {
		if entry.Candidate.PathID == "p0" {
			deadline, _ = checkCtx.Deadline()
		} else if entry.Candidate.PathID == "p1" {
			select {
			case <-first:
				cancel()
			case <-checkCtx.Done():
				return checkCtx.Err()
			}
		}
		return nil
	}
	r, err := e.MaintainLeases(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("parent cancellation was not reported", err)
	}
	assertOverlapRevoked(t, e, b, r, deadline)
	if len(b.started) != 1 || len(b.grants) != 0 {
		t.Error("queued candidate started or granted after parent cancellation")
	}
}

func TestNodeLeaseOverlapExpiredCleanupBudgetReportsFailure(t *testing.T) {
	e, base := overlapLeaseFixture(t, 2)
	b := &overlapRevocationBackend{overlapLeaseBackend: base}
	e.backend = b
	for _, entry := range e.journal.Entries {
		b.active[entry.Candidate.PathID] = true
	}
	b.gates["p0"] = make(chan struct{})
	b.beforeCheck = func(ctx context.Context, entry Entry) error {
		if entry.Candidate.PathID == "p1" {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	r, err := e.MaintainLeases(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errOverlapExpiredCleanup) || r.KernelReady || len(e.maintained) != 0 || b.inflight != 0 {
		t.Fatal("exhausted cleanup budget was not reported truthfully", err)
	}
	for _, p := range r.Paths {
		if p.KernelReady || p.Lease != nil && p.Lease.Active || !b.active[p.PathID] || b.blocks[p.PathID] != 0 {
			t.Error("expired cleanup incorrectly claimed revocation or readiness")
		}
	}
	if len(b.cleanupDeadlines) != 0 {
		t.Error("cleanup obtained a new budget after the original deadline")
	}
}
