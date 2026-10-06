// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func waveFixture(t *testing.T) (*Engine, *fakeNodeLease) {
	t.Helper()
	e, k, _ := nodeLeaseFixture(t)
	for i := 0; i < 8; i++ {
		if _, err := e.PrepareProtected(context.Background(), fmt.Sprint("p", i), "", true); err != nil {
			t.Fatal(err)
		}
	}
	return e, k
}
func TestObservationProofsOverlapButChecksAndRenewalsDoNot(t *testing.T) {
	e, k := waveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var checking, peak, probes atomic.Int32
	k.onCheck = func() {
		n := checking.Add(1)
		if n > 1 {
			t.Error("kernel checks overlap")
		}
		time.Sleep(time.Millisecond)
		checking.Add(-1)
	}
	entered := make(chan string, 8)
	release := make(chan struct{})
	done := make(chan TargetReport, 1)
	go func() {
		out, _ := e.observeTarget(ctx, "app", "", time.Second, func(ctx context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
			n := probes.Add(1)
			defer probes.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			entered <- entry.Candidate.PathID
			select {
			case <-release:
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			case <-ctx.Done():
				return targetProof{}, ctx.Err()
			}
		})
		done <- out
	}()
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		select {
		case id := <-entered:
			seen[id] = true
		case <-time.After(2 * time.Second):
			t.Fatal("slow path serialized unrelated proofs")
		}
	}
	if len(seen) != 8 || peak.Load() != 8 {
		t.Fatal("unbounded or missing proof population", seen, peak.Load())
	}
	// Release all proofs, then join them before return.
	close(release)
	out := <-done
	if !out.Valid || probes.Load() != 0 || k.renewals != 8 || out.Diagnostics.Phases["maintenance"].Calls != 1 {
		t.Fatal(out, probes.Load(), k.renewals)
	}
	for _, p := range out.Paths {
		if p.State != "reachable" {
			t.Fatal(p)
		}
	}
}
func TestObservationCancellationJoinsAllProbes(t *testing.T) {
	e, _ := waveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 8)
	var live atomic.Int32
	done := make(chan TargetReport, 1)
	go func() {
		out, _ := e.observeTarget(ctx, "app", "", 2*time.Second, func(ctx context.Context, _ Entry, _ relaycatalog.Target) (targetProof, error) {
			live.Add(1)
			defer live.Add(-1)
			entered <- struct{}{}
			<-ctx.Done()
			return targetProof{}, ctx.Err()
		})
		done <- out
	}()
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("missing probe")
		}
	}
	cancel()
	select {
	case out := <-done:
		if out.Valid || live.Load() != 0 {
			t.Fatal("canceled wave retained evidence/work", out, live.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not drain probes")
	}
}

type exhaustedWaveBackend struct {
	*fakeNodeLease
	checks int
}

func (k *exhaustedWaveBackend) Check(ctx context.Context, e Entry, fresh bool) (bool, error) {
	k.checks++
	if k.checks > 8 {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return k.fakeNodeLease.Check(ctx, e, fresh)
}
func TestObservationBudgetExhaustionCannotCreateHealth(t *testing.T) {
	e, k := waveFixture(t)
	e.backend = &exhaustedWaveBackend{fakeNodeLease: k}
	began := time.Now()
	called := false
	out, err := e.observeTarget(context.Background(), "app", "", time.Second, func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		called = true
		return targetProof{handshake: 1, rx: 1, tx: 1}, nil
	})
	if err != nil || !out.Valid || out.Reason != "observation_budget_exhausted" || called || time.Since(began) > 5*time.Second {
		t.Fatal(out, err, called, time.Since(began))
	}
	for _, p := range out.Paths {
		if p.State != "unknown" {
			t.Fatal("unverified health escaped exhausted wave", p)
		}
	}
}
