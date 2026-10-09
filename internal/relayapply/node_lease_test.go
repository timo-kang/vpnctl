// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayguard"
)

type fakeNodeLease struct {
	mu sync.Mutex
	*fakeKernel
	active           map[string]bool
	failPath         string
	renewals, blocks int
}

func (k *fakeNodeLease) Lease(_ context.Context, e Entry, f FreshApproval) (DeploymentLease, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e.Candidate.PathID == k.failPath {
		return DeploymentLease{}, ErrConflict
	}
	if !k.active[e.Candidate.PathID] && f.At.IsZero() {
		return DeploymentLease{}, ErrLeaseExpired
	}
	k.renewals++
	k.active[e.Candidate.PathID] = true
	return DeploymentLease{Active: true, Boot: &relayguard.State{Active: true, DeadlineNS: e.ApprovalBootNS}}, nil
}
func (k *fakeNodeLease) LeaseStatus(_ context.Context, e Entry) (DeploymentLease, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return DeploymentLease{Active: k.active[e.Candidate.PathID], Boot: &relayguard.State{Active: k.active[e.Candidate.PathID], DeadlineNS: e.ApprovalBootNS}}, nil
}
func (k *fakeNodeLease) Block(_ context.Context, e Entry) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.blocks++
	k.active[e.Candidate.PathID] = false
	return nil
}
func nodeLeaseFixture(t *testing.T) (*Engine, *fakeNodeLease, string) {
	e, k, dir := fixture(t, "robot")
	w, _, _, err := e.cache.LeaseApproval()
	if err != nil {
		t.Fatal(err)
	}
	e.journal.Domain = w.Domain
	b := &fakeNodeLease{fakeKernel: k, active: map[string]bool{}}
	e.backend = b
	return e, b, dir
}
func TestNodeLeaseRestartCannotRearmAndFaultIsolation(t *testing.T) {
	for _, size := range []int{1, 4, 8} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			e, k, dir := nodeLeaseFixture(t)
			for i := 0; i < size; i++ {
				r, err := e.PrepareProtected(context.Background(), fmt.Sprint("p", i), "", true)
				if err != nil || r.KernelReady || r.Reason != "lease_inactive" {
					t.Fatal(r, err)
				}
			}
			if r, err := e.MaintainLeases(context.Background()); err != nil || !r.KernelReady || len(r.Paths) != size {
				t.Fatal(r, err)
			}
			e = reopen(t, e, dir)
			if _, err := e.MaintainLeases(context.Background()); err != nil {
				t.Fatal("cached continuation", err)
			}
			k.active["p0"] = false
			r, err := e.MaintainLeases(context.Background())
			if err == nil || r.KernelReady || k.active["p0"] {
				t.Fatal("rearmed from disk", r, err)
			}
			for i := 1; i < size; i++ {
				if !k.active[fmt.Sprint("p", i)] {
					t.Fatal("independent candidate starved")
				}
			}
			k.foreign = true
			_, err = e.MaintainLeases(context.Background())
			if err == nil || len(k.objects) != size {
				t.Fatal("foreign state adopted or deleted")
			}
			for _, active := range k.active {
				if active {
					t.Fatal("conflicting candidate not blocked")
				}
			}
		})
	}
}
func TestNodeLeaseUncertainJournalBlocksAll(t *testing.T) {
	e, k, _ := nodeLeaseFixture(t)
	for _, p := range []string{"p0", "p1"} {
		if _, err := e.PrepareProtected(context.Background(), p, "", true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.MaintainLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.uncertain = true
	if _, err := e.MaintainLeases(context.Background()); !errors.Is(err, relaycache.ErrUncertain) {
		t.Fatal(err)
	}
	if k.active["p0"] || k.active["p1"] {
		t.Fatal("uncertain journal kept live leases")
	}
}
func TestNodeLeaseObserveKeepsMaintenanceSeparate(t *testing.T) {
	e, k, _ := nodeLeaseFixture(t)
	for i := 0; i < 8; i++ {
		if _, err := e.PrepareProtected(context.Background(), fmt.Sprint("p", i), "", true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.MaintainLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := k.renewals
	r, err := e.observeTarget(context.Background(), "app", "", time.Second, func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		return targetProof{handshake: 1, rx: 1, tx: 1}, nil
	})
	if err != nil || !r.Valid || len(r.Paths) != 8 || k.renewals-before != 8 {
		t.Fatal(r, err, k.renewals-before)
	}
	for _, p := range r.Paths {
		if p.State != "reachable" {
			t.Fatal(p)
		}
	}
}

func TestNodeLeasePrepareFaultsAndRecoveryNeverGrant(t *testing.T) {
	for _, step := range []string{"link", "tag", "guard", "endpoint", "rule", "address", "wg", "up", "probe-targets", "probe-source"} {
		for _, mode := range []string{"before", "after", "crash"} {
			t.Run(step+"/"+mode, func(t *testing.T) {
				e, k, dir := nodeLeaseFixture(t)
				k.fail = step
				k.after = mode != "before"
				k.crash = mode == "crash"
				if mode == "crash" {
					func() {
						defer func() {
							if recover() == nil {
								t.Fatal("fault not exercised")
							}
						}()
						e.PrepareProtected(context.Background(), "p0", "", true)
					}()
					e = reopen(t, e, dir)
					if out, err := e.Recover(context.Background()); err != nil || out.State != "empty" {
						t.Fatal(out, err)
					}
				} else {
					if _, err := e.PrepareProtected(context.Background(), "p0", "", true); err == nil {
						t.Fatal("failed prepare succeeded")
					}
				}
				if k.renewals != 0 || k.active["p0"] || len(k.objects) != 0 || len(e.journal.Entries) != 0 {
					t.Fatal("failed prepare granted or leaked", k.renewals)
				}
			})
		}
	}
}

func TestNodeLeaseJournalFailuresCannotAuthorize(t *testing.T) {
	for _, point := range []int{1, 2} {
		t.Run(fmt.Sprint(point), func(t *testing.T) {
			e, k, dir := nodeLeaseFixture(t)
			save := e.save
			writes := 0
			e.save = func(b []byte) error {
				writes++
				if writes == point {
					return relaycache.ErrUncertain
				}
				return save(b)
			}
			if _, err := e.PrepareProtected(context.Background(), "p0", "", true); err == nil {
				t.Fatal("lost durable commit accepted")
			}
			if _, err := e.MaintainLeases(context.Background()); err == nil || k.renewals != 0 || k.active["p0"] {
				t.Fatal("uncertain intent granted lease", err)
			}
			e = reopen(t, e, dir)
			if out, err := e.Recover(context.Background()); err != nil || out.State != "empty" || len(k.objects) != 0 {
				t.Fatal(out, err)
			}
		})
	}
}
