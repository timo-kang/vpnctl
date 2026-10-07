// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

func TestUnchangedTargetUsesFreshApplicationProofWithoutAnotherBoundProbe(t *testing.T) {
	e, m, _, _ := appFixture(t)
	s := activateApp(t, e)
	var bound atomic.Int32
	e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		bound.Add(1)
		return targetProof{handshake: 1, rx: 1, tx: 1}, nil
	}
	probe, ordinary := e.appProbe, 0
	e.appProbe = func(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
		ordinary++
		return probe(ctx, g, entry, target)
	}
	mutations := m.mutations
	out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
	if err != nil || !out.Applied || bound.Load() != 3 || ordinary != 1 || m.mutations != mutations {
		t.Fatal("steady route duplicated proofs or lost actual application verification", out, err, bound.Load(), ordinary, m.mutations-mutations)
	}
	bound.Store(0)
	s.RecordApplied("p1", time.Now())
	out, err = e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
	if err != nil || !out.Applied || out.Selection.DesiredPathID != "p1" || bound.Load() != 4 || m.mutations == mutations {
		t.Fatal("changed route lost candidate revalidation", out, err, bound.Load())
	}
}

func TestUnchangedTargetRejectsFaultBeforeAndDuringApplicationProof(t *testing.T) {
	for _, moment := range []string{"before", "during"} {
		for _, fault := range []string{"lease", "kernel", "approval", "underlay", "unbound"} {
			t.Run(moment+"/"+fault, func(t *testing.T) {
				e, m, k, _ := appFixture(t)
				events := &testUnderlayEvents{}
				ctx := relayobserve.WithUnderlayEvents(context.Background(), events)
				s := appSelector(t)
				for i := 0; i < 2; i++ {
					e.ReconcileTarget(ctx, "app", "", s, time.Second)
				}
				r, err := e.ObserveTarget(ctx, "app", "", time.Second)
				if err != nil {
					t.Fatal(err)
				}
				d := s.Decide(r)
				g := e.journal.Targets[0]
				if g.Phase != "active" || d.DesiredPathID != "p0" {
					t.Fatal("missing steady baseline", g, d)
				}
				inject := func() {
					switch fault {
					case "lease":
						k.active["p0"] = false
					case "kernel":
						k.foreign = true
					case "approval":
						e.cache.Refresh(ctx, &rejectTargetApproval{})
					case "underlay":
						events.version.Add(1)
					}
				}
				probe, called := e.appProbe, false
				e.appProbe = func(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
					called = true
					if moment == "during" {
						inject()
					}
					if fault == "unbound" {
						return ApplicationProof{}, errors.New("ordinary application cannot reach target")
					}
					return probe(ctx, g, entry, target)
				}
				if moment == "before" {
					inject()
				}
				mutations := m.mutations
				out, err := e.applyTarget(ctx, g, g.Active, d, time.Second)
				if err == nil || out.Activated || m.mutations != mutations {
					t.Fatal("invalid steady path verified or rewritten", out, err)
				}
				if moment == "before" && fault != "unbound" && called {
					t.Fatal("invalid precheck reached application TCP")
				}
			})
		}
	}
}
