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
	"vpnctl/internal/relayobserve"
)

type testUnderlayEvents struct {
	version     atomic.Int64
	unavailable atomic.Bool
}

func (e *testUnderlayEvents) Generation(ctx context.Context, id string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if e.unavailable.Load() {
		return "", fmt.Errorf("event stream lost")
	}
	n := int64(0)
	if id == "lan0" {
		n = e.version.Load()
	}
	return fmt.Sprintf("%064d", n), nil
}
func TestUnderlayEventsRejectChangesDuringTCPAndDoNotInvalidateOtherPaths(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(fmt.Sprint(loss), func(t *testing.T) {
			e, _ := waveFixture(t)
			events := &testUnderlayEvents{}
			ctx := relayobserve.WithUnderlayEvents(context.Background(), events)
			out, err := e.observeTarget(ctx, "app", "", time.Second, func(_ context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
				if entry.Candidate.PathID == "p0" {
					if loss {
						events.unavailable.Store(true)
					} else {
						events.version.Add(1)
					}
				}
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			})
			if err != nil || !out.Valid {
				t.Fatal(out, err)
			}
			for _, p := range out.Paths {
				if p.PathID == "p0" && p.State != "unknown" {
					t.Fatal("ABA escaped TCP postcheck", p)
				}
				if !loss && p.UnderlayID != "lan0" && p.State != "reachable" {
					t.Fatal("unrelated underlay invalidated", p)
				}
				if loss && p.State != "unknown" {
					t.Fatal("stream loss accepted", p)
				}
			}
		})
	}
}
func TestUnderlayEventsRejectBetweenConfirmationAndCommit(t *testing.T) {
	for _, where := range []string{"before-apply", "during-app-proof", "between-proofs"} {
		t.Run(where, func(t *testing.T) {
			e, _, _, _ := appFixture(t)
			events := &testUnderlayEvents{}
			ctx := relayobserve.WithUnderlayEvents(context.Background(), events)
			s := appSelector(t)
			first, _ := e.ReconcileTarget(ctx, "app", "", s, time.Second)
			if first.Applied {
				t.Fatal("single proof accepted")
			}
			report, err := e.ObserveTarget(ctx, "app", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			d := s.Decide(report)
			if d.DesiredPathID != "p0" {
				t.Fatal(d)
			}
			g := e.journal.Targets[e.targetIndex("app")]
			entry := e.journal.Entries[e.index("p0")]
			switch where {
			case "before-apply":
				events.version.Add(1)
			case "between-proofs":
				e.targets = &changingApplicationRoutes{targetBackend: e.targets, targetApplicationBackend: e.targets.(targetApplicationBackend), change: func() { events.version.Add(1) }}
			case "during-app-proof":
				original := e.appProbe
				e.appProbe = func(ctx context.Context, g TargetGuard, e Entry, target relaycatalog.Target) (ApplicationProof, error) {
					events.version.Add(1)
					return original(ctx, g, e, target)
				}

			}
			out, err := e.applyTarget(ctx, g, routeForEntry(entry), d, time.Second)
			if err == nil || out.Activated {
				t.Fatal("old decision activated", out, err)
			}
			if _, err := e.quarantineTarget(ctx, "app"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestUnderlayEventsDisallowOldGenerationRollback(t *testing.T) {
	e, _, _, _ := appFixture(t)
	events := &testUnderlayEvents{}
	ctx := relayobserve.WithUnderlayEvents(context.Background(), events)
	s := appSelector(t)
	for i := 0; i < 2; i++ {
		out, err := e.ReconcileTarget(ctx, "app", "", s, time.Second)
		if i == 1 && (err != nil || !out.Applied) {
			t.Fatal(out, err)
		}
	}
	report, err := e.ObserveTarget(ctx, "app", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Decide(report)
	old := e.journal.Targets[e.targetIndex("app")]
	events.version.Add(1)
	out, err := e.rollbackTarget(ctx, old, d, time.Second, fmt.Errorf("switch failed"))
	if err == nil || out.Activated || !out.Guarded {
		t.Fatal("old-generation rollback reopened", out, err)
	}
}

type changingApplicationRoutes struct {
	targetBackend
	targetApplicationBackend
	change func()
}

func (b *changingApplicationRoutes) SetRoutes(ctx context.Context, g TargetGuard, entries []Entry, r *TargetRoute) error {
	err := b.targetApplicationBackend.SetRoutes(ctx, g, entries, r)
	if err == nil && r != nil {
		b.change()
	}
	return err
}

type underlayEventsFunc func(context.Context, string) (string, error)

func (f underlayEventsFunc) Generation(ctx context.Context, id string) (string, error) {
	return f(ctx, id)
}

func TestUnderlayFinalReadCannotCommitExpiredOrCancelledDecision(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, _ := appFixture(t)
			events := &testUnderlayEvents{}
			ctx, cancel := context.WithCancel(relayobserve.WithUnderlayEvents(context.Background(), events))
			defer cancel()
			s := appSelector(t)
			_, _ = e.ReconcileTarget(ctx, "app", "", s, time.Second)
			report, err := e.ObserveTarget(ctx, "app", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			d := s.Decide(report)
			if d.DesiredPathID != "p0" {
				t.Fatal(d)
			}
			d.ValidUntil = time.Now().Add(time.Second)
			g := e.journal.Targets[e.targetIndex("app")]
			entry := e.journal.Entries[e.index("p0")]
			afterProof, finalRead := false, false
			reads := 0
			original := e.appProbe
			e.appProbe = func(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
				proof, err := original(ctx, g, entry, target)
				afterProof = true
				return proof, err
			}
			ctx = relayobserve.WithUnderlayEvents(ctx, underlayEventsFunc(func(ctx context.Context, id string) (string, error) {
				generation, err := events.Generation(ctx, id)
				if afterProof {
					reads++
				}
				if reads == 2 {
					finalRead = true
					if mode == "deadline" {
						time.Sleep(time.Until(d.ValidUntil) + time.Millisecond)
					} else {
						cancel()
					}
				}
				return generation, err
			}))
			out, err := e.applyTarget(ctx, g, routeForEntry(entry), d, time.Second)
			if !finalRead {
				t.Fatal("final read boundary not exercised", out, err)
			}
			if err == nil || out.Activated {
				t.Fatal("decision committed after last read consumed validity", out, err)
			}
		})
	}
}
