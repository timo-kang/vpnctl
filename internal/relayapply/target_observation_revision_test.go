// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayselect"
)

// Model an ownership handoff; production still holds its lock across probes.
// One pinned candidate keeps the modeled journal write in a single worker.
func TestTargetObservationRejectsChangedReservationWithoutChangingReplacementRoute(t *testing.T) {
	for _, mode := range []string{"removed", "recreated", "active_route", "prefix", "node", "domain", "revision_aba", "verified_at", "expired_candidate"} {
		t.Run(mode, func(t *testing.T) {
			e, m, k, _ := appFixture(t)
			activateApp(t, e)
			p := relayselect.DefaultPolicy()
			p.Mode = "manual"
			p.ManualPin = "p0"
			s, err := relayselect.New(p)
			if err != nil {
				t.Fatal(err)
			}
			// Establish the same manual policy before injecting the ownership change.
			for i := 0; i < 2; i++ {
				out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
				if i == 1 && (err != nil || !out.Applied) {
					t.Fatal("manual baseline", err)
				}
			}
			mutations, blocks := m.mutations, k.blocks
			calls := 0
			e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
				calls++
				switch mode {
				case "removed":
					e.journal.Targets = nil
				case "recreated":
					e.journal.Targets[0].Owner = "vpnctl:11111111111111111111111111111111"
				case "active_route":
					e.journal.Targets[0].Active = routeForEntry(e.journal.Entries[1])
				case "prefix":
					e.journal.Targets[0].Prefixes[0] = "203.0.113.99/32"
				case "node":
					e.journal.Node += "-new"
				case "domain":
					e.journal.Domain += "-new"
				case "revision_aba":
					g := e.journal.Targets[0]
					original := g.Active
					g.Active = routeForEntry(e.journal.Entries[1])
					g.RouteRevision = nextRouteRevision(g.RouteRevision)
					e.journal.Targets[0] = g
					if err := e.persist(); err != nil {
						t.Error(err)
					}
					g.Active = original
					g.RouteRevision = nextRouteRevision(g.RouteRevision)
					e.journal.Targets[0] = g
					if err := e.persist(); err != nil {
						t.Error(err)
					}
				case "verified_at":
					at := e.journal.Targets[0].VerifiedAt.Add(time.Second)
					e.journal.Targets[0].VerifiedAt = &at
				case "expired_candidate":
					e.journal.Targets[0].Owner = "vpnctl:11111111111111111111111111111111"
					k.active["p0"] = false
				}
				mutations, blocks = m.mutations, k.blocks
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			}
			out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
			if calls != 1 || !errors.Is(err, ErrConflict) || out.Applied || out.Application.Activated || out.Application.Guarded || out.Application.Reason != "target_changed_during_observation" || out.Application.Reservation != nil {
				t.Fatalf("stale target result: calls=%d err=%v applied=%t reason=%s", calls, err, out.Applied, out.Application.Reason)
			}
			if mode == "expired_candidate" {
				blocks++ // Independent live lease expiry must still fail closed.
			}
			if m.mutations != mutations || k.blocks != blocks {
				t.Fatal("old observation changed replacement routing or bypassed lease enforcement")
			}
		})
	}
}

func TestTargetObservationFenceFindsCurrentIndexAndRejectsOtherLifetime(t *testing.T) {
	e, _, _, _ := appFixture(t)
	activateApp(t, e)
	guard := e.journal.Targets[0]
	fence := e.targetObservationFence(guard)
	// Reordering alone must not leave the caller with a stale slice index.
	other := guard
	other.TargetID = "other"
	e.journal.Targets = []TargetGuard{other, guard}
	i, got, ok := fence.current(e)
	if !ok || i != 1 || got.TargetID != "app" {
		t.Fatal("target index was not reacquired")
	}
	if _, _, ok := fence.current(&Engine{journal: e.journal}); ok {
		t.Fatal("fence escaped its Engine lifetime")
	}
	e.Close()
	if _, _, ok := fence.current(e); ok {
		t.Fatal("closed Engine retained target authority")
	}
}

func TestTargetRevisionSaturationDoesNotPreventSafetyQuarantine(t *testing.T) {
	for _, mode := range []string{"active", "guarded", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			e, m, _, _ := appFixture(t)
			s := activateApp(t, e)
			if mode == "guarded" {
				if _, err := e.quarantineTarget(context.Background(), "app"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "rollback" {
				e.journal.Targets[0].RouteRevision = ^uint64(0) - 1
				s.RecordApplied("p1", time.Now())
				m.mutations, m.failAt, m.mode = 0, 1, "after"
				out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
				if err == nil || out.Application.State != "rolled_back" || e.journal.Targets[0].RouteRevision != ^uint64(0) {
					t.Fatal("saturation lost bounded rollback", err)
				}
				m.failAt = 0
			} else {
				e.journal.Targets[0].RouteRevision = ^uint64(0)
			}
			calls := 0
			e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
				calls++
				return targetProof{}, nil
			}
			out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
			if !errors.Is(err, ErrRecovery) || calls != 0 || out.Applied || out.Application.Activated || !out.Application.Guarded || e.journal.Targets[0].Phase != "guarded" || e.journal.Targets[0].RouteRevision != ^uint64(0) {
				t.Fatal("saturation prevented quarantine or authorized new work", err)
			}
		})
	}
}

// A discarded report must not seed confirmation history or reset applied dwell.
func TestTargetObservationDiscardPreservesSelectorState(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		name := "confirmation"
		if confirmed {
			name = "applied_dwell"
		}
		t.Run(name, func(t *testing.T) {
			e, _, _, _ := appFixture(t)
			activateApp(t, e)
			p := relayselect.DefaultPolicy()
			p.Mode, p.ManualPin = "manual", "p0"
			s, err := relayselect.New(p)
			if err != nil {
				t.Fatal(err)
			}
			if confirmed {
				for i := 0; i < 2; i++ {
					out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
					if i == 1 && (err != nil || !out.Applied) {
						t.Fatal("manual baseline", err)
					}
				}
			}
			anchor := time.Now().Add(-time.Second)
			s.RecordApplied("p0", anchor)
			e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
				e.journal.Targets[0].RouteRevision++
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			}
			if _, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second); !errors.Is(err, ErrConflict) {
				t.Fatal("changed target accepted", err)
			}
			appProbes(e)
			out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
			if confirmed {
				if err != nil || !out.Applied || out.Selection.Changed || !out.Selection.ChangedAt.Equal(anchor) {
					t.Fatal("discarded observation reset applied path or dwell", err)
				}
				return
			}
			if err == nil || out.Applied || out.Selection.Reason != "manual_pin_unavailable" || out.Selection.PreviousPathID != "p0" {
				t.Fatal("discarded observation advanced selection", err)
			}
			found := false
			for _, candidate := range out.Selection.Candidates {
				if candidate.PathID == "p0" {
					found = true
					if candidate.ConsecutiveSuccesses != 1 || candidate.Eligible {
						t.Fatal("discarded observation counted toward confirmation")
					}
				}
			}
			if !found {
				t.Fatal("missing pinned candidate")
			}
		})
	}
}
