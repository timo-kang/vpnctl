// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayselect"
)

func appFixture(t *testing.T) (*Engine, *targetMachine, *fakeNodeLease, string) {
	t.Helper()
	e, k, dir := nodeLeaseFixture(t)
	m := &targetMachine{routes: []object{}, rules: []object{}}
	e.targets = targetKernel{kernel{run: m.run}}
	for _, path := range []string{"p0", "p1", "p2"} {
		if _, err := e.PrepareApplication(context.Background(), path, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.MaintainLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReserveTarget(context.Background(), "app", ""); err != nil {
		t.Fatal(err)
	}
	appProbes(e)
	return e, m, k, dir
}
func appProbes(e *Engine) {
	e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		return targetProof{handshake: 1, rx: 1, tx: 1}, nil
	}
	e.appProbe = func(_ context.Context, _ TargetGuard, entry Entry, _ relaycatalog.Target) (ApplicationProof, error) {
		r := routeForEntry(entry)
		return ApplicationProof{Evidence: "test_tcp", Interface: r.Interface, Source: r.Source, ObservedAt: time.Now()}, nil
	}
}
func appSelector(t *testing.T) *relayselect.Selector {
	t.Helper()
	s, err := relayselect.New(relayselect.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func activateApp(t *testing.T, e *Engine) *relayselect.Selector {
	t.Helper()
	s := appSelector(t)
	for i := 0; i < 2; i++ {
		out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
		if i == 0 && (err == nil || out.Applied || !out.Application.Guarded) {
			t.Fatal("missing confirmation", out, err)
		}
		if i == 1 && (err != nil || !out.Applied || !out.Application.Activated) {
			t.Fatal("application unavailable", out, err)
		}
	}
	return s
}
func TestTargetApplicationOwnsRoutesAndColdRestart(t *testing.T) {
	e, m, _, dir := appFixture(t)
	s := activateApp(t, e)
	before := m.mutations
	if out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second); err != nil || !out.Applied || before != m.mutations {
		t.Fatal("steady state rewrote routes", out, err)
	}
	e = reopenTarget(t, e, m, dir)
	appProbes(e)
	if out, err := e.RecoverTarget(context.Background(), "app"); err != nil || !out.Activated || out.Proof == nil {
		t.Fatal(out, err)
	}
	activateApp(t, e) // New selector confirms again, without replaying journal health.
	if _, err := e.Release(context.Background(), "p0"); err != nil {
		t.Fatal(err)
	}
	if out, err := e.InspectTarget(context.Background(), "app"); err != nil || !out.Guarded || out.Activated || len(m.routes) != 1 {
		t.Fatal("candidate deletion opened fallback", out, err)
	}
}
func TestTargetApplicationSwitchFailureRollbackAndCrash(t *testing.T) {
	for _, mode := range []string{"before", "after", "crash"} {
		for point := 1; point <= 2; point++ {
			t.Run(fmt.Sprintf("%s/%d", mode, point), func(t *testing.T) {
				e, m, k, dir := appFixture(t)
				s := activateApp(t, e)
				// Both candidates are verified; exercise a decision for the alternate.
				s.RecordApplied("p1", time.Now())
				m.mutations, m.failAt, m.mode = 0, point, mode
				func() {
					defer func() {
						r := recover()
						if mode == "crash" && r == nil {
							t.Error("crash not exercised")
						}
						if mode != "crash" && r != nil {
							panic(r)
						}
					}()
					out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
					if err == nil || out.Applied || !out.Application.Activated || out.Application.State != "rolled_back" || out.Application.Reservation.Active.PathID != "p0" {
						t.Fatal("lost valid rollback", out, err)
					}
				}()
				m.failAt = 0
				e = reopenTarget(t, e, m, dir)
				appProbes(e)
				if mode == "crash" {
					if _, err := e.MaintainLeases(context.Background()); err == nil || k.active["p0"] || k.active["p1"] || !k.active["p2"] {
						t.Fatal("pending switch renewed or starved unrelated candidate", err)
					}
				}
				out, err := e.RecoverTarget(context.Background(), "app")
				if err != nil || mode == "crash" && (!out.Guarded || out.Activated || len(m.routes) != 1) || mode != "crash" && !out.Activated {
					t.Fatal(out, err)
				}
			})
		}
	}
}
func TestTargetApplicationPersistenceNeverClaimsSuccess(t *testing.T) {
	for point := 1; point <= 2; point++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%v", point, after), func(t *testing.T) {
				e, m, k, dir := appFixture(t)
				s := activateApp(t, e)
				s.RecordApplied("p1", time.Now())
				save, calls := e.save, 0
				e.save = func(b []byte) error {
					calls++
					if calls != point {
						return save(b)
					}
					if after {
						if err := save(b); err != nil {
							return err
						}
					}
					return errors.New("lost durable write acknowledgement")
				}
				out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
				if err == nil || out.Applied || out.Application.Activated || !e.uncertain || k.active["p1"] {
					t.Fatal("uncertain commit authorized traffic", out, err)
				}
				e = reopenTarget(t, e, m, dir)
				appProbes(e)
				// Active committed state still needs a live lease and fresh app proof.
				out2, err := e.RecoverTarget(context.Background(), "app")
				if out2.Activated && err != nil {
					t.Fatal("failed readback marked active")
				}
				if e.journal.Targets[0].Phase == "switching" || err == nil && !out2.Guarded && !out2.Activated {
					t.Fatal(out2, err)
				}
			})
		}
	}
}
func TestTargetApplicationRejectsUnprotectedAndRevoked(t *testing.T) {
	for _, fault := range []string{"legacy", "denied_after_app", "inventory_after_app", "unbound_failure"} {
		t.Run(fault, func(t *testing.T) {
			e, m, k, _ := appFixture(t)
			s := appSelector(t)
			if fault == "legacy" {
				for i := range e.journal.Entries {
					e.journal.Entries[i].LeaseVersion, e.journal.Entries[i].ApprovalBootNS, e.journal.Entries[i].ProbeScope = 0, 0, 0
				}
			} else {
				good := e.appProbe
				e.appProbe = func(ctx context.Context, g TargetGuard, entry Entry, target relaycatalog.Target) (ApplicationProof, error) {
					switch fault {
					case "denied_after_app":
						e.cache.Refresh(ctx, &rejectTargetApproval{})
					case "inventory_after_app":
						k.foreign = true
					case "unbound_failure":
						return ApplicationProof{}, errors.New("unbound source mismatch")
					}
					return good(ctx, g, entry, target)
				}
			}
			for i := 0; i < 2; i++ {
				out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
				if err == nil || out.Applied || out.Application.Activated {
					t.Fatal("unsafe candidate applied", out, err)
				}
			}
			if len(m.routes) != 1 {
				t.Fatal("failed application left open target")
			}
		})
	}
}
func TestTargetApplicationForeignRoutesPreserved(t *testing.T) {
	e, m, _, _ := appFixture(t)
	s := activateApp(t, e)
	g := e.journal.Targets[0]
	m.routes = append(m.routes, object{"table": g.Table, "dst": "203.0.113.1/32", "protocol": 99, "dev": "foreign0"})
	before, _ := json.Marshal(m.routes)
	out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
	if err == nil || out.Applied || out.Application.Activated || out.Application.Guarded {
		t.Fatal("foreign route adopted", out, err)
	}
	after, _ := json.Marshal(m.routes)
	if string(before) != string(after) {
		t.Fatal("foreign state deleted")
	}
}
func TestTargetApplicationEightPrefixInterruption(t *testing.T) {
	for point := 1; point <= 16; point++ {
		for _, mode := range []string{"before", "after", "crash"} {
			t.Run(fmt.Sprintf("%d/%s", point, mode), func(t *testing.T) {
				e, m, _, dir := appFixture(t)
				if _, err := e.ReleaseTarget(context.Background(), "app"); err != nil {
					t.Fatal(err)
				}
				g := TargetGuard{Controller: e.journal.Entries[0].Controller, Node: "robot", Generation: 1, TargetID: "app", Phase: "reserving"}
				g.Owner, g.Metric, _, _ = token()
				g.Table, g.Priority = targetSlots(g.Controller, g.Node, g.TargetID)
				for i := 0; i < 8; i++ {
					g.Prefixes = append(g.Prefixes, fmt.Sprintf("198.18.%d.2/32", i))
				}
				e.journal.Targets = []TargetGuard{g}
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
				if _, err := e.RecoverTarget(context.Background(), "app"); err != nil {
					t.Fatal(err)
				}
				g = e.journal.Targets[0]
				g.ApplicationVersion = 1
				g.Active, g.Pending, g.Phase = routeForEntry(e.journal.Entries[0]), routeForEntry(e.journal.Entries[1]), "switching"
				b := e.targets.(targetApplicationBackend)
				if err := b.SetRoutes(context.Background(), g, e.journal.Entries, g.Active); err != nil {
					t.Fatal(err)
				}
				e.journal.Targets[0] = g
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
				m.mutations, m.failAt, m.mode = 0, point, mode
				func() {
					defer func() {
						if mode == "crash" && recover() == nil {
							t.Error("crash missing")
						}
					}()
					if err := b.SetRoutes(context.Background(), g, e.journal.Entries, g.Pending); err == nil {
						t.Error("fault missing")
					}
				}()
				m.failAt = 0
				e = reopenTarget(t, e, m, dir)
				if out, err := e.RecoverTarget(context.Background(), "app"); err != nil || !out.Guarded || out.Activated || len(m.routes) != 1 || len(m.rules) != 8 {
					t.Fatal("partial switch escaped quarantine", out, err)
				}
			})
		}
	}
}

func TestTargetApplicationLegacyProbeFence(t *testing.T) {
	e, m, _, _ := appFixture(t)
	// A single old source-only probe would let existing app sockets bypass guard.
	if _, err := e.Release(context.Background(), "p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.PrepareProtected(context.Background(), "p2", "", true); err != nil {
		t.Fatal(err)
	}
	s := appSelector(t)
	for i := 0; i < 2; i++ {
		out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
		if err == nil || out.Applied {
			t.Fatal("source bypass admitted", out, err)
		}
	}
	if len(m.routes) != 1 {
		t.Fatal("legacy probe opened app")
	}
	if _, err := e.Release(context.Background(), "p2"); err != nil {
		t.Fatal(err)
	}
	activateApp(t, e)
	if _, err := e.Release(context.Background(), "p0"); err != nil {
		t.Fatal(err)
	}
	if e.journal.Targets[0].ApplicationVersion != 1 {
		t.Fatal("lost application fence")
	}
	if _, err := e.PrepareProtected(context.Background(), "p0", "", true); err == nil {
		t.Fatal("legacy probe reopened quarantined app")
	}
	if _, err := e.PrepareApplication(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
}

func TestTargetApplicationProbeRuleScope(t *testing.T) {
	e, _, _, _ := appFixture(t)
	entry := e.journal.Entries[0]
	o := object{"priority": decimal(probePriority(entry)), "src": entry.Candidate.InnerAddress, "table": decimal(entry.Candidate.Pin.Table), "protocol": "186", "oif": entry.Candidate.Pin.WGInterface}
	if !probeRuleMatches(o, entry) {
		t.Fatal("scoped rule rejected")
	}
	delete(o, "oif")
	if probeRuleMatches(o, entry) {
		t.Fatal("source-only rule adopted")
	}
	k := kernel{run: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		return []byte("2\n"), nil
	}}
	if k.checkProbeEnvironment(context.Background(), entry, true) == nil {
		t.Fatal("rp_filter accepted")
	}
	k.run = func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		return []byte("0\n"), nil
	}
	if err := k.checkProbeEnvironment(context.Background(), entry, false); err != nil {
		t.Fatal(err)
	}
}

func TestTargetApplicationStaleChoiceAndPolicyRollback(t *testing.T) {
	for _, fault := range []string{"expired", "fingerprint", "generation", "manual_rollback"} {
		t.Run(fault, func(t *testing.T) {
			e, m, _, _ := appFixture(t)
			s := activateApp(t, e)
			report, err := e.ObserveTarget(context.Background(), "app", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			d := s.Decide(report)
			g := e.journal.Targets[0]
			before := m.mutations
			switch fault {
			case "expired":
				d.ValidUntil = time.Now().Add(-time.Second)
			case "generation":
				d.Generation++
			case "fingerprint":
				for i := range d.Candidates {
					d.Candidates[i].Fingerprint = "stale"
				}
			case "manual_rollback":
				for i := range d.Candidates {
					d.Candidates[i].Eligible = d.Candidates[i].PathID == "p1"
				}
				g.Phase, g.Pending = "switching", routeForEntry(e.journal.Entries[1])
				e.journal.Targets[0] = g
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
				out, err := e.rollbackTarget(context.Background(), g, d, time.Second, errors.New("switch failed"))
				if err == nil || out.Activated || !out.Guarded || len(m.routes) != 1 {
					t.Fatal("policy-excluded LKG revived", out, err)
				}
				return
			}
			if _, err := e.applyTarget(context.Background(), g, g.Active, d, time.Second); err == nil || m.mutations != before {
				t.Fatal("stale choice mutated kernel", err)
			}
		})
	}
}

// A steady target must not repeat the full sweep after its bounded wave, and
// must still reject a lease expiring between observation and route application.
func TestTargetApplicationOneSweepAndApplyTimeLeaseExpiry(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(fmt.Sprint(expire), func(t *testing.T) {
			e, _, k, _ := appFixture(t)
			s := activateApp(t, e)
			before := k.renewals
			var proofs atomic.Int32
			e.probe = func(_ context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
				if proofs.Add(1) == 4 && expire {
					k.active[entry.Candidate.PathID] = false
				}
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			}
			out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
			if k.renewals-before != 3 || out.Diagnostics.Phases["maintenance"].Calls != 1 {
				t.Fatal("repeated full sweep", k.renewals-before, out.Diagnostics)
			}
			if expire {
				if err == nil || out.Applied || out.Application.Activated || !out.Application.Guarded {
					t.Fatal("expired apply-time lease authorized route", out, err)
				}
			} else if err != nil || !out.Applied {
				t.Fatal(out, err)
			}
		})
	}
}

func TestTargetChoiceFreshPrecheckBeforeProbe(t *testing.T) {
	for _, fault := range []string{"expired_lease", "kernel_changed", "revoked"} {
		t.Run(fault, func(t *testing.T) {
			e, _, k, _ := appFixture(t)
			s := activateApp(t, e)
			report, err := e.ObserveTarget(context.Background(), "app", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			d := s.Decide(report)
			if d.DesiredPathID == "" {
				t.Fatal("missing baseline choice")
			}
			g := e.journal.Targets[0]
			entry := e.journal.Entries[e.index(d.DesiredPathID)]
			switch fault {
			case "expired_lease":
				k.active[d.DesiredPathID] = false
			case "kernel_changed":
				k.foreign = true
			case "revoked":
				e.cache.Refresh(context.Background(), &rejectTargetApproval{})
			}
			probed := false
			e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
				probed = true
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			}
			if _, err := e.verifyTargetChoice(context.Background(), g, routeForEntry(entry), d, time.Second); err == nil || probed {
				t.Fatal("fresh precheck omitted before TCP", err, probed)
			}
		})
	}
}
