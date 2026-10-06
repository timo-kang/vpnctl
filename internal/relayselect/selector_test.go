// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayselect

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/relayobserve"
)

type scenario struct {
	s          *Selector
	at         time.Time
	boot       time.Duration
	generation uint64
	until      time.Time
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	policy := DefaultPolicy()
	policy.MinimumDwell = 10 * time.Second
	policy.HoldDown = 5 * time.Second
	s, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	f := &scenario{s: s, at: time.Now().UTC(), boot: time.Hour, generation: 1}
	f.until = f.at.Add(time.Hour)
	s.now = func() time.Time { return f.at }
	s.boot = func() (time.Duration, error) { return f.boot, nil }
	return f
}
func (f *scenario) report(states ...string) relayobserve.TargetReport {
	f.at = f.at.Add(time.Second)
	f.boot += time.Second
	r := relayobserve.TargetReport{SchemaVersion: 1, ControllerID: "controller", NodeID: "robot", Generation: f.generation, TargetID: "app", StartedAt: f.at.Add(-100 * time.Millisecond), ObservedAt: f.at, BootTime: f.boot, ApprovalUntil: f.until, Valid: true}
	for i, state := range states {
		r.Paths = append(r.Paths, relayobserve.TargetObservation{PathID: fmt.Sprintf("p%d", i), RelayID: fmt.Sprintf("r%d", i/2), UnderlayID: fmt.Sprintf("u%d", i%2), Priority: i, Cost: i, Fingerprint: strings.Repeat(fmt.Sprint(i), 64), State: state, Reason: state, ObservedAt: f.at.Add(-50 * time.Millisecond), ConnectTime: time.Millisecond, Handshake: 1, RXDelta: 100, TXDelta: 100})
	}
	return r
}
func (f *scenario) step(states ...string) Decision { return f.s.Decide(f.report(states...)) }
func wantPath(t *testing.T, d Decision, path string) {
	t.Helper()
	if d.DesiredPathID != path || d.Applied {
		t.Fatalf("want %q, got %+v", path, d)
	}
}
func TestFailoverDwellAndContinuousRecovery(t *testing.T) {
	f := newScenario(t)
	wantPath(t, f.step("reachable", "reachable"), "")
	wantPath(t, f.step("reachable", "reachable"), "p0")
	d := f.step("unreachable", "reachable")
	wantPath(t, d, "p1")
	if d.Reason != "selected_path_unavailable" || d.PreviousPathID != "p0" || !d.Changed {
		t.Fatal(d)
	}
	for i := 0; i < 7; i++ {
		wantPath(t, f.step("reachable", "reachable"), "p1")
	}
	wantPath(t, f.step("unreachable", "reachable"), "p1") // flapping restarts hold-down
	for i := 0; i < 5; i++ {
		wantPath(t, f.step("reachable", "reachable"), "p1")
	}
	d = f.step("reachable", "reachable")
	wantPath(t, d, "p0")
	if d.Reason != "preferred_path_recovered" {
		t.Fatal(d)
	}
	// Loss overrides dwell immediately; all failed does not claim physical no-uplink.
	d = f.step("unreachable", "unreachable")
	wantPath(t, d, "")
	if d.State != "no_verified_path" {
		t.Fatal(d)
	}
	wantPath(t, f.step("unknown", "unreachable"), "")
}
func TestManualCostDrainAndFreshEvidence(t *testing.T) {
	for _, mode := range []string{"manual", "cost", "drain", "fingerprint", "generation", "stale", "gap"} {
		t.Run(mode, func(t *testing.T) {
			f := newScenario(t)
			if mode == "manual" {
				f.s.policy.Mode = "manual"
				f.s.policy.ManualPin = "p0"
			}
			if mode == "cost" {
				f.s.policy.MaxCost = 0
			}
			f.step("reachable", "reachable")
			wantPath(t, f.step("reachable", "reachable"), "p0")
			r := f.report("reachable", "reachable")
			switch mode {
			case "manual", "cost":
				r.Paths[0].State = "unreachable"
			case "drain":
				r.Paths[0].State = "excluded"
				r.Paths[0].Reason = "draining"
			case "fingerprint":
				r.Paths[0].Fingerprint = strings.Repeat("a", 64)
			case "generation":
				r.Generation++
			case "stale":
				r.Paths[0].ObservedAt = r.StartedAt.Add(-time.Second)
			case "gap":
				f.at = f.at.Add(11 * time.Second)
				f.boot += 11 * time.Second
				r = f.report("reachable", "reachable")
			}
			d := f.s.Decide(r)
			expected := "p1"
			if mode == "manual" || mode == "cost" || mode == "generation" || mode == "gap" {
				expected = ""
			}
			wantPath(t, d, expected)
		})
	}
}
func TestApprovalClockReplayAndMalformedEvidence(t *testing.T) {
	for _, mode := range []string{"expired", "suspend-rollback", "wall-rollback", "generation-regression", "identity", "same-generation-expiry", "replay", "duplicate", "zero-counter", "zero-handshake", "missing-fingerprint", "future", "batch-expired", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newScenario(t)
			f.generation = 2
			f.step("reachable", "reachable")
			wantPath(t, f.step("reachable", "reachable"), "p0")
			r := f.report("reachable", "reachable")
			switch mode {
			case "expired":
				f.at = f.until
				f.boot += time.Hour
				r = f.report("reachable", "reachable")
			case "suspend-rollback":
				f.boot += 2 * time.Hour
				r.BootTime = f.boot
			case "wall-rollback":
				f.at = f.at.Add(-time.Minute)
			case "generation-regression":
				r.Generation = 1
			case "identity":
				r.ControllerID = "imposter"
			case "same-generation-expiry":
				r.ApprovalUntil = r.ApprovalUntil.Add(time.Hour)
			case "replay":
				r.StartedAt = f.s.lastBatch
			case "duplicate":
				r.Paths[1].PathID = r.Paths[0].PathID
			case "zero-counter":
				r.Paths[0].RXDelta = 0
			case "zero-handshake":
				r.Paths[0].Handshake = 0
			case "missing-fingerprint":
				r.Paths[0].Fingerprint = ""
			case "future":
				r.ObservedAt = f.at.Add(time.Second)
			case "batch-expired":
				f.at = f.at.Add(time.Minute)
				f.boot += time.Minute
			case "unavailable":
				r.Valid = false
			}
			d := f.s.Decide(r)
			wantPath(t, d, "")
			if d.State != "blocked" {
				t.Fatal(d)
			}
			if mode == "suspend-rollback" {
				// Repeated observations of the same grant cannot replenish BOOTTIME.
				for i := 0; i < 3; i++ {
					d = f.step("reachable", "reachable")
					wantPath(t, d, "")
					if d.Reason != "approval_expired" {
						t.Fatal(d)
					}
				}
				f.generation++
				f.until = f.at.Add(time.Hour)
				f.step("reachable", "reachable")
				wantPath(t, f.step("reachable", "reachable"), "p0")
			}
		})
	}
}
func TestSelectionBoundedWindowVariableFleetAndRepeatedFailures(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			for node := 0; node < size; node++ {
				f := newScenario(t)
				for iteration := 0; iteration < 100; iteration++ {
					states := []string{"reachable", "reachable", "reachable", "reachable", "reachable", "reachable", "reachable", "reachable"}
					if iteration%3 == 0 {
						states[0] = "unreachable"
					}
					d := f.step(states...)
					for _, c := range d.Candidates {
						if c.Samples > 16 || c.Failures > c.Samples || c.FailureFraction < 0 || c.FailureFraction > 1 {
							t.Fatal(c)
						}
					}
					if len(f.s.histories) > 8 {
						t.Fatal("unbounded history")
					}
					if iteration > 2 && d.DesiredPathID != "p1" {
						t.Fatal("flapping preferred path displaced stable alternate", d)
					}
				}
			}
		})
	}
}

func TestWithdrawalExplicitlyClearsSerializedDesiredPath(t *testing.T) {
	f := newScenario(t)
	f.step("reachable", "reachable")
	prior := f.step("reachable", "reachable")
	withdrawn := f.step("unreachable", "unreachable")
	b, err := json.Marshal(withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"desired_path_id":""`) {
		t.Fatal("withdrawal omitted desired path", string(b))
	}
	if err = json.Unmarshal(b, &prior); err != nil || prior.DesiredPathID != "" {
		t.Fatal("previous desired path survived withdrawal", prior, err)
	}
}

func TestGenerationWithdrawalReportsActualChangeTime(t *testing.T) {
	f := newScenario(t)
	f.step("reachable")
	selected := f.step("reachable")
	wantPath(t, selected, "p0")
	f.generation++
	withdrawn := f.step("reachable")
	wantPath(t, withdrawn, "")
	if !withdrawn.Changed || withdrawn.PreviousPathID != "p0" || !withdrawn.ChangedAt.Equal(f.at) || !withdrawn.ChangedAt.After(selected.ChangedAt) {
		t.Fatal("generation withdrawal retained the old selection timestamp", withdrawn)
	}
	stillUnknown := f.step("unknown")
	if stillUnknown.Changed || !stillUnknown.ChangedAt.Equal(withdrawn.ChangedAt) {
		t.Fatal("unchanged withdrawal moved its timestamp", stillUnknown)
	}
	wantPath(t, f.step("reachable"), "")
	recovered := f.step("reachable")
	wantPath(t, recovered, "p0")
	if !recovered.Changed || !recovered.ChangedAt.Equal(f.at) {
		t.Fatal("freshly confirmed selection did not record its change time", recovered)
	}
}

func TestRankingUsesPriorityThenCostAndDeterministicTie(t *testing.T) {
	for _, mode := range []string{"priority", "cost", "tie"} {
		t.Run(mode, func(t *testing.T) {
			f := newScenario(t)
			var d Decision
			for i := 0; i < 2; i++ {
				r := f.report("reachable", "reachable")
				r.Paths[0].Cost = 100
				r.Paths[1].Cost = 1
				if mode != "priority" {
					r.Paths[1].Priority = 0
				}
				if mode == "tie" {
					r.Paths[0].Cost = 1
					r.Paths[1].ConnectTime = time.Microsecond
				}
				d = f.s.Decide(r)
			}
			expected := "p0"
			if mode == "cost" {
				expected = "p1"
			}
			wantPath(t, d, expected)
		})
	}
}

func TestRecordAppliedAnchorsRealDwellWithoutGrantingHealth(t *testing.T) {
	f := newScenario(t)
	f.step("reachable", "reachable")
	wantPath(t, f.step("reachable", "reachable"), "p0")
	// A failed switch restored p1 later than the recommendation timestamp.
	at := f.at
	f.s.RecordApplied("p1", at)
	for i := 0; i < 9; i++ {
		d := f.step("reachable", "reachable")
		wantPath(t, d, "p1")
		if d.Reason != "minimum_dwell" {
			t.Fatal(d)
		}
	}
	wantPath(t, f.step("reachable", "reachable"), "p0")
	f.s.RecordApplied("p1", f.at)
	wantPath(t, f.step("reachable", "unknown"), "p0") // applied history cannot authorize a failed path
}

func TestObservationBudgetIsDiagnosticNotAuthority(t *testing.T) {
	f := newScenario(t)
	f.step("reachable", "reachable")
	wantPath(t, f.step("reachable", "reachable"), "p0")
	r := f.report("unknown", "unknown")
	r.Reason = "observation_budget_exhausted"
	d := f.s.Decide(r)
	wantPath(t, d, "")
	if d.State != "unknown" || d.Reason != r.Reason {
		t.Fatal(d)
	}
	// A partial wave can use only newly confirmed healthy evidence, never the
	// remembered former path or accounting fields as a substitute for proof.
	for i := 0; i < 2; i++ {
		r = f.report("unknown", "reachable")
		r.Reason = "observation_budget_exhausted"
		d = f.s.Decide(r)
		want := ""
		if i == 1 {
			want = "p1"
		}
		wantPath(t, d, want)
	}
}
