// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayselect"
)

type observationScheduleBackend struct {
	*fakeNodeLease
	mu                        sync.Mutex
	calls                     map[string]int
	started                   time.Time
	preCost, postCost         time.Duration
	lateStarted, lateFinished time.Duration
	checking, probes          atomic.Int32
	failPost                  string
	blockPre                  string
	blockPost                 string
	blockTCP                  bool
	preCosts, postCosts       map[string]time.Duration
	healthyPath               string
	healthyDuration           time.Duration
	provisionalSuccess        bool
	failedPosts               map[string]bool
	stageEntered              chan string
	probeEntered              chan string
}

func observationScheduleWait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (k *observationScheduleBackend) Check(ctx context.Context, entry Entry, available bool) (bool, error) {
	id := entry.Candidate.PathID
	k.mu.Lock()
	k.calls[id]++
	call := k.calls[id]
	k.mu.Unlock()
	// One synchronous maintenance check precedes each candidate's pre/post
	// checks. Only the latter incur the controlled wave costs.
	var cost time.Duration
	if call == 2 {
		cost = k.preCost
	}
	if call == 3 {
		cost = k.postCost
	}
	if override, ok := k.preCosts[id]; call == 2 && ok {
		cost = override
	}
	if override, ok := k.postCosts[id]; call == 3 && ok {
		cost = override
	}
	if k.checking.Add(1) != 1 {
		panic("ownership checks overlapped")
	}
	defer k.checking.Add(-1)
	if call >= 2 && k.stageEntered != nil {
		k.stageEntered <- fmt.Sprintf("%d/%s", call, id)
	}
	if call == 2 && id == k.blockPre || call == 3 && id == k.blockPost {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if err := observationScheduleWait(ctx, cost); err != nil {
		return false, err
	}
	if call == 3 && (id == k.failPost || k.failedPosts[id]) {
		return false, ErrConflict
	}
	return k.fakeNodeLease.Check(ctx, entry, available)
}

func (k *observationScheduleBackend) probe(ctx context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
	k.probes.Add(1)
	defer k.probes.Add(-1)
	id := entry.Candidate.PathID
	if k.probeEntered != nil {
		k.probeEntered <- id
	}
	if k.blockTCP {
		<-ctx.Done()
		return targetProof{}, ctx.Err()
	}
	healthy := k.healthyPath
	if healthy == "" {
		healthy = "p7"
	}
	duration := 10 * time.Millisecond
	if id == healthy {
		duration = k.healthyDuration
		if duration == 0 {
			duration = 900 * time.Millisecond
		}
		k.mu.Lock()
		k.lateStarted = time.Since(k.started)
		k.mu.Unlock()
	}
	if err := observationScheduleWait(ctx, duration); err != nil {
		return targetProof{}, err
	}
	if id != healthy && !k.provisionalSuccess {
		return targetProof{}, &targetConnectError{reason: "target_connect_failed"}
	}
	if id == healthy {
		k.mu.Lock()
		k.lateFinished = time.Since(k.started)
		k.mu.Unlock()
	}
	return targetProof{duration: duration, handshake: 1, rx: 96, tx: 192}, nil
}

// The total work fits the unchanged three-second wave: eight 180ms prechecks
// launch the last 900ms TCP at 1.44s; seven 160ms postchecks overlap that TCP and
// the last 160ms postcheck finishes at 2.72s. Every failed early TCP still needs
// its full attribution postcheck. If those postchecks displace queued prechecks,
// the healthy final TCP starts at 2.40s and expires before it can finish.
// synctest makes all waits deterministic; no socket or host clock is changed.
func TestSlowEarlyPostchecksDoNotStarveHealthyLateCandidate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, base := waveFixture(t)
		selector, err := relayselect.New(relayselect.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		for wave := 0; wave < 2; wave++ {
			// Distinct reports must start strictly after the preceding report
			// completed. synctest does not advance time for synchronous work.
			if wave > 0 {
				time.Sleep(time.Millisecond)
			}
			k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, preCost: 180 * time.Millisecond, postCost: 160 * time.Millisecond, started: time.Now()}
			e.backend = k
			report, err := e.observeTarget(context.Background(), "app", "", selector.MaxConnectTime(), k.probe)
			if err != nil || !report.Valid || k.checking.Load() != 0 || k.probes.Load() != 0 {
				t.Fatalf("wave did not join its bounded work: valid=%v err=%v checks=%d probes=%d", report.Valid, err, k.checking.Load(), k.probes.Load())
			}
			var late TargetObservation
			for _, candidate := range report.Paths {
				if candidate.PathID == "p7" {
					late = candidate
				}
			}
			if late.State != "reachable" || report.Reason != "" {
				t.Fatalf("healthy 900ms TCP starved: wave=%s reason=%s late=%s/%s tcp_started=%s tcp_finished=%s", time.Since(k.started), report.Reason, late.State, late.Reason, k.lateStarted, k.lateFinished)
			}
			if time.Since(k.started) >= targetObservationWaveDuration || late.ConnectTime != 900*time.Millisecond {
				t.Fatal("wave or connect limit changed", time.Since(k.started), late.ConnectTime)
			}
			for i := 0; i < 8; i++ {
				if k.calls[fmt.Sprint("p", i)] != 3 {
					t.Fatal("maintenance or proof-boundary check omitted", k.calls)
				}
			}
			decision := selector.Decide(report)
			if wave == 0 && decision.DesiredPathID != "" {
				t.Fatal("single proof bypassed selector confirmation")
			}
			if wave == 1 && decision.DesiredPathID != "p7" {
				t.Fatal("unchanged selector rejected two fresh healthy proofs", decision.Reason)
			}
		}
	})
}

func TestLateCandidateStillNeedsSuccessfulPostcheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, base := waveFixture(t)
		k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, preCost: time.Millisecond, postCost: time.Millisecond, started: time.Now(), failPost: "p7"}
		e.backend = k
		report, err := e.observeTarget(context.Background(), "app", "", time.Second, k.probe)
		if err != nil || !report.Valid {
			t.Fatal("bounded safety control failed", err)
		}
		for _, candidate := range report.Paths {
			if candidate.PathID == "p7" && (candidate.State != "unknown" || candidate.Reason != "kernel_changed_during_probe" || k.calls["p7"] != 3) {
				t.Fatal("TCP success overrode failed postproof ownership", candidate.State, candidate.Reason, k.calls["p7"])
			}
		}
		if k.probes.Load() != 0 || k.checking.Load() != 0 {
			t.Fatal("safety control leaked a worker")
		}
	})
}

// Prioritizing every precheck until the last one finishes is not sufficient:
// an independent late ownership read may consume the rest of the wave. An
// already verified early TCP must get its postcheck before that unrelated
// stalled read. This preserves the current fault-isolation contract without
// declaring an unchecked or stale proof healthy.
func TestBlockedLatePrecheckPreservesEarlierVerifiedCandidate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, base := waveFixture(t)
		k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, preCost: 180 * time.Millisecond, postCost: 160 * time.Millisecond, started: time.Now(), blockPre: "p7"}
		e.backend = k
		report, err := e.observeTarget(context.Background(), "app", "", time.Second, func(ctx context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
			k.probes.Add(1)
			defer k.probes.Add(-1)
			if err := observationScheduleWait(ctx, 10*time.Millisecond); err != nil {
				return targetProof{}, err
			}
			if entry.Candidate.PathID != "p0" {
				return targetProof{}, &targetConnectError{reason: "target_connect_failed"}
			}
			return targetProof{duration: 10 * time.Millisecond, handshake: 1, rx: 96, tx: 192}, nil
		})
		if err != nil || !report.Valid || report.Reason != "observation_budget_exhausted" || time.Since(k.started) != targetObservationWaveDuration {
			t.Fatal("blocked precheck escaped the existing shared deadline", report.Valid, report.Reason, err, time.Since(k.started))
		}
		for _, candidate := range report.Paths {
			if candidate.PathID == "p0" && (candidate.State != "reachable" || k.calls["p0"] != 3) {
				t.Fatalf("independent stalled precheck starved early postproof verification: early=%s/%s checks=%d", candidate.State, candidate.Reason, k.calls["p0"])
			}
			if candidate.PathID == "p7" && candidate.State != "unknown" {
				t.Fatal("unverified late candidate acquired health")
			}
		}
		if k.probes.Load() != 0 || k.checking.Load() != 0 {
			t.Fatal("deadline retained live workers")
		}
	})
}

// These are finite outcome contracts, not a mandated pre/post call order.
// Each uniform-cost case has a feasible 3s schedule even when the only true
// healthy path is last. The slow-position controls have enough slack even if
// all TCP/check time is added serially. No claim is made that an online gate
// can predict arbitrary blocking calls or always find an offline-optimal plan.
type observationScheduleCase struct {
	healthy           string
	pre, post         time.Duration
	slowPre, slowPost string
	provisional       bool
}

func runObservationScheduleCase(t *testing.T, settings observationScheduleCase) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		e, base := waveFixture(t)
		selector, err := relayselect.New(relayselect.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		for wave := 0; wave < 2; wave++ {
			// Distinct reports must start strictly after the preceding report
			// completed. synctest does not advance time for synchronous work.
			if wave > 0 {
				time.Sleep(time.Millisecond)
			}
			k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, started: time.Now(), preCost: settings.pre, postCost: settings.post, healthyPath: settings.healthy, provisionalSuccess: settings.provisional, failedPosts: map[string]bool{}}
			if settings.slowPre != "" {
				k.preCosts = map[string]time.Duration{settings.slowPre: 500 * time.Millisecond}
			}
			if settings.slowPost != "" {
				k.postCosts = map[string]time.Duration{settings.slowPost: 500 * time.Millisecond}
			}
			if settings.provisional {
				for i := 0; i < 8; i++ {
					id := fmt.Sprint("p", i)
					k.failedPosts[id] = id != settings.healthy
				}
			}
			e.backend = k
			report, err := e.observeTarget(context.Background(), "app", "", selector.MaxConnectTime(), k.probe)
			if err != nil || !report.Valid || k.checking.Load() != 0 || k.probes.Load() != 0 || time.Since(k.started) > targetObservationWaveDuration {
				t.Fatalf("bounded engine did not join safely: valid=%v err=%v elapsed=%s checks=%d probes=%d", report.Valid, err, time.Since(k.started), k.checking.Load(), k.probes.Load())
			}
			decision := selector.Decide(report)
			var healthy TargetObservation
			for _, candidate := range report.Paths {
				if candidate.PathID == settings.healthy {
					healthy = candidate
					continue
				}
				if candidate.State == "reachable" {
					t.Errorf("nonhealthy provisional TCP became trusted without ownership: %s", candidate.PathID)
				}
				if settings.provisional && k.calls[candidate.PathID] == 3 && candidate.Reason != "kernel_changed_during_probe" {
					t.Errorf("post-ownership rejection lost for %s: %s/%s", candidate.PathID, candidate.State, candidate.Reason)
				}
			}
			t.Logf("wave=%d healthy=%s state=%s reason=%s tcp_start=%s tcp_end=%s elapsed=%s selected=%s", wave, settings.healthy, healthy.State, healthy.Reason, k.lateStarted, k.lateFinished, time.Since(k.started), decision.DesiredPathID)
			if healthy.State != "reachable" || healthy.ConnectTime != 900*time.Millisecond || report.Reason != "" {
				t.Errorf("finite workload starved unique healthy path: %s/%s report=%s", healthy.State, healthy.Reason, report.Reason)
			}
			for i := 0; i < 8; i++ {
				if k.calls[fmt.Sprint("p", i)] != 3 {
					t.Errorf("proof-boundary work incomplete: p%d checks=%d", i, k.calls[fmt.Sprint("p", i)])
				}
			}
			if wave == 0 && decision.DesiredPathID != "" {
				t.Error("selector accepted only one proof")
			}
			if wave == 1 && decision.DesiredPathID != settings.healthy {
				t.Errorf("unchanged selector lacked two fresh healthy proofs: %s", decision.Reason)
			}
		}
	})
}

func TestObservationScheduleUniqueHealthyPosition(t *testing.T) {
	for _, provisional := range []bool{false, true} {
		for healthy := 0; healthy < 8; healthy++ {
			t.Run(fmt.Sprintf("provisional_%t/healthy_%d", provisional, healthy), func(t *testing.T) {
				runObservationScheduleCase(t, observationScheduleCase{healthy: fmt.Sprint("p", healthy), pre: 180 * time.Millisecond, post: 160 * time.Millisecond, provisional: provisional})
			})
		}
	}
}

func TestObservationScheduleSlowCheckPositionsWithSlack(t *testing.T) {
	for _, phase := range []string{"pre", "post"} {
		for position := 0; position < 8; position++ {
			for healthy := 0; healthy < 8; healthy++ {
				t.Run(fmt.Sprintf("%s_%d/healthy_%d", phase, position, healthy), func(t *testing.T) {
					settings := observationScheduleCase{healthy: fmt.Sprint("p", healthy), pre: 25 * time.Millisecond, post: 25 * time.Millisecond, provisional: true}
					if phase == "pre" {
						settings.slowPre = fmt.Sprint("p", position)
					} else {
						settings.slowPost = fmt.Sprint("p", position)
					}
					runObservationScheduleCase(t, settings)
				})
			}
		}
	}

}

func TestObservationScheduleCancellationJoinsEveryPhase(t *testing.T) {
	for _, phase := range []string{"pre", "tcp", "post"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, base := waveFixture(t)
				k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, preCost: time.Millisecond, postCost: time.Millisecond, stageEntered: make(chan string, 16), probeEntered: make(chan string, 8), started: time.Now()}
				switch phase {
				case "pre":
					k.blockPre = "p0"
				case "tcp":
					k.blockTCP = true
				case "post":
					k.blockPost = "p0"
				}
				e.backend = k
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan targetOrderResult, 1)
				go func() {
					report, err := e.observeTarget(ctx, "app", "", time.Second, k.probe)
					done <- targetOrderResult{report, err}
				}()
				if phase == "tcp" {
					for i := 0; i < 8; i++ {
						<-k.probeEntered
					}
				} else {
					wanted := "2/p0"
					if phase == "post" {
						wanted = "3/p0"
					}
					for event := range k.stageEntered {
						if event == wanted {
							break
						}
					}
				}
				synctest.Wait()
				cancelled := time.Now()
				cancel()
				out := <-done
				if !errors.Is(out.err, context.Canceled) || out.report.Valid || k.checking.Load() != 0 || k.probes.Load() != 0 || time.Since(cancelled) != 0 {
					t.Fatalf("cancelled %s retained work/evidence: valid=%v err=%v checks=%d probes=%d join=%s", phase, out.report.Valid, out.err, k.checking.Load(), k.probes.Load(), time.Since(cancelled))
				}
			})
		})
	}
}

// Diagnostic controls separate pre-existing nonpreemptible-check limitations
// from desired scheduler behavior. Once a slow precheck owns the serial gate,
// TCP completion alone cannot make an earlier path eligible. Do not turn these
// observations into an impossible promise to preserve every healthy position.
func TestObservationScheduleBlockedPrecheckLimitations(t *testing.T) {
	for _, blocked := range []string{"p0", "p1", "p7"} {
		t.Run(blocked, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, base := waveFixture(t)
				k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, preCost: 180 * time.Millisecond, postCost: 160 * time.Millisecond, blockPre: blocked, healthyPath: "p0", healthyDuration: 10 * time.Millisecond, started: time.Now()}
				e.backend = k
				report, err := e.observeTarget(context.Background(), "app", "", time.Second, k.probe)
				if err != nil || !report.Valid || time.Since(k.started) != targetObservationWaveDuration || k.checking.Load() != 0 || k.probes.Load() != 0 {
					t.Fatal("blocked-check limit was weakened", report.Valid, err, time.Since(k.started))
				}
				for _, candidate := range report.Paths {
					if candidate.State == "reachable" && (candidate.PathID != "p0" || k.calls[candidate.PathID] != 3) {
						t.Fatal("missing postcheck or failed TCP was accepted")
					}
					if candidate.PathID == "p0" {
						t.Logf("blocked=%s healthy=%s/%s checks=%d", blocked, candidate.State, candidate.Reason, k.calls["p0"])
					}
				}
			})
		})
	}
}

// Confirmation still needs distinct fresh reports; advancing virtual time
// between waves must not make replaying the same proof acceptable.
func TestObservationScheduleSelectorConfirmationAndReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, base := waveFixture(t)
		selector, err := relayselect.New(relayselect.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		for wave := 0; wave < 2; wave++ {
			if wave > 0 {
				time.Sleep(time.Millisecond)
			}
			k := &observationScheduleBackend{fakeNodeLease: base, calls: map[string]int{}, preCost: time.Millisecond, postCost: time.Millisecond, healthyDuration: 10 * time.Millisecond, started: time.Now()}
			e.backend = k
			report, err := e.observeTarget(context.Background(), "app", "", selector.MaxConnectTime(), k.probe)
			if err != nil || !report.Valid || report.Reason != "" {
				t.Fatal("fresh confirmation report failed", report.Reason, err)
			}
			decision := selector.Decide(report)
			if wave == 0 && decision.DesiredPathID != "" {
				t.Fatal("one report satisfied confirmation")
			}
			if wave == 1 {
				if decision.DesiredPathID != "p7" {
					t.Fatal("two distinct reports did not confirm health", decision.Reason)
				}
				replayed := selector.Decide(report)
				if replayed.DesiredPathID != "" || replayed.Reason != "observation_replayed" {
					t.Fatal("selector accepted replayed proof", replayed.Reason)
				}
			}
		}
	})
}
