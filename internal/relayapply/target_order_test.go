// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relaycatalog"
)

// Each wave performs one maintenance check before its two proof boundaries.
// Record the real precheck admission, independently of TCP completion order.
// Only the existing fake kernel is used: no socket or host network mutation.
type targetOrderBackend struct {
	*fakeNodeLease
	mu         sync.Mutex
	calls      map[string]int
	prechecks  []string
	onPrecheck func(context.Context, Entry) error
}

func (k *targetOrderBackend) Check(ctx context.Context, entry Entry, fresh bool) (bool, error) {
	id := entry.Candidate.PathID
	k.mu.Lock()
	k.calls[id]++
	precheck := k.calls[id] == 2
	if precheck {
		k.prechecks = append(k.prechecks, id)
	}
	k.mu.Unlock()
	if precheck && k.onPrecheck != nil {
		if err := k.onPrecheck(ctx, entry); err != nil {
			return false, err
		}
	}
	return k.fakeNodeLease.Check(ctx, entry, fresh)
}

func (k *targetOrderBackend) order() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.prechecks)
}

type targetOrderResult struct {
	report TargetReport
	err    error
}

// All probes must enter before any is released. Thus preserving precheck order
// cannot pass by serializing TCP, reducing the candidate population, or waiting
// for the preceding candidate's successful probe. Reverse TCP completion must
// not reorder admission in the following wave.
func TestTargetPrechecksFollowCatalogOrderAcrossWaves(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprintf("filtered_%t", filtered), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, base := waveFixture(t)
				want := []string{"p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"}
				var exclude func(string, int) string
				if filtered {
					want = []string{"p0", "p2", "p3", "p5", "p6", "p7"}
					exclude = func(path string, _ int) string {
						if path == "p1" || path == "p4" {
							return "cost_limit"
						}
						return ""
					}
				}
				for wave := 0; wave < 3; wave++ {
					k := &targetOrderBackend{fakeNodeLease: base, calls: map[string]int{}}
					k.onPrecheck = func(context.Context, Entry) error {
						time.Sleep(100 * time.Microsecond)
						return nil
					}
					e.backend = k
					entered := make(chan string, len(want))
					release := map[string]chan struct{}{}
					for _, id := range want {
						release[id] = make(chan struct{})
					}
					var live, peak atomic.Int32
					done := make(chan targetOrderResult, 1)
					go func() {
						report, err := e.observeTargetFiltered(context.Background(), "app", "", 2*time.Second, func(ctx context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
							n := live.Add(1)
							defer live.Add(-1)
							for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
							}
							entered <- entry.Candidate.PathID
							select {
							case <-release[entry.Candidate.PathID]:
								return targetProof{handshake: 1, rx: 96, tx: 192}, nil
							case <-ctx.Done():
								return targetProof{}, ctx.Err()
							}
						}, exclude)
						done <- targetOrderResult{report, err}
					}()
					seen := map[string]bool{}
					for range want {
						select {
						case id := <-entered:
							seen[id] = true
						case <-time.After(time.Second):
							t.Fatal("ordered prechecks serialized TCP or stranded a queued job")
						}
					}
					for i := len(want) - 1; i >= 0; i-- {
						close(release[want[i]])
						synctest.Wait()
					}
					out := <-done
					if out.err != nil || !out.report.Valid || len(seen) != len(want) || int(peak.Load()) != len(want) || live.Load() != 0 {
						t.Fatalf("wave %d: valid=%t err=%v seen=%d peak=%d live=%d", wave, out.report.Valid, out.err, len(seen), peak.Load(), live.Load())
					}
					if got := k.order(); !slices.Equal(got, want) {
						t.Errorf("wave %d precheck admission = %v; want unchanged catalog order %v", wave, got, want)
					}
					for _, path := range out.report.Paths {
						if !slices.Contains(want, path.PathID) {
							if path.State != "excluded" {
								t.Errorf("omitted job %s acquired health: %s", path.PathID, path.State)
							}
						} else if path.State != "reachable" {
							t.Errorf("verified path %s = %s/%s", path.PathID, path.State, path.Reason)
						}
					}
				}
			})
		})
	}
}

func TestTargetFailedFirstPrecheckReleasesFollowingJobs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, base := waveFixture(t)
		k := &targetOrderBackend{fakeNodeLease: base, calls: map[string]int{}}
		k.onPrecheck = func(_ context.Context, entry Entry) error {
			if entry.Candidate.PathID == "p0" {
				return ErrConflict
			}
			return nil
		}
		e.backend = k
		var proofs atomic.Int32
		report, err := e.observeTarget(context.Background(), "app", "", time.Second, func(_ context.Context, entry Entry, _ relaycatalog.Target) (targetProof, error) {
			proofs.Add(1)
			if entry.Candidate.PathID == "p0" {
				t.Error("failed precheck reached TCP")
			}
			return targetProof{handshake: 1, rx: 96, tx: 192}, nil
		})
		if err != nil || !report.Valid || proofs.Load() != 7 || report.Reason != "" {
			t.Fatalf("first failure stranded independent jobs: valid=%t reason=%s err=%v proofs=%d", report.Valid, report.Reason, err, proofs.Load())
		}
		for _, path := range report.Paths {
			if path.PathID == "p0" {
				if path.State != "unknown" || path.Reason != "kernel_conflict_or_unavailable" {
					t.Errorf("failed precheck granted health: %s/%s", path.State, path.Reason)
				}
			} else if path.State != "reachable" {
				t.Errorf("independent job %s was stranded: %s/%s", path.PathID, path.State, path.Reason)
			}
		}
	})
}

func TestTargetQueuedPrechecksJoinOnCancellationAndDeadline(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel_%t", cancelParent), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, base := waveFixture(t)
				k := &targetOrderBackend{fakeNodeLease: base, calls: map[string]int{}}
				entered := make(chan struct{}, 8)
				var checks, probes atomic.Int32
				k.onPrecheck = func(ctx context.Context, _ Entry) error {
					checks.Add(1)
					defer checks.Add(-1)
					entered <- struct{}{}
					<-ctx.Done()
					return ctx.Err()
				}
				e.backend = k
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan targetOrderResult, 1)
				began := time.Now()
				go func() {
					report, err := e.observeTarget(ctx, "app", "", time.Second, func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
						probes.Add(1)
						return targetProof{handshake: 1, rx: 96, tx: 192}, nil
					})
					done <- targetOrderResult{report, err}
				}()
				<-entered
				synctest.Wait() // First check holds the gate; remaining workers wait.
				if cancelParent {
					cancel()
				}
				out := <-done
				if probes.Load() != 0 || checks.Load() != 0 {
					t.Fatalf("canceled wave retained work/evidence: probes=%d checks=%d", probes.Load(), checks.Load())
				}
				if cancelParent {
					if out.report.Valid || !errors.Is(out.err, context.Canceled) || time.Since(began) != 0 {
						t.Fatalf("parent cancellation did not join immediately: valid=%t err=%v elapsed=%s", out.report.Valid, out.err, time.Since(began))
					}
				} else if out.err != nil || !out.report.Valid || out.report.Reason != "observation_budget_exhausted" || time.Since(began) != targetObservationWaveDuration {
					// Even when shared and child deadlines are simultaneous,
					// completed workers must not hide the exhausted budget.
					t.Fatalf("shared wave deadline changed: valid=%t reason=%s err=%v elapsed=%s", out.report.Valid, out.report.Reason, out.err, time.Since(began))
				}
				for _, path := range out.report.Paths {
					if path.State != "unknown" {
						t.Errorf("unchecked path %s acquired health: %s", path.PathID, path.State)
					}
				}
			})
		})
	}
}

// Force each later job to arrive and block before the first job can run. Unlike
// a launch-order stress test, this does not depend on the Go scheduler choosing
// an inconvenient interleaving: synctest.Wait proves each reverse arrival has
// reached a durable wait without advancing time.
func TestTargetPrecheckGateOrdersReverseArrivals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), targetObservationWaveDuration)
		defer cancel()
		gates := newObservationGates(3)
		order := []int{}
		prechecked := make(chan int, len(gates))
		release := make(chan struct{})
		done := make(chan error, len(gates))
		began := time.Now()
		for i := len(gates) - 1; i >= 0; i-- {
			go func() {
				_, finish, err := observationStage(ctx, "precheck", gates[i])
				if err != nil {
					finish()
					done <- err
					return
				}
				order = append(order, i) // Protected by the shared checks gate.
				finish()
				prechecked <- i
				select {
				case <-release:
				case <-ctx.Done():
					done <- ctx.Err()
					return
				}
				_, finish, err = observationStage(ctx, "postcheck", gates[i])
				finish()
				done <- err
			}()
			synctest.Wait()
			if i != 0 && len(prechecked) != 0 {
				t.Errorf("job %d bypassed the catalog predecessor", i)
			}
		}
		if len(prechecked) != len(gates) || !slices.Equal(order, []int{0, 1, 2}) {
			t.Errorf("reverse arrivals changed precheck order or serialized proofs: order=%v completed=%d", order, len(prechecked))
		}
		close(release)
		for range gates {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		if time.Since(began) != 0 {
			t.Fatalf("precheck ordering waited for a timer: %s", time.Since(began))
		}
	})
}
