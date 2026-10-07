// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Delay only nonce responses. The fake kernel still enforces durable intent,
// ownership and fresh counter growth through the real Engine.Step path.
type waveBoundsKernel struct {
	*fakeKernel
	observations sync.Mutex
	delays       map[string]time.Duration
	failures     map[string]bool
	silentKey    string
	started      bool
	readbacks    int
	requests     map[string]int
	durations    map[string]time.Duration
	completed    map[string]time.Time
	removed      map[string]time.Time
}

func newWaveBoundsKernel(k *fakeKernel) *waveBoundsKernel {
	return &waveBoundsKernel{
		fakeKernel: k,
		delays:     map[string]time.Duration{},
		failures:   map[string]bool{},
		requests:   map[string]int{},
		durations:  map[string]time.Duration{},
		completed:  map[string]time.Time{},
		removed:    map[string]time.Time{},
	}
}

func (k *waveBoundsKernel) Snapshot(ctx context.Context) (snapshot, error) {
	k.observations.Lock()
	if k.started {
		// Exclude installation readbacks: this guard measures verification work
		// from the first nonce request through the final Step readback.
		k.readbacks++
	}
	k.observations.Unlock()
	return k.fakeKernel.Snapshot(ctx)
}

func (k *waveBoundsKernel) Probe(ctx context.Context, c Candidate) error {
	began := time.Now()
	k.observations.Lock()
	k.started = true
	k.requests[c.Key]++
	k.observations.Unlock()
	defer func() {
		k.observations.Lock()
		defer k.observations.Unlock()
		k.durations[c.Key] = time.Since(began)
		k.completed[c.Key] = time.Now()
	}()
	if c.Key == k.silentKey {
		<-ctx.Done()
		return ctx.Err()
	}
	timer := time.NewTimer(k.delays[c.Key])
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if k.failures[c.Key] {
		return errors.New("simulated lost nonce")
	}
	return k.fakeKernel.Probe(ctx, c)
}

func (k *waveBoundsKernel) Remove(ctx context.Context, keys []string) error {
	if err := k.fakeKernel.Remove(ctx, keys); err != nil {
		return err
	}
	k.observations.Lock()
	defer k.observations.Unlock()
	for _, key := range keys {
		k.removed[key] = time.Now()
	}
	return nil
}

func waveBoundsCandidates(template Candidate, count int) []Candidate {
	candidates := make([]Candidate, count)
	for i := range candidates {
		c := template
		c.ID = fmt.Sprintf("peer-%d", i)
		c.Key = key(byte(i + 3))
		c.Address = fmt.Sprintf("10.7.0.%d", i+3)
		c.Endpoint = fmt.Sprintf("192.0.2.%d:51820", i+3)
		candidates[i] = c
	}
	return candidates
}

func TestMixedWaveReadbacksStayBoundedAcrossCandidateCounts(t *testing.T) {
	type measurement struct {
		readbacks int
		elapsed   time.Duration
	}
	measurements := map[int]measurement{}
	for _, count := range []int{2, 32} {
		t.Run(fmt.Sprintf("candidates-%d", count), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, kernel, template := fixture(t)
				candidates := waveBoundsCandidates(template, count)
				k := newWaveBoundsKernel(kernel)
				k.silentKey = candidates[count-1].Key
				for i, c := range candidates[:count-1] {
					// Distinct completions spread over the first 200 ms expose a
					// per-completion subprocess readback implementation.
					k.delays[c.Key] = time.Duration(i+1) * 200 * time.Millisecond / time.Duration(count-1)
				}
				e.backend = k
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				began := time.Now()
				statuses, err := e.Step(ctx, candidates)
				if err != nil {
					t.Fatal(err)
				}
				elapsed := time.Since(began)
				if elapsed < time.Second || elapsed >= 2*time.Second {
					t.Fatalf("mixed wave did not retain its bounded full-second request: elapsed=%s", elapsed)
				}
				states := map[string]string{}
				for _, status := range statuses {
					states[status.ID] = status.State
				}
				for _, c := range candidates[:count-1] {
					if states[c.ID] != "active" || e.successes[c.Key] != 2 || k.requests[c.Key] < 2 {
						t.Fatalf("bounded work skipped timely fresh proofs: peer=%s state=%s proofs=%d requests=%d", c.ID, states[c.ID], e.successes[c.Key], k.requests[c.Key])
					}
				}
				silent := candidates[count-1]
				if states[silent.ID] == "active" || e.successes[silent.Key] != 0 || k.durations[silent.Key] < time.Second {
					t.Fatalf("silent peer became verified or lost its request budget: state=%s proofs=%d duration=%s", states[silent.ID], e.successes[silent.Key], k.durations[silent.Key])
				}
				measurements[count] = measurement{k.readbacks, elapsed}
				t.Logf("candidates=%d verification_readbacks=%d elapsed=%s", count, k.readbacks, elapsed)
			})
		})
	}
	small, smallOK := measurements[2]
	large, largeOK := measurements[32]
	if !smallOK || !largeOK {
		t.Fatal("missing successful mixed-wave measurement")
	}
	// Permit one extra readback per verification tick and a final boundary
	// readback. This allows scheduling/batching changes, but cannot grow into
	// a readback for each of the 31 independently completed healthy peers.
	ticks := int((large.elapsed + VerificationInterval - 1) / VerificationInterval)
	if large.readbacks > small.readbacks+ticks+1 {
		t.Fatalf("verification readbacks scale with peers instead of cadence: 2 peers=%d, 32 peers=%d, ticks=%d", small.readbacks, large.readbacks, ticks)
	}
}

func TestActiveFailureIsRemovedDuringInitialRetryChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, kernel, template := fixture(t)
		candidates := waveBoundsCandidates(template, 32)
		failed, healthy := candidates[0], candidates[1]
		for range 2 {
			if _, err := e.Step(context.Background(), candidates[:2]); err != nil {
				t.Fatal(err)
			}
		}
		if e.successes[failed.Key] != 2 || e.successes[healthy.Key] != 2 {
			t.Fatal("fixture did not establish both active peers")
		}
		k := newWaveBoundsKernel(kernel)
		k.delays[failed.Key], k.failures[failed.Key] = 20*time.Millisecond, true
		k.delays[healthy.Key] = 900 * time.Millisecond
		k.silentKey = candidates[len(candidates)-1].Key
		for i, c := range candidates[2 : len(candidates)-1] {
			k.delays[c.Key] = time.Duration(i+1) * 200 * time.Millisecond / time.Duration(len(candidates)-3)
			k.failures[c.Key] = true
		}
		e.backend = k
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		statuses, err := e.Step(ctx, candidates)
		if err != nil {
			t.Fatal(err)
		}
		removed := k.removed[failed.Key]
		if removed.IsZero() || !removed.Before(k.completed[healthy.Key]) {
			t.Fatalf("initial churn held failed active route until the slow probe finished: removed=%s healthy_completed=%s", removed, k.completed[healthy.Key])
		}
		if _, installed := kernel.s.Peers[failed.Key]; installed {
			t.Fatal("failed active peer retained its application route")
		}
		if k.durations[healthy.Key] < 900*time.Millisecond || e.successes[healthy.Key] != 2 {
			t.Fatalf("failed-peer removal truncated a healthy active request: duration=%s proofs=%d", k.durations[healthy.Key], e.successes[healthy.Key])
		}
		if _, installed := kernel.s.Peers[healthy.Key]; !installed {
			t.Fatal("healthy active peer lost its application route")
		}
		for _, c := range candidates[2 : len(candidates)-1] {
			if k.requests[c.Key] < 2 || e.successes[c.Key] != 0 {
				t.Fatalf("fixture did not exercise continuing failed initial retries: peer=%s requests=%d proofs=%d", c.ID, k.requests[c.Key], e.successes[c.Key])
			}
		}
		for _, status := range statuses {
			if status.ID == healthy.ID && status.State != "active" || status.ID != healthy.ID && status.State == "active" {
				t.Fatalf("mixed-wave verification state does not match nonce outcomes: %+v", status)
			}
		}
	})
}
