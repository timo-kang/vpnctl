// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

type probeResult struct {
	key       string
	err       error
	completed time.Time
}

// probeTrials keeps active peers' full verification budget while the Step owner
// removes expired initial routes. Probe goroutines never mutate engine state.
// A timely second nonce still needs a kernel readback before its route can stay.
func (e *Engine) probeTrials(ctx context.Context, trials map[string]Candidate, before snapshot) (map[string]error, []Status, error) {
	wave, cancel := context.WithCancel(ctx)
	expires := map[string]time.Time{}
	for key := range trials {
		if started, initial := e.trialStarted[key]; initial && e.successes[key] < 2 {
			remaining := InitialTrialWindow - e.now().Sub(started)
			if e.now().Before(started) {
				remaining = 0
			}
			expires[key] = time.Now().Add(remaining)
		}
	}
	out := make(chan probeResult, len(trials))
	var workers sync.WaitGroup
	for key, c := range trials {
		limit := time.Second
		if deadline, initial := expires[key]; initial {
			limit = min(time.Second, time.Until(deadline))
		}
		probeCtx, stop := context.WithTimeout(wave, limit)
		workers.Go(func() {
			defer stop()
			err := e.backend.Probe(probeCtx, c)
			out <- probeResult{key, err, time.Now()}
		})
	}
	// The buffered result channel also lets canceled probes finish on errors.
	// Join every probe before the caller can Reset or begin another Step.
	defer func() { cancel(); workers.Wait() }()
	results := make(map[string]error, len(trials))
	completed := make(map[string]probeResult, len(trials))
	remaining := len(trials)
	record := func(result probeResult) {
		results[result.key] = result.err
		completed[result.key] = result
		remaining--
	}
	var statuses []Status
	for {
		// Reconcile all already-published proofs before examining deadlines.
		// In particular, a slower active peer must not hide nonce number two.
	drain:
		for {
			select {
			case result := <-out:
				record(result)
			default:
				break drain
			}
		}
		var expired, proven []string
		now := time.Now()
		for key, deadline := range expires {
			if now.Before(deadline) {
				continue
			}
			expired = append(expired, key)
			if result, ok := completed[key]; ok && result.err == nil && result.completed.Before(deadline) && e.successes[key] == 1 {
				proven = append(proven, key)
			}
		}
		if len(proven) != 0 {
			after, err := e.inspect(ctx)
			if err != nil {
				return results, statuses, err
			}
			for _, key := range proven {
				p, old := after.Peers[key], before.Peers[key]
				if !matches(p, trials[key]) {
					return results, statuses, errors.New("direct peer changed during verification")
				}
				if p.Handshake > 0 && p.RX > old.RX && p.TX > old.TX {
					e.successes[key] = 2
					delete(expires, key)
				}
			}
		}
		var remove []string
		for _, key := range expired {
			if _, pending := expires[key]; pending {
				remove = append(remove, key)
			}
		}
		if len(remove) != 0 {
			sort.Strings(remove)
			if err := e.remove(ctx, remove); err != nil {
				return results, statuses, err
			}
			for _, key := range remove {
				c := trials[key]
				e.cooldown[c.ID] = e.now().Add(e.retryDelay(c))
				statuses = append(statuses, Status{c.ID, "relay_unverified", "initial_trial_expired", c.Generation})
				delete(trials, key)
				delete(expires, key)
			}
		}
		if remaining == 0 {
			return results, statuses, nil
		}
		var next time.Time
		for _, deadline := range expires {
			if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}
		var timer *time.Timer
		var expiredC <-chan time.Time
		if !next.IsZero() {
			delay := time.Until(next)
			if delay <= 0 {
				continue
			}
			timer = time.NewTimer(delay)
			expiredC = timer.C
		}
		select {
		case result := <-out:
			record(result)
		case <-expiredC:
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return results, statuses, ctx.Err()
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
