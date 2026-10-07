// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

type probeResult struct {
	key       string
	err       error
	completed time.Time
	before    kernelPeer
	counted   bool
}

// probeTrials gives pending peers another nonce opportunity while unrelated
// requests remain in flight. Readbacks and retries are batched on the worker's
// verification cadence; each individual request retains its one-second budget.
// Only this Step owner changes proofs, journals, or kernel peer ownership.
func (e *Engine) probeTrials(ctx context.Context, trials map[string]Candidate, before snapshot) (map[string]probeResult, []Status, error) {
	wave, cancel := context.WithCancel(ctx)
	expires := map[string]time.Time{}
	baseline := map[string]kernelPeer{}
	for key := range trials {
		baseline[key] = before.Peers[key]
		if started, initial := e.trialStarted[key]; initial && e.successes[key] < 2 {
			remaining := InitialTrialWindow - e.now().Sub(started)
			if e.now().Before(started) {
				remaining = 0
			}
			expires[key] = time.Now().Add(remaining)
		}
	}
	out := make(chan probeResult, len(trials))
	results := make(map[string]probeResult, len(trials))
	var workers sync.WaitGroup
	inFlight := 0
	launch := func(key string) {
		c := trials[key]
		old := baseline[key]
		limit := time.Second
		if deadline, initial := expires[key]; initial {
			limit = min(time.Second, time.Until(deadline))
		}
		probeCtx, stop := context.WithTimeout(wave, limit)
		delete(results, key)
		inFlight++
		workers.Go(func() {
			defer stop()
			err := e.backend.Probe(probeCtx, c)
			out <- probeResult{key: key, err: err, completed: time.Now(), before: old}
		})
	}
	for key := range trials {
		launch(key)
	}
	// A bounded channel lets every canceled probe publish and exit, including
	// when removal/readback fails. Join them before the caller can Reset.
	defer func() { cancel(); workers.Wait() }()
	record := func(result probeResult) {
		results[result.key] = result
		inFlight--
	}
	var statuses []Status
	nextBatch := time.Now().Add(VerificationInterval)
	for {
	drain:
		for {
			select {
			case result := <-out:
				record(result)
			default:
				break drain
			}
		}
		now := time.Now()
		expired := map[string]bool{}
		for key, deadline := range expires {
			if !now.Before(deadline) {
				expired[key] = true
			}
		}
		// Fast waves return their one result per peer to Step as before. Only
		// a wave still waiting on another peer needs an in-wave retry batch.
		batch := inFlight > 0 && len(expires) > 0 && !now.Before(nextBatch)
		var reconcile []string
		for key, result := range results {
			if _, present := trials[key]; present && !result.counted && (batch || expired[key]) {
				reconcile = append(reconcile, key)
			}
		}
		remove := map[string]string{}
		var retry []string
		if len(reconcile) != 0 {
			after, err := e.inspect(ctx)
			if err != nil {
				return results, statuses, err
			}
			for _, key := range reconcile {
				result := results[key]
				p, old := after.Peers[key], baseline[key]
				if !matches(p, trials[key]) {
					return results, statuses, errors.New("direct peer changed during verification")
				}
				deadline, initial := expires[key]
				valid := result.err == nil && p.Handshake > 0 && p.RX > old.RX && p.TX > old.TX
				if initial && !result.completed.Before(deadline) {
					valid = false
				}
				if valid {
					e.successes[key] = min(2, e.successes[key]+1)
					if e.successes[key] == 2 {
						delete(expires, key)
					}
				} else if initial {
					e.successes[key] = 0
				} else {
					remove[key] = probeFailureReason(p, result.err)
				}
				result.counted = true
				results[key] = result
				if initial && e.successes[key] < 2 && time.Now().Before(deadline) && batch {
					baseline[key] = p
					retry = append(retry, key)
				}
			}
		}
		for key := range expires {
			if !time.Now().Before(expires[key]) {
				remove[key] = "initial_trial_expired"
			}
		}
		if len(remove) != 0 {
			keys := make([]string, 0, len(remove))
			for key := range remove {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if err := e.remove(ctx, keys); err != nil {
				return results, statuses, err
			}
			for _, key := range keys {
				c := trials[key]
				e.cooldown[c.ID] = e.now().Add(e.retryDelay(c))
				statuses = append(statuses, Status{c.ID, "relay_unverified", remove[key], c.Generation})
				delete(trials, key)
				delete(expires, key)
			}
		}
		for _, key := range retry {
			if deadline, pending := expires[key]; pending && time.Now().Before(deadline) {
				launch(key)
			}
		}
		if inFlight == 0 {
			return results, statuses, nil
		}
		if batch {
			nextBatch = time.Now().Add(VerificationInterval)
		}
		var next time.Time
		if len(expires) != 0 {
			next = nextBatch
			for _, deadline := range expires {
				if deadline.Before(next) {
					next = deadline
				}
			}
		}
		var timer *time.Timer
		var tick <-chan time.Time
		if !next.IsZero() {
			delay := time.Until(next)
			if delay <= 0 {
				continue
			}
			timer = time.NewTimer(delay)
			tick = timer.C
		}
		select {
		case result := <-out:
			record(result)
		case <-tick:
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

func probeFailureReason(p kernelPeer, err error) string {
	reason := "direct_traffic_not_observed"
	if p.Handshake <= 0 {
		reason = "direct_handshake_missing"
	}
	if err != nil {
		reason = "overlay_probe_failed"
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			reason = "overlay_probe_timeout"
		}
		if p.Handshake <= 0 {
			reason += "_no_handshake"
		}
	}
	return reason
}
