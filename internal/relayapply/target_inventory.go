// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"strings"
	"time"
)

type observationCheckerKey struct{}
type observationFloorKey struct{}
type observationChecker func(context.Context, Entry, bool) (bool, error)

// A wave cache belongs to one Engine lifetime; another Engine must collect afresh.
type ownedObservationChecker struct {
	owner *Engine
	check observationChecker
}

// Share only the public namespace inventory within one observation. The caller
// must defer the returned restoration so later inspection, application proof,
// maintenance and mutation checks read live state, including after failed waves.
// A fresh Engine gets a fresh cache for its postchecks.
func enableTargetObservationInventory(e *Engine) func() {
	if e == nil {
		return nil
	}
	k, ok := e.backend.(nodeKernel)
	if !ok {
		return nil
	}
	original := e.backend
	k.run = observationInventory(k.run, leaseBootTime)
	e.backend = k
	return func() { e.backend = original }
}

func (e *Engine) targetProbeChecker(ctx context.Context) observationChecker {
	if shared, ok := ctx.Value(observationCheckerKey{}).(ownedObservationChecker); ok && shared.owner == e {
		return shared.check
	}
	if k, ok := e.backend.(nodeKernel); ok {
		return k.kernel.Check
	}
	return e.backend.Check
}

// Only the serialized pre/post ownership checks within one wave share these
// public namespace inventories. Per-interface state, nft/BPF leases, approvals,
// underlay collection and the TCP/route proof remain live. A postcheck cannot
// reuse any inventory whose command started before that candidate's TCP ended.
func observationInventory(run commandFunc, clock func() (time.Duration, error)) commandFunc {
	type snapshot struct {
		data []byte
		at   time.Duration
	}
	cache := map[string]snapshot{}
	return func(ctx context.Context, input, name string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := name + "\x00" + strings.Join(args, "\x00")
		if input != "" || !sharedMaintenanceInventory(key) {
			return run(ctx, input, name, args...)
		}
		now, err := clock()
		if err != nil {
			return nil, err
		}
		floor, _ := ctx.Value(observationFloorKey{}).(time.Duration)
		if now < floor {
			return nil, errors.New("observation clock discontinuity")
		}
		if s, ok := cache[key]; ok && now >= s.at && now-s.at < targetObservationWaveDuration && s.at >= floor {
			return append([]byte(nil), s.data...), nil
		}
		delete(cache, key) // A failed fresh read must not leave older evidence available.
		b, err := run(ctx, input, name, args...)
		if err == nil {
			if len(b) > 512<<10 {
				return nil, errors.New("observation inventory exceeds limit")
			}
			cache[key] = snapshot{append([]byte(nil), b...), now}
		}
		return b, err
	}
}
