// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"sync"

	"vpnctl/internal/relayobserve"
)

// A wave has one serialized check owner. Prechecks retain catalog order;
// after at most two admissions a waiting postcheck gets its turn. Registering
// all precheck tickets up front makes arbitration independent of goroutine
// arrival order. The 2:1 bound gives queued TCP starts forward progress without
// deferring every postcheck until all prechecks finish. It is an admission bound,
// not a time guarantee for an arbitrarily slow check. TCP work is outside this
// gate and never awaited by arbitration.
type observationGate struct {
	checks *observationChecks
	pre    *observationCheck
}

type observationCheck struct {
	ready    chan struct{}
	canceled bool
}

type observationChecks struct {
	mu            sync.Mutex
	pre, post     []*observationCheck
	active        *observationCheck
	preAdmissions int
}

func newObservationGates(count int) []*observationGate {
	checks := &observationChecks{}
	gates := make([]*observationGate, count)
	for i := range gates {
		request := &observationCheck{ready: make(chan struct{})}
		checks.pre = append(checks.pre, request)
		gates[i] = &observationGate{checks: checks, pre: request}
	}
	return gates
}

// dispatch requires mu. Tickets carry only ownership, not an observation or
// cached authority. Every admitted stage still performs its original checks.
func (c *observationChecks) dispatch() {
	if c.active != nil {
		return
	}
	for len(c.pre) != 0 && c.pre[0].canceled {
		c.pre = c.pre[1:]
	}
	for len(c.post) != 0 && c.post[0].canceled {
		c.post = c.post[1:]
	}
	switch {
	case len(c.post) != 0 && (len(c.pre) == 0 || c.preAdmissions >= 2):
		c.active, c.post = c.post[0], c.post[1:]
		c.preAdmissions = 0
	case len(c.pre) != 0:
		c.active, c.pre = c.pre[0], c.pre[1:]
		c.preAdmissions++
	default:
		return
	}
	close(c.active.ready)
}

func (g *observationGate) acquire(ctx context.Context, pre bool) (func(), error) {
	c, request := g.checks, g.pre
	c.mu.Lock()
	if !pre {
		request = &observationCheck{ready: make(chan struct{})}
		c.post = append(c.post, request)
	}
	c.dispatch()
	c.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-request.ready:
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		// Cancellation can race a grant. Relinquish that grant too so the
		// remaining workers can exit without retaining a check owner.
		request.canceled = true
		if c.active == request {
			c.active = nil
		}
		c.dispatch()
		c.mu.Unlock()
		return func() {}, err
	}
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.active = nil
		c.dispatch()
		c.mu.Unlock()
	}, nil
}

func observationStage(ctx context.Context, phase string, gate *observationGate) (context.Context, func(), error) {
	ctx, done := relayobserve.Phase(ctx, phase)
	if gate == nil {
		return ctx, done, ctx.Err()
	}
	release, err := gate.acquire(ctx, phase == "precheck")
	return ctx, func() { release(); done() }, err
}
