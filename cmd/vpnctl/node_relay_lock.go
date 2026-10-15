// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayobserve"
)

// Waiting carries no observations or authority. Keep the FIFO ticket through
// contention so an immediately rejoining process cannot overtake an older one.
const nodeAdmissionDuration = 10 * time.Second

func openNodeRelayEngine(ctx context.Context, node *config.NodeConfig, dir string) (*relaycache.Store, *relayapply.Engine, error) {
	locks, cancel := context.WithTimeout(ctx, nodeAdmissionDuration)
	defer cancel()
	c, err := openNodeRelayCacheUsing(node, dir, false, func(dir string, opts relaycache.Options) (*relaycache.Store, error) {
		return relaycache.OpenQueued(locks, dir, opts)
	})
	if err != nil {
		return nil, nil, err
	}
	kernel, kernelDone := relayobserve.Phase(locks, "admission_kernel")
	e, err := retrySupervisedLock(kernel, func() (*relayapply.Engine, error) { return relayapply.Open(c, node.RelayUnderlays) }, relayapply.ErrKernelBusy)
	kernelDone()
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	relayobserve.Mark(ctx, "admission_kernel_ready")
	return c, e, nil
}

func nodeAdmissionReason(err error) string {
	if errors.Is(err, relaycache.ErrAdmissionFull) {
		return "admission_capacity_exhausted"
	}
	return "ownership_unavailable"
}

// nodeRelayObservationOwnership returns the complete Store and namespace lock
// while candidate sockets run, then reopens both from the durable cache.
// It is scoped to one reconciliation cycle; a failed reentry remains closed.
type nodeRelayObservationOwnership struct {
	node   *config.NodeConfig
	dir    string
	cache  *relaycache.Store
	engine *relayapply.Engine
}

func (o *nodeRelayObservationOwnership) Release(ctx context.Context, engine *relayapply.Engine) error {
	if o == nil || engine == nil || engine != o.engine || o.cache == nil {
		return errors.New("relay observation ownership mismatch")
	}
	err := closeNodeRelayEngine(ctx, o.cache, engine)
	o.engine, o.cache = nil, nil
	return err
}

func (o *nodeRelayObservationOwnership) Reacquire(ctx context.Context) (*relayapply.Engine, error) {
	if o == nil || o.engine != nil || o.cache != nil {
		return nil, errors.New("relay observation ownership was not released")
	}
	admission, done := relayobserve.Phase(ctx, "admission")
	cache, engine, err := openNodeRelayEngine(admission, o.node, o.dir)
	done()
	if err != nil {
		return nil, err
	}
	o.cache, o.engine = cache, engine
	return engine, nil
}

func (o *nodeRelayObservationOwnership) Close(ctx context.Context) {
	if o == nil || o.engine == nil || o.cache == nil {
		return
	}
	closeNodeRelayEngine(ctx, o.cache, o.engine)
	o.engine, o.cache = nil, nil
}
