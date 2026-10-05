// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"

	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
)

// Mutating CLI calls and observations share the supervisor's bounded admission
// retry. Only lock contention is retried; a failed operation is never replayed.
func openNodeRelayEngine(ctx context.Context, node *config.NodeConfig, dir string) (*relaycache.Store, *relayapply.Engine, error) {
	locks, cancel := relaySupervisionLockContext(ctx)
	defer cancel()
	c, err := retrySupervisedLock(locks, func() (*relaycache.Store, error) { return openNodeRelayCache(node, dir, false) }, relaycache.ErrBusy)
	if err != nil {
		return nil, nil, err
	}
	e, err := retrySupervisedLock(locks, func() (*relayapply.Engine, error) { return relayapply.Open(c, node.RelayUnderlays) }, relayapply.ErrKernelBusy)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, e, nil
}
