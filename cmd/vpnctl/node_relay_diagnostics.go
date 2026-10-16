// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayobserve"
)

// Bracket release without claiming to observe the exact unlock instant. The
// caller snapshots diagnostics after this returns, for success and work errors.
func closeNodeRelayEngine(ctx context.Context, cache *relaycache.Store, engine *relayapply.Engine) {
	relayobserve.Mark(ctx, "ownership_release_started")
	defer relayobserve.Mark(ctx, "ownership_release_finished")
	defer cache.Close()
	engine.Close()
}
