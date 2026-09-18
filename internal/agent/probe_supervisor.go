// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"

	"vpnctl/internal/config"
	"vpnctl/internal/direct"
)

// ProbeSupervisor owns the shared UDP socket across controller registration,
// session retries and backoff. Configure and RunSession are called sequentially
// by the process owner, after any preceding session has joined its workers.
// A UDP reply indicates responder reachability, never successful registration.
type ProbeSupervisor struct {
	shared *direct.Shared
	port   int
}

func (p *ProbeSupervisor) Configure(cfg config.NodeConfig) error {
	if cfg.ProbePort == p.port {
		return nil
	}
	if cfg.ProbePort <= 0 {
		p.Close()
		return nil
	}
	next, err := direct.ListenShared(fmt.Sprintf(":%d", cfg.ProbePort))
	if err != nil {
		return err
	}
	// Bind the replacement first, retaining the old working socket on failure.
	p.Close()
	p.shared, p.port = next, cfg.ProbePort
	slog.Info("probe responder started", "addr", next.LocalAddr())
	return nil
}

func (p *ProbeSupervisor) Close() {
	if p.shared != nil {
		_ = p.shared.Close()
		p.shared = nil
	}
	p.port = 0
}

func (p *ProbeSupervisor) RunSession(ctx context.Context, cfg config.NodeConfig) error {
	if err := p.Configure(cfg); err != nil {
		return err
	}
	client := newClient(cfg)
	defer client.CloseIdleConnections()
	return runSessionWithProbe(ctx, cfg, client, p.shared)
}
