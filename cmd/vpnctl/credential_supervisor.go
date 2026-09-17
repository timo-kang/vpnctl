// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
)

// One worker per node-serve process, retained across agent attempts. A target or
// identity change drains the old worker before a new one can access credentials.
type credentialSupervisor struct {
	cfg    config.NodeConfig
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *credentialSupervisor) configure(cfg config.NodeConfig) {
	if cfg.PKIDir != s.cfg.PKIDir || cfg.Name != s.cfg.Name || cfg.Controller != s.cfg.Controller {
		s.stop()
	}
	s.cfg = cfg
}
func (s *credentialSupervisor) start(ctx context.Context) {
	if s.cancel != nil || s.cfg.PKIDir == "" || s.cfg.Controller == "" {
		return
	}
	child, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	cfg, done := s.cfg, s.done
	go func() {
		defer close(done)
		client := api.NewCredentialClient(cfg.Controller, cfg.PKIDir)
		defer client.CloseIdleConnections()
		client.MaintainCredentials(child, cfg.PKIDir, cfg.Name)
	}()
}
func (s *credentialSupervisor) stop() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	<-s.done
	s.cancel = nil
	s.done = nil
}
