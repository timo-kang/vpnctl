// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/diagnostic"
	"vpnctl/internal/history"
)

// EventSupervisor retains delivery and transition state across agent retries.
// One owner calls Configure/Stop after joining sessions using the old identity.
type EventSupervisor struct {
	key    string
	queue  *diagnostic.Queue
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *EventSupervisor) Configure(ctx context.Context, cfg config.NodeConfig) context.Context {
	key, _ := json.Marshal([]string{cfg.Name, cfg.Controller, cfg.PKIDir})
	if string(key) != s.key || s.queue == nil {
		s.Stop()
		s.key = string(key)
		s.queue = diagnostic.New("node", cfg.Name)
		work, cancel := context.WithCancel(ctx)
		s.cancel, s.done = cancel, make(chan struct{})
		q, done := s.queue, s.done
		go func() {
			defer close(done)
			client := newClient(cfg)
			defer client.CloseIdleConnections()
			q.Run(work, func(ctx context.Context, e history.Event) (bool, error) {
				err := client.SubmitEvent(ctx, api.EventRequest{NodeID: cfg.Name, Event: e})
				var response *api.HTTPError
				retry := true
				if errors.As(err, &response) {
					// 401/403 can recover after registration/trust sync; still bounded.
					retry = response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusConflict && response.StatusCode != http.StatusRequestEntityTooLarge && response.StatusCode != http.StatusNotFound
				}
				return retry, err
			})
		}()
	}
	return diagnostic.WithQueue(ctx, s.queue)
}
func (s *EventSupervisor) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	s.key, s.queue, s.cancel, s.done = "", nil, nil, nil
}

func observeNAT(ctx context.Context, addr, nat string) {
	if ctx.Err() != nil {
		return
	}
	raw, _ := json.Marshal(struct {
		Address string `json:"address"`
		Type    string `json:"type"`
	}{addr, nat})
	diagnostic.Observe(ctx, "nat", history.Event{Kind: "nat_remap", Source: "node-stun", Target: "shared-udp", Current: string(raw), Severity: "info", Validity: "observed"})
}
