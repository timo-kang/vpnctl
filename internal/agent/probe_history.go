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
	"vpnctl/internal/history"
	"vpnctl/internal/observation"
)

// ProbeHistorySupervisor retains probe delivery across agent retries.
// One owner calls Configure/Stop after joining sessions using the old identity.
type ProbeHistorySupervisor struct {
	key    string
	queue  *observation.Queue
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *ProbeHistorySupervisor) Configure(ctx context.Context, cfg config.NodeConfig) context.Context {
	key, _ := json.Marshal([]string{cfg.Name, cfg.Controller, cfg.PKIDir})
	if string(key) != s.key || s.queue == nil {
		s.Stop()
		s.key = string(key)
		s.queue = observation.New()
		// The lifecycle owner stops delivery after joining producers. Detaching
		// parent cancellation lets an in-flight probe enqueue its final
		// outcome before Stop accounts for every remaining observation.
		work, cancel := context.WithCancel(context.WithoutCancel(ctx))
		s.cancel, s.done = cancel, make(chan struct{})
		q, done := s.queue, s.done
		go func() {
			defer close(done)
			client := newClient(cfg)
			defer client.CloseIdleConnections()
			q.Run(work, func(ctx context.Context, e history.Observation) (bool, error) {
				err := client.SubmitMetrics(ctx, api.MetricsRequest{NodeID: cfg.Name, Observations: []history.Observation{e}})
				var response *api.HTTPError
				retry := true
				if errors.As(err, &response) {
					if response.StatusCode == http.StatusServiceUnavailable && response.Code == api.CodeHistoryQuota {
						return false, errors.Join(observation.ErrQuotaRejected, err)
					}
					// 401/403 can recover after registration/trust sync; still bounded.
					retry = response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusConflict && response.StatusCode != http.StatusRequestEntityTooLarge && response.StatusCode != http.StatusNotFound
				}
				return retry, err
			})
		}()
	}
	return observation.WithQueue(ctx, s.queue)
}
func (s *ProbeHistorySupervisor) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	s.key, s.queue, s.cancel, s.done = "", nil, nil, nil
}
