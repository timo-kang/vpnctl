// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/uplink"
)

// UplinkSupervisor owns observation across registration/tunnel recovery retries.
// Calls to Configure/Stop belong to one lifecycle owner, like the credential supervisor.
type UplinkSupervisor struct {
	key    string
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *UplinkSupervisor) Configure(ctx context.Context, cfg config.NodeConfig) {
	key, _ := json.Marshal(struct {
		Name, Controller, PKI string
		Observation           *uplink.Config
	}{cfg.Name, cfg.Controller, cfg.PKIDir, cfg.UplinkObservation})
	if string(key) == s.key {
		return
	}
	s.Stop()
	s.key = string(key)
	if cfg.UplinkObservation == nil {
		return
	}
	work, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		client := newClient(cfg)
		defer client.CloseIdleConnections()
		observer := uplink.Observer{Config: *cfg.UplinkObservation, Collector: uplink.LinuxCollector{}, Prober: uplink.NetworkProber{}}
		runObservations(work, *cfg.UplinkObservation, observer.Collect, func(ctx context.Context, snapshot uplink.Snapshot) error {
			return client.SubmitUplink(ctx, api.UplinkRequest{NodeID: cfg.Name, Snapshot: snapshot})
		})
	}()
}
func (s *UplinkSupervisor) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel = nil
	}
	s.key = ""
}

const maxPendingUplinks = 64

func runObservations(ctx context.Context, cfg uplink.Config, collect func(context.Context) uplink.Snapshot, submit func(context.Context, uplink.Snapshot) error) {
	pending := make([]uplink.Snapshot, 0, maxPendingUplinks)
	var dropped uint64
	defer func() {
		if len(pending) > 0 {
			slog.Warn("uplink observation queue discarded on stop", "count", len(pending))
		}
	}()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}
		snapshot := collect(ctx)
		if ctx.Err() != nil {
			return
		}
		if len(pending) == maxPendingUplinks {
			pending = pending[1:]
			dropped++
			slog.Warn("uplink observation queue full", "dropped", dropped)
		}
		snapshot.Dropped = dropped
		pending = append(pending, snapshot)
		// Finite catch-up budget; failed uploads preserve the exact sample ID/body.
		for attempts := 0; attempts < 4 && len(pending) > 0; attempts++ {
			work, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := submit(work, pending[0])
			cancel()
			if err != nil {
				var response *api.HTTPError
				if errors.As(err, &response) && (response.StatusCode == 400 || response.StatusCode == 409 || response.StatusCode == 413) {
					pending = pending[1:]
					dropped++
					slog.Error("uplink observation permanently rejected", "status", response.StatusCode, "dropped", dropped)
					continue
				}
				if ctx.Err() == nil {
					slog.Warn("uplink observation upload failed", "pending", len(pending))
				}
				break
			}
			pending = pending[1:]
		}
		timer.Reset(time.Duration(cfg.IntervalSec) * time.Second)
	}
}
