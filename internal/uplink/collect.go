// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplink

import (
	"context"
	"crypto/rand"
	"sync"
	"time"
)

type Collector interface {
	Collect(context.Context, LinkConfig) Link
}
type Prober interface {
	Probe(context.Context, Endpoint, string) (Route, Check)
}
type Observer struct {
	Config    Config
	Collector Collector
	Prober    Prober
}

// Collect waits for every bounded task; it never changes network configuration.
func (o Observer) Collect(ctx context.Context) Snapshot {
	s := Snapshot{ID: rand.Text(), IntervalSec: o.Config.IntervalSec, Links: make([]Link, len(o.Config.Links)), Targets: make([]Target, len(o.Config.Targets))}
	timeout := time.Duration(o.Config.TimeoutMS) * time.Millisecond
	var workers sync.WaitGroup
	for i, cfg := range o.Config.Links {
		workers.Add(1)
		go func() {
			defer workers.Done()
			work, cancel := context.WithTimeout(ctx, timeout*3)
			l := o.Collector.Collect(work, cfg)
			cancel()
			l.Controller = Unknown("not_configured")
			l.ControllerRoute = Route{Check: Unknown("not_configured")}
			if o.Config.Controller != nil {
				work, cancel = context.WithTimeout(ctx, timeout)
				l.ControllerRoute, l.Controller = o.Prober.Probe(work, *o.Config.Controller, cfg.Interface)
				cancel()
			}
			s.Links[i] = l
		}()
	}
	for i, cfg := range o.Config.Targets {
		workers.Add(1)
		go func() {
			defer workers.Done()
			t := Target{TransportRoute: Route{Check: Unknown("not_observed")}, ID: cfg.ID, Protocol: cfg.Protocol, ExpectedRelayID: cfg.RelayID, Relay: Unknown("not_configured")}
			if cfg.RelayProbe != nil {
				work, cancel := context.WithTimeout(ctx, timeout)
				r, result := o.Prober.Probe(work, *cfg.RelayProbe, cfg.Interface)
				cancel()
				t.Relay = result
				if r.State != "up" {
					t.Relay = Unknown("relay_route_unverified")
				}
			}
			work, cancel := context.WithTimeout(ctx, timeout)
			t.Route, t.Service = o.Prober.Probe(work, cfg.Endpoint, "")
			cancel()
			if cfg.Interface != "" && t.Route.State == "up" && t.Route.Interface != cfg.Interface {
				t.Route.Check = Down("unexpected_interface")
			}
			if transport, ok := o.Prober.(interface {
				Transport(context.Context, Route) (Route, string)
			}); ok {
				work, cancel = context.WithTimeout(ctx, timeout)
				t.TransportRoute, t.RelayPeerFingerprint = transport.Transport(work, t.Route)
				cancel()
			}
			s.Targets[i] = t
		}()
	}
	workers.Wait()
	s.Underlay = Down("no_uplink")
	for _, l := range s.Links {
		if l.State == "up" {
			s.Underlay = Up()
			break
		}
		if l.State == "unknown" {
			s.Underlay = Unknown("collector_unavailable")
		}
	}
	// Reconcile the configured link set before classifying any target.
	for _, t := range s.Targets {
		if t.Service.State == "up" && s.Underlay.State == "down" {
			s.Underlay = Unknown("unlisted_uplink")
		}
	}
	for i, t := range s.Targets {
		stage := "unknown"
		switch {
		case t.Service.State == "up":
			stage = "none"

		case s.Underlay.State == "down":
			stage = "underlay"
		case t.Route.State == "down":
			stage = "overlay_route"
		case t.Relay.State == "down":
			stage = "relay_tunnel"
		case t.Service.State == "down":
			stage = "server_endpoint"
		}
		// Controller failure is reported independently per link. A controller is
		// not a prerequisite for an already configured tunnel/target to work.
		s.Targets[i].FailureStage = stage
	}
	s.At = time.Now().UTC().Truncate(time.Microsecond)
	return s
}
