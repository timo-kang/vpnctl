// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplink

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type gatedLinkCollector struct{ entered, release chan struct{} }

func (c gatedLinkCollector) Collect(ctx context.Context, cfg LinkConfig) Link {
	close(c.entered)
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return Link{ID: cfg.ID, Interface: cfg.Interface, Kind: cfg.Kind, Check: Up(),
		Modem: Unknown("not_configured"), GatewayState: Up(), DNS: Up()}
}

type gatedServiceProber struct {
	entered, release chan struct{}
	transportAt      time.Time
	service          Check
}

func (p *gatedServiceProber) Probe(context.Context, Endpoint, string) (Route, Check) {
	return Route{Check: Up(), Interface: "wg0"}, p.service
}
func (p *gatedServiceProber) Transport(ctx context.Context, _ Route) (Route, string) {
	p.transportAt = time.Now().UTC()
	close(p.entered)
	select {
	case <-p.release:
	case <-ctx.Done():
	}
	return Route{Check: Up(), Interface: "eth0"}, "peer"
}

func TestServiceTimingExcludesLaterCollection(t *testing.T) {
	for _, service := range []Check{{State: "up", RTTMs: ptr(0.0)}, Down("service_refused"), Unknown("canceled")} {
		t.Run(service.State, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cfg := fixtureConfig()
			cfg.TimeoutMS = 1000
			cfg.Controller, cfg.Targets[0].RelayProbe = nil, nil
			link := gatedLinkCollector{make(chan struct{}), make(chan struct{})}
			prober := &gatedServiceProber{entered: make(chan struct{}), release: make(chan struct{}), service: service}
			done := make(chan Snapshot, 1)
			before := time.Now().UTC().Truncate(time.Microsecond)
			go func() { done <- (Observer{cfg, link, prober}).Collect(ctx) }()
			for _, entered := range []chan struct{}{link.entered, prober.entered} {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("collector did not reach barrier")
				}
			}
			select {
			case <-done:
				t.Fatal("cycle did not wait for pending workers")
			default:
			}
			close(link.release)
			close(prober.release)
			var snapshot Snapshot
			select {
			case snapshot = <-done:
			case <-ctx.Done():
				t.Fatal("collector failed to finish")
			}
			// Decode the wire fields so the original implementation fails on
			// behavior (missing event times), not a missing Go field.
			data, err := json.Marshal(snapshot.Targets[0])
			if err != nil {
				t.Fatal(err)
			}
			var target struct {
				Started   *time.Time `json:"service_started_at"`
				Completed *time.Time `json:"service_completed_at"`
			}
			if err := json.Unmarshal(data, &target); err != nil {
				t.Fatal(err)
			}
			if target.Started == nil || target.Completed == nil {
				t.Fatal("service attempt timing missing; cycle time cannot describe an earlier result")
			}
			if target.Started.Before(before) || target.Completed.Before(*target.Started) || target.Completed.After(prober.transportAt) || snapshot.At.Before(prober.transportAt.Truncate(time.Microsecond)) {
				t.Fatalf("invalid measurement/cycle ordering: %s %s transport=%s cycle=%s", target.Started, target.Completed, prober.transportAt, snapshot.At)
			}
			if err := snapshot.Validate(time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type cancelServiceProber struct{ entered chan struct{} }

func (p cancelServiceProber) Probe(ctx context.Context, _ Endpoint, _ string) (Route, Check) {
	close(p.entered)
	<-ctx.Done()
	return Route{Check: Unknown("canceled")}, Unknown("canceled")
}

func TestServiceTimingCanceledProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cfg := fixtureConfig()
	cfg.Controller, cfg.Targets[0].RelayProbe = nil, nil
	link := gatedLinkCollector{make(chan struct{}), make(chan struct{})}
	close(link.release)
	prober := cancelServiceProber{make(chan struct{})}
	done := make(chan Snapshot, 1)
	go func() { done <- (Observer{cfg, link, prober}).Collect(ctx) }()
	select {
	case <-prober.entered:
	case <-ctx.Done():
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case snapshot := <-done:
		target := snapshot.Targets[0]
		if target.Service.State != "unknown" || target.Service.Reason != "canceled" || target.ServiceStartedAt == nil || target.ServiceCompletedAt == nil {
			t.Fatal("cancellation lost observation interval", target)
		}
		if err := snapshot.Validate(time.Now()); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled collector did not finish")
	}
}
