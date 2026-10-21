// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictorinput

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"vpnctl/internal/uplink"
)

var serviceScope = ServiceStream{NodeID: "robot", TargetID: "server", Protocol: "tcp"}

func serviceSnapshot() uplink.Snapshot {
	return uplink.Snapshot{ID: "cycle", At: tick, IntervalSec: 60, Underlay: uplink.Up(), Dropped: 3,
		Links:   []uplink.Link{{ID: "lan", Interface: "eth0", Kind: "ethernet", Check: uplink.Up(), Modem: uplink.Unknown("not_configured"), GatewayState: uplink.Up(), DNS: uplink.Up(), Controller: uplink.Up(), ControllerRoute: uplink.Route{Check: uplink.Up()}}},
		Targets: []uplink.Target{{ID: "server", Protocol: "tcp", Route: uplink.Route{Check: uplink.Up()}, TransportRoute: uplink.Route{Check: uplink.Unknown("not_observed")}, Relay: uplink.Unknown("not_configured"), Service: uplink.Check{State: "up", RTTMs: ptr(0.0)}, FailureStage: "none", ServiceStartedAt: ptr(tick.Add(-2 * time.Second)), ServiceCompletedAt: ptr(tick.Add(-time.Second))}}}
}

func TestUplinkServiceEvidenceStates(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		mutate                   func(*uplink.Snapshot)
		state, reason            string
		ready, success, duration bool
	}{
		{"zero", func(*uplink.Snapshot) {}, "observed", "", true, true, true},
		{"failure", func(s *uplink.Snapshot) { s.Targets[0].Service = uplink.Down("service_refused") }, "observed", "service_refused", true, false, false},
		{"unknown", func(s *uplink.Snapshot) { s.Targets[0].Service = uplink.Unknown("trust_unavailable") }, "unknown", "trust_unavailable", false, false, false},
		{"unknown-no-reason", func(s *uplink.Snapshot) { s.Targets[0].Service = uplink.Unknown("") }, "unknown", "service_unknown", false, false, false},
		{"legacy", func(s *uplink.Snapshot) { s.Targets[0].ServiceStartedAt, s.Targets[0].ServiceCompletedAt = nil, nil }, "missing", "service_time_unavailable", false, false, false},
		{"target-absent", func(s *uplink.Snapshot) { s.Targets[0].ID = "other" }, "missing", "target_not_collected", false, false, false},
		{"source-stale", func(s *uplink.Snapshot) { s.Stale = true }, "stale", "service_expired", false, false, false},
		{"expiry-equality", func(s *uplink.Snapshot) { s.Targets[0].ServiceStartedAt = ptr(tick.Add(-5 * time.Second)) }, "stale", "service_expired", false, false, false},
		{"long-attempt-fresh-completion", func(s *uplink.Snapshot) {
			s.Targets[0].ServiceStartedAt = ptr(tick.Add(-10 * time.Second))
			s.Targets[0].ServiceCompletedAt = ptr(tick)
		}, "stale", "service_expired", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := serviceSnapshot()
			tc.mutate(&s)
			got, err := BuildUplinkService(serviceScope, s, tick, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got.Feature.State != tc.state || got.Feature.Reason != tc.reason || got.Ready != tc.ready || (got.Success != nil) != tc.ready || (got.DurationMS != nil) != tc.duration {
				t.Fatalf("%+v", got)
			}
			if got.Success != nil && *got.Success != tc.success {
				t.Fatal("failure fabricated/lost")
			}
			if got.DurationMS != nil && *got.DurationMS != 0 {
				t.Fatal("valid zero lost")
			}
			if got.Feature.Source != "uplink-service" || got.Stream != serviceScope || got.Dropped != 3 || got.IntervalSec != 60 {
				t.Fatal("provenance lost", got)
			}
			if got.Feature.State == "missing" && got.Feature.AgeNS != nil {
				t.Fatal("invented event age")
			}
		})
	}
}

func TestUplinkServiceProtocolsDetachedReplayAndAging(t *testing.T) {
	for _, tc := range []struct{ protocol, kind string }{{"tcp", "tcp_connect"}, {"tls", "tcp_connect_tls_handshake"}, {"udp-echo", "udp_socket_echo"}} {
		t.Run(tc.protocol, func(t *testing.T) {
			s, stream := serviceSnapshot(), serviceScope
			s.Targets[0].Protocol, stream.Protocol = tc.protocol, tc.protocol
			*s.Targets[0].ServiceStartedAt = s.Targets[0].ServiceStartedAt.In(time.FixedZone("fixture", 9*3600))
			before, _ := json.Marshal(s)
			got, err := BuildUplinkService(stream, s, tick, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got.DurationKind != tc.kind || *got.Feature.AgeNS != int64(2*time.Second) || got.Feature.ObservedAt.Location() != time.UTC || !got.CompletedAt.Equal(tick.Add(-time.Second)) {
				t.Fatalf("%+v", got)
			}
			replay, err := BuildUplinkService(stream, s, tick, 5*time.Second)
			if err != nil || !reflect.DeepEqual(got, replay) {
				t.Fatal("non-deterministic replay", err)
			}
			after, _ := json.Marshal(s)
			if string(before) != string(after) {
				t.Fatal("builder mutated input")
			}
			aged, err := BuildUplinkService(stream, s, tick.Add(3*time.Second), 5*time.Second)
			if err != nil || aged.Ready || aged.Feature.State != "stale" || aged.DurationMS != nil || aged.Success != nil {
				t.Fatal("read refreshed measurement", aged, err)
			}
			*s.Targets[0].ServiceStartedAt = tick
			*s.Targets[0].Service.RTTMs = 999
			*got.CompletedAt = tick
			*got.DurationMS = 999
			if *replay.DurationMS != 0 || !replay.Feature.ObservedAt.Equal(tick.Add(-2*time.Second)) || !replay.CompletedAt.Equal(tick.Add(-time.Second)) {
				t.Fatal("output aliases input or another result")
			}
		})
	}
}

func TestUplinkServiceRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*uplink.Snapshot)
	}{
		{"future-nanos", func(s *uplink.Snapshot) { s.At = tick.Add(time.Nanosecond) }},
		{"after-cycle", func(s *uplink.Snapshot) { s.Targets[0].ServiceCompletedAt = ptr(tick.Add(time.Nanosecond)) }},
		{"partial-time", func(s *uplink.Snapshot) { s.Targets[0].ServiceStartedAt = nil }},
		{"reverse-time", func(s *uplink.Snapshot) { s.Targets[0].ServiceStartedAt = ptr(tick) }},
		{"protocol-change", func(s *uplink.Snapshot) { s.Targets[0].Protocol = "tls" }},
		{"nan", func(s *uplink.Snapshot) { s.Targets[0].Service.RTTMs = ptr(math.NaN()) }},
		{"inf", func(s *uplink.Snapshot) { s.Targets[0].Service.RTTMs = ptr(math.Inf(1)) }},
		{"negative", func(s *uplink.Snapshot) { s.Targets[0].Service.RTTMs = ptr(-1.0) }},
		{"too-large", func(s *uplink.Snapshot) { s.Targets[0].Service.RTTMs = ptr(60001.0) }},
		{"duplicate-target", func(s *uplink.Snapshot) { s.Targets = append(s.Targets, s.Targets[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := serviceSnapshot()
			tc.mutate(&s)
			if _, err := BuildUplinkService(serviceScope, s, tick, 5*time.Second); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid evidence accepted", err)
			}
		})
	}
	for _, age := range []time.Duration{0, -1, MaxWindow + 1} {
		if _, err := BuildUplinkService(serviceScope, serviceSnapshot(), tick, age); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid maxAge accepted", age, err)
		}
	}
	for _, stream := range []ServiceStream{{"", "server", "tcp"}, {"robot\n", "server", "tcp"}, {"robot", "--target", "tcp"}, {"robot", "server", "http"}} {
		if _, err := BuildUplinkService(stream, serviceSnapshot(), tick, time.Second); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid scope accepted", stream, err)
		}
	}
}

func TestUplinkServiceHonorsSourceExpiryWithoutQueryFlag(t *testing.T) {
	s := serviceSnapshot()
	s.IntervalSec = 30
	s.At = tick.Add(-90 * time.Second)
	s.Targets[0].ServiceStartedAt = ptr(s.At)
	s.Targets[0].ServiceCompletedAt = ptr(s.At)
	got, err := BuildUplinkService(serviceScope, s, tick, 2*time.Minute)
	if err != nil || got.Ready || got.Feature.State != "stale" || got.Success != nil {
		t.Fatal("maxAge revived expired source", got, err)
	}
}
