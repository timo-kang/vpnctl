//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"testing"
	"time"
	"vpnctl/internal/history"
)

func TestSoakReadinessRequiresPostFaultCurrentProducers(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	after := now.Add(-10 * time.Second)
	current := now.Add(-time.Second)
	healthy := func() soakObservation {
		v := soakObservation{Storage: history.StorageHealth{Validity: "observed"}, RegisteredNodes: 3, WGReports: 1, WGPeers: 3, WGPeerNodes: []string{"", "node-1", "replacement-2"}, WGObservedAt: &current, UplinkObservedAt: &current, UplinkSamples: 1, LatestUplinkStage: "none", Sources: map[string]int{"agent-direct": 2, "monitor-overlay": 2}}
		v.Delivery.WireGuardDelivery.Delivered = 1
		return v
	}
	peers := []string{"node-1", "replacement-2"}
	if e := checkSoakReady(healthy(), 3, peers, after, now); e != nil {
		t.Fatal(e)
	}
	tests := []struct {
		name string
		edit func(*soakObservation)
	}{
		{"pre-fault WG still fresh", func(v *soakObservation) { at := after.Add(-time.Second); v.WGObservedAt = &at }},
		{"pre-fault uplink still fresh", func(v *soakObservation) { at := after.Add(-time.Second); v.UplinkObservedAt = &at }},
		{"partial peer snapshot", func(v *soakObservation) { v.WGPeers = 1 }},
		{"old identity same count", func(v *soakObservation) { v.WGPeerNodes = []string{"", "node-1", "deleted-2"} }},
		{"unknown time", func(v *soakObservation) { v.UplinkObservedAt = nil }},
		{"future time", func(v *soakObservation) { at := now.Add(time.Second); v.WGObservedAt = &at }},
		{"heartbeat delayed", func(v *soakObservation) { v.HeartbeatMaxAgeSeconds = 31 }},
		{"heartbeat unknown", func(v *soakObservation) { v.HeartbeatUnknown = 1 }},
		{"storage stale", func(v *soakObservation) { v.Storage.Stale = true }},
		{"endpoint still down", func(v *soakObservation) { v.LatestUplinkStage = "server_endpoint" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := healthy()
			tc.edit(&v)
			if e := checkSoakReady(v, 3, peers, after, now); e == nil {
				t.Fatal("incomplete recovery accepted")
			}
		})
	}
	// Initial/final checks also reject stale snapshots without a fault cutoff.
	v := healthy()
	old := now.Add(-90 * time.Second)
	v.WGObservedAt = &old
	if e := checkSoakReady(v, 3, peers, time.Time{}, now); e == nil {
		t.Fatal("stale initial/final snapshot accepted")
	}
}

func TestSoakReadinessProfileMatchesCredentialCadence(t *testing.T) {
	for _, duration := range []time.Duration{12 * time.Minute, 24 * time.Hour} {
		p, e := resolveSoakProfile(duration, "auto")
		if e != nil {
			t.Fatal(e)
		}
		if duration >= 24*time.Hour && (p.cadence != 60 || p.caWait != 2*time.Minute || p.leaf != "1h") {
			t.Fatal(p)
		}
		if duration < 24*time.Hour && (p.cadence != 2 || p.caWait != 30*time.Second) {
			t.Fatal(p)
		}
	}
	p, e := resolveSoakProfile(20*time.Minute, "production")
	if e != nil || p.leaf != "1h" || p.cadence != 60 || p.caWait != 2*time.Minute {
		t.Fatal(p, e)
	}
	for _, s := range []string{"typo", "smoke"} {
		if _, e := resolveSoakProfile(24*time.Hour, s); e == nil {
			t.Fatal("invalid long profile accepted", s)
		}
	}
}
