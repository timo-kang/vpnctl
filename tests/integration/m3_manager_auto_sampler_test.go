//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"
	"vpnctl/internal/relayobserve"
)

// Host-safe: net.Pipe uses no kernel interface or network configuration.
func TestManagerStreamRetainsPartialFrameAcrossTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	finished := make(chan error, 1)
	go func() {
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(server, nonce); err != nil {
			finished <- err
			return
		}
		if _, err := server.Write([]byte("198.18.0")); err != nil {
			finished <- err
			return
		}
		time.Sleep(450 * time.Millisecond)
		if _, err := server.Write(append([]byte(".11:1234\n"), nonce[:3]...)); err != nil {
			finished <- err
			return
		}
		time.Sleep(450 * time.Millisecond)
		_, err := server.Write(nonce[3:])
		finished <- err
	}()
	stream := managerStream{c: client, reader: bufio.NewReader(client)}
	for i := 0; i < 2; i++ {
		_, err := stream.exchange()
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("expected timeout %d: %v", i, err)
		}
	}
	sent := stream.sentAt
	source, err := stream.exchange()
	if err != nil || source != "198.18.0.11" || stream.sentAt != sent {
		t.Fatalf("lost pending frame: %q %v", source, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestManagerStreamRejectsCorruptNonce(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(server, nonce); err == nil {
			nonce[0] ^= 1
			server.Write(append([]byte("198.18.0.11:1234\n"), nonce...))
		}
	}()
	stream := managerStream{c: client, reader: bufio.NewReader(client)}
	if _, err := stream.exchange(); !errors.Is(err, errManagerProtocol) {
		t.Fatalf("corruption treated as outage: %v", err)
	}
	if _, err := stream.exchange(); !errors.Is(err, errManagerProtocol) {
		t.Fatalf("fatal corruption not retained: %v", err)
	}
}

func TestManagerTimelineKeepsPostFaultCheckpointsFromInflightCycle(t *testing.T) {
	cycles := []managerAutoCycle{{Target: "app", Path: "p01", Applied: true, Diagnostics: &relayobserve.Diagnostics{
		StartedMono: 50, FinishedMono: 130, Checkpoints: []relayobserve.Checkpoint{
			{Name: "observation_complete", At: 100}, {Name: "decision_complete", At: 110}, {Name: "target_routes_applied", At: 120},
		},
	}}}
	packets := []managerAutoEvent{
		{Kind: "tcp-new", Begin: 70, End: 80, OK: true, Source: "198.18.0.11"},
		{Kind: "tcp-new", Begin: 85, End: 95, OK: false},
		{Kind: "tcp-new", Begin: 100, End: 105, OK: true, Source: "198.18.0.11"},
		{Kind: "tcp-new", Begin: 125, End: 127, OK: true, Source: "198.18.0.11"},
	}
	v := managerTimeline(packets, cycles, "p00", "p01", "198.18.0.11", 90)
	if v["decision_complete"] != 110 || v["routes_completed"] != 120 || v["first_success"] != 127 || v["first_failure"] != 95 || v["last_success_before_fault"] != 80 {
		t.Fatal(v)
	}
	// Failed application and the other target's checkpoints cannot establish
	// successful route application even when packets happen to be flowing.
	for _, mutate := range []func(){func() { cycles[0].Applied = false }, func() { cycles[0].Applied = true; cycles[0].Target = "app2" }} {
		mutate()
		v = managerTimeline(packets, cycles, "p00", "p01", "198.18.0.11", 90)
		if v["routes_completed"] != 0 {
			t.Fatal("unrelated/failed application qualified", v)
		}
		wantDecision := int64(110)
		if cycles[0].Target != "app" {
			wantDecision = 0
		}
		if v["decision_complete"] != wantDecision {
			t.Fatal("decision confused with application", v)
		}
	}
}

func TestManagerTimelineKeepsQuarantineBeforeNoPathDecision(t *testing.T) {
	cycles := []managerAutoCycle{
		{Target: "app", Path: "p11", Guarded: true, Diagnostics: &relayobserve.Diagnostics{StartedMono: 50, FinishedMono: 125, Checkpoints: []relayobserve.Checkpoint{
			{Name: "decision_complete", At: 110}, {Name: "candidate_revalidation_failed", At: 115}, {Name: "target_routes_blocked", At: 120},
		}}},
		{Target: "app", Guarded: true, Diagnostics: &relayobserve.Diagnostics{StartedMono: 130, FinishedMono: 145, Checkpoints: []relayobserve.Checkpoint{{Name: "decision_complete", At: 140}}}},
	}
	got := managerTimeline(nil, cycles, "p11", "", "", 90)
	if got["detection_complete"] != 115 || got["routes_completed"] != 120 || got["decision_complete"] != 140 {
		t.Fatal("lost earlier safety quarantine", got)
	}
}

func TestManagerTimelineFirstAlternativePrecedesPreferredRecovery(t *testing.T) {
	cycles := []managerAutoCycle{
		{Target: "app", Path: "p02", Applied: true, Diagnostics: &relayobserve.Diagnostics{StartedMono: 50, FinishedMono: 130, Checkpoints: []relayobserve.Checkpoint{{Name: "decision_complete", At: 110}, {Name: "target_routes_applied", At: 120}}}},
		{Target: "app", Path: "p01", Applied: true, Diagnostics: &relayobserve.Diagnostics{StartedMono: 180, FinishedMono: 210, Checkpoints: []relayobserve.Checkpoint{{Name: "decision_complete", At: 190}, {Name: "target_routes_applied", At: 200}}}},
	}
	packets := []managerAutoEvent{
		{Kind: "tcp-new", Begin: 100, End: 105, OK: true, Source: "198.18.0.11"}, // before a fresh apply
		{Kind: "tcp-new", Begin: 125, End: 127, OK: true, Source: "198.18.0.11"},
		{Kind: "tcp-new", Begin: 205, End: 207, OK: true, Source: "198.18.0.11"},
	}
	sources := map[string]string{"p00": "198.18.0.11", "p01": "198.18.0.11", "p02": "198.18.0.11"}
	path, got := managerFailoverTimeline(packets, cycles, "p00", sources, 90)
	if path != "p02" || got["first_success"] != 127 || got["routes_completed"] != 120 || got["decision_complete"] != 110 {
		t.Fatal("preferred dwell counted as failover", path, got)
	}
	// The relay source is identical for both underlays. A reply after p01's
	// apply cannot be credited to p02 merely because its SNAT source matches.
	path, got = managerFailoverTimeline([]managerAutoEvent{packets[0], packets[2]}, cycles, "p00", sources, 90)
	if path != "p01" || got["first_success"] != 207 || got["routes_completed"] != 200 {
		t.Fatal("later same-relay reply credited to an earlier path", path, got)
	}
	// A failed apply, unrelated application or unknown source/path is not proof.
	for _, mutate := range []func([]managerAutoCycle){
		func(c []managerAutoCycle) { c[0].Applied = false },
		func(c []managerAutoCycle) { c[0].Target = "app2" },
		func(c []managerAutoCycle) { c[0].Path = "unapproved" },
	} {
		changed := append([]managerAutoCycle(nil), cycles...)
		mutate(changed)
		path, got = managerFailoverTimeline(packets, changed, "p00", sources, 90)
		if path != "p01" || got["first_success"] != 207 {
			t.Fatal("invalid alternative qualified", path, got)
		}
	}
	// p02's reply after a quarantine cannot be attributed to its earlier apply.
	blocked := append(append([]managerAutoCycle(nil), cycles...), managerAutoCycle{Target: "app", Guarded: true, Diagnostics: &relayobserve.Diagnostics{StartedMono: 121, FinishedMono: 124, Checkpoints: []relayobserve.Checkpoint{{Name: "target_routes_blocked", At: 123}}}})
	path, got = managerFailoverTimeline(packets, blocked, "p00", sources, 90)
	if path != "p01" || got["first_success"] != 207 {
		t.Fatal("reply after quarantine qualified", path, got)
	}
	path, got = managerFailoverTimeline(packets, cycles, "p00", map[string]string{"p01": "198.18.0.12", "p02": "198.18.0.12"}, 90)
	if path != "" || got["first_success"] != 0 || got["routes_completed"] != 0 {
		t.Fatal("wrong relay source qualified", path, got)
	}
}
