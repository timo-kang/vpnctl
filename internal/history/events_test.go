// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpnctl/internal/uplink"
)

func TestEventTimelineIdempotencyAndAlerts(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	first := uplinkFixture(now.Add(-2*time.Second), "event-one")
	if err := s.IngestUplink(ctx, "robot", first, now); err != nil {
		t.Fatal(err)
	}
	second := uplinkFixture(now.Add(-time.Second), "event-two")
	second.Underlay = uplink.Down("no_default_route")
	second.Targets[0].Service = uplink.Down("timeout")
	second.Targets[0].FailureStage = "server_endpoint"
	second.Targets[0].Relay = uplink.Down("relay_unreachable")
	if err := s.IngestUplink(ctx, "robot", second, now); err != nil {
		t.Fatal(err)
	}
	history, err := s.QueryEvents(ctx, "robot", now, time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Events) < 4 || history.Events[0].Timestamp.Before(history.Events[1].Timestamp) {
		t.Fatalf("events not newest first: %+v", history.Events)
	}
	seen := map[string]bool{}
	for _, event := range history.Events {
		seen[event.Kind] = true
	}
	for _, kind := range []string{"uplink_change", "route_change", "relay_failover", "probe_error"} {
		if !seen[kind] {
			t.Fatalf("missing %s event: %+v", kind, history.Events)
		}
	}
	alerts, err := s.Alerts(ctx, "robot", now)
	if err != nil {
		t.Fatal(err)
	}
	active := map[string]bool{}
	for _, alert := range alerts {
		active[alert.Code] = alert.Active
	}
	if !active["no_uplink"] || active["persistent_loss"] || !active["relay_failure"] {
		t.Fatalf("alerts=%+v", alerts)
	}

	explicit := Event{Timestamp: now.Add(-500 * time.Millisecond), Kind: "certificate", Source: "agent", Severity: "warning", Validity: "observed", Message: "renewal_due"}
	if err := s.IngestEvent(ctx, "robot", explicit, now); err != nil {
		t.Fatal(err)
	}
	// A generated ID makes the same payload retry safe; a caller-supplied ID
	// protects integrations from accidentally reusing it with different data.
	explicit.ID = "certificate-1"
	if err := s.IngestEvent(ctx, "robot", explicit, now); err != nil {
		t.Fatal(err)
	}
	if err := s.IngestEvent(ctx, "robot", explicit, now); err != nil {
		t.Fatal(err)
	}
	explicit.Message = "different"
	if !errors.Is(s.IngestEvent(ctx, "robot", explicit, now), ErrConflict) {
		t.Fatal("event ID reuse was accepted")
	}
}

func TestEventRetentionAndQueryLimit(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		e := Event{ID: string(rune('a' + i)), Timestamp: now.Add(-time.Duration(i+1) * time.Second), Kind: "nat_remap", Source: "agent", Severity: "info", Validity: "observed"}
		if err := s.IngestEvent(ctx, "robot", e, now); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.QueryEvents(ctx, "robot", now, time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Events) != 2 || !h.Truncated {
		t.Fatalf("history=%+v", h)
	}
	if err := s.Maintain(ctx, now.Add(Retention)); err != nil {
		t.Fatal(err)
	}
	h, err = s.QueryEvents(ctx, "robot", now.Add(Retention), Retention, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Events) != 0 {
		t.Fatalf("expired events retained: %+v", h.Events)
	}
}
