// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/relayobserve"
)

func TestCommandCostTracksReapedAndMissingChildrenWithoutSecrets(t *testing.T) {
	t.Setenv("VPNCTL_COST_DETAILS", "1")
	ctx, r := relayobserve.Start(context.Background())
	ctx, done := relayobserve.Phase(ctx, "maintenance")
	for _, script := range []string{"exit 0", "echo secret-private-key >&2; exit 2"} {
		_, _ = command(ctx, "secret-private-key", "sh", "-c", script)
	}
	_, _ = command(ctx, "secret-private-key", "/nonexistent-vpnctl-secret-private-key")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = command(canceled, "secret-private-key", "sh", "-c", "exit 0")
	deadline, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	_, _ = command(deadline, "", "sleep", "10")
	stop()
	done()
	data, err := json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-private-key") {
		t.Fatal("command diagnostics exposed arguments or input")
	}
	var d struct {
		Details *struct {
			Commands map[string]struct {
				Calls          int
				CPUAvailable   int           `json:"cpu_available"`
				CPUUnavailable int           `json:"cpu_unavailable"`
				Wall           time.Duration `json:"summed_wall_ns"`
				User           time.Duration `json:"summed_user_cpu_ns"`
				System         time.Duration `json:"summed_system_cpu_ns"`
			}
		}
	}
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if d.Details == nil {
		t.Fatal("opt-in command CPU evidence missing")
	}
	var calls, available, missing int
	for _, p := range d.Details.Commands {
		calls += p.Calls
		available += p.CPUAvailable
		missing += p.CPUUnavailable
		if p.Wall <= 0 || p.User < 0 || p.System < 0 {
			t.Fatal(p)
		}
	}
	if calls != 5 || available != 3 || missing != 2 {
		t.Fatalf("calls=%d available=%d missing=%d", calls, available, missing)
	}
	if p := r.Snapshot().Phases["maintenance"]; p.KernelCommands != 5 || p.Calls != 1 {
		t.Fatal("legacy accounting changed", p)
	}
}
