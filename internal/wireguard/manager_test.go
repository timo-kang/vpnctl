// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vpnctl/internal/config"
	"vpnctl/internal/execx"
)

type recordRunner struct {
	cmds []string
}

func (r *recordRunner) Run(name string, args ...string) error {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return nil
}

func (r *recordRunner) Output(name string, args ...string) (string, error) { return "", nil }

var _ execx.Runner = (*recordRunner)(nil)

func TestManagerUp_InstallsPolicyBaselineRoute(t *testing.T) {
	t.Parallel()

	rr := &recordRunner{}
	m := NewManager(rr)

	enabled := true
	cfg := config.NodeConfig{
		WGInterface:           "wg0",
		VPNIP:                 "10.7.0.2/32",
		MTU:                   1280,
		ServerAllowedIPs:      []string{"10.7.0.0/24"},
		PolicyRoutingEnabled:  &enabled,
		PolicyRoutingTable:    51820,
		PolicyRoutingPriority: 1000,
		PolicyRoutingCIDR:     "10.7.0.0/24",
	}

	if err := m.Up(cfg, "[Interface]\nPrivateKey = x\n"); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// This is the critical regression check: rule should not capture traffic into an empty table.
	want := "ip route replace 10.7.0.0/24 dev wg0 table 51820"
	found := false
	for _, c := range rr.cmds {
		if c == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing baseline route command; cmds=%v", rr.cmds)
	}
}

func TestCanceledManagerDoesNotMutateOrCancelOriginal(t *testing.T) {
	runner := &recordRunner{}
	manager := NewManager(runner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	disabled := false
	cfg := config.NodeConfig{WGInterface: "test-wg", VPNIP: "10.7.0.2/32", PolicyRoutingEnabled: &disabled}
	if err := manager.WithContext(ctx).Up(cfg, "[Interface]\n"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(runner.cmds) != 0 {
		t.Fatal("canceled operation mutated kernel")
	}
	if err := manager.Up(cfg, "[Interface]\n"); err != nil {
		t.Fatal("original manager inherited cancellation", err)
	}
}
