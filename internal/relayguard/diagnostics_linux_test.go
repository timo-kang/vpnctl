// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"context"
	"errors"
	"testing"

	"vpnctl/internal/relayobserve"
)

func TestGuardDiagnosticsPreserveEarlyCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, recorder := relayobserve.Start(parent)
	if _, err := Update(ctx, Owner{}, 0, 0, 0); !errors.Is(err, context.Canceled) {
		t.Fatal("changed cancellation", err)
	}
	if _, err := Read(ctx, Owner{}); !errors.Is(err, context.Canceled) {
		t.Fatal("changed read cancellation", err)
	}
	d := recorder.Snapshot()
	if d.Phases["lease_guard_update"].Calls != 1 || d.Phases["lease_guard_inventory"].Calls != 2 || d.Phases["lease_guard_load"].Calls != 0 || d.Phases["lease_guard_test"].Calls != 0 {
		t.Fatal("early failure accounting or unexpected kernel load", d.Phases)
	}
	for _, p := range d.Phases {
		if p.Duration <= 0 || p.KernelCommands != 0 || p.InventoryCommands != 0 {
			t.Fatal("invalid syscall-only cost", p)
		}
	}
}
