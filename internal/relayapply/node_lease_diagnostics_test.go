// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"

	"vpnctl/internal/relayobserve"
)

type measuredNodeLease struct{ *fakeNodeLease }

func (k measuredNodeLease) Check(ctx context.Context, e Entry, fresh bool) (bool, error) {
	relayobserve.Command(ctx, false)()
	return k.fakeNodeLease.Check(ctx, e, fresh)
}
func (k measuredNodeLease) Lease(ctx context.Context, e Entry, fresh FreshApproval) (DeploymentLease, error) {
	relayobserve.Command(ctx, false)()
	return k.fakeNodeLease.Lease(ctx, e, fresh)
}
func (k measuredNodeLease) Block(ctx context.Context, e Entry) error {
	relayobserve.Command(ctx, false)()
	return k.fakeNodeLease.Block(ctx, e)
}

// The additional timers must cover failed operations too, without moving the
// existing command accounting out of maintenance or changing fail-closed work.
func TestNodeMaintenanceBreakdownPreservesCommandsAndFailures(t *testing.T) {
	for _, fault := range []string{"none", "approval", "kernel", "renewal"} {
		t.Run(fault, func(t *testing.T) {
			e, k, _ := nodeLeaseFixture(t)
			for _, id := range []string{"p0", "p1"} {
				if _, err := e.PrepareProtected(context.Background(), id, "", true); err != nil {
					t.Fatal(err)
				}
			}
			e.backend = measuredNodeLease{k}
			checks, renewals, commands := 2, 2, 4
			switch fault {
			case "approval":
				e.uncertain = true
				checks, renewals, commands = 0, 0, 2
			case "kernel":
				k.foreign = true
				renewals = 0
			case "renewal":
				k.failPath = "p0"
				commands = 5
			}
			ctx, recorder := relayobserve.Start(context.Background())
			out, err := e.MaintainLeases(ctx)
			if (err != nil) != (fault != "none") || out.KernelReady != (fault == "none") {
				t.Fatal("diagnostics changed outcome", out, err)
			}
			if fault == "renewal" && (!errors.Is(err, ErrConflict) || k.active["p0"] || !k.active["p1"]) {
				t.Fatal("renewal failure escaped or blocked independent candidate", out, err)
			}
			d := recorder.Snapshot()
			for name, calls := range map[string]int{
				"maintenance": 1, "maintenance_approval_plan": 1,
				"maintenance_consent": 2, "maintenance_kernel": checks,
				"maintenance_authority": renewals, "maintenance_renewal": renewals,
			} {
				p := d.Phases[name]
				if p.Calls != calls || calls > 0 && p.Duration <= 0 {
					t.Fatalf("missing %s boundary: %+v", name, d.Phases)
				}
			}
			if d.Phases["maintenance"].KernelCommands != commands {
				t.Fatal("parent command count changed", d.Phases)
			}
			for name, p := range d.Phases {
				if name != "maintenance" && (p.KernelCommands != 0 || p.InventoryCommands != 0 || p.CommandDuration != 0) {
					t.Fatal("nested timer stole command attribution", name, p)
				}
			}
		})
	}
}
