// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"testing"
	"vpnctl/internal/relayobserve"
)

func TestDetailedMaintenancePreservesIndependentRenewalAndConflictBlocking(t *testing.T) {
	for _, mode := range []string{"0", "1"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("VPNCTL_COST_DETAILS", mode)
			e, k := waveFixture(t)
			ctx, r := relayobserve.Start(context.Background())
			out, err := e.MaintainLeases(ctx)
			if err != nil || !out.KernelReady || k.renewals != 8 {
				t.Fatal(out, err, k.renewals)
			}
			if mode == "1" {
				d := r.Snapshot().Details
				for name, want := range map[string]int{"maintenance_approval": 1, "maintenance_plan": 1, "maintenance_eligibility": 8, "maintenance_kernel": 8, "maintenance_authority": 8, "maintenance_lease": 8} {
					if d.Steps[name].Calls != want {
						t.Fatal(name, d.Steps)
					}
				}
			} else if r.Snapshot().Details != nil {
				t.Fatal("details enabled in control")
			}
			k.failPath = "p0"
			ctx, r = relayobserve.Start(context.Background())
			out, err = e.MaintainLeases(ctx)
			if err == nil || out.KernelReady || k.active["p0"] || !k.active["p7"] || k.renewals != 15 {
				t.Fatal("fault no longer isolated", out, err, k.renewals)
			}
			if mode == "1" && r.Snapshot().Details.Steps["maintenance_block"].Calls != 1 {
				t.Fatal(r.Snapshot())
			}
			k.foreign = true
			ctx, r = relayobserve.Start(context.Background())
			_, err = e.MaintainLeases(ctx)
			if err == nil || k.renewals != 15 {
				t.Fatal("foreign state renewed", err, k.renewals)
			}
			for _, active := range k.active {
				if active {
					t.Fatal("conflict did not block")
				}
			}
			if mode == "1" && (r.Snapshot().Details.Steps["maintenance_block"].Calls != 8 || r.Snapshot().Details.Steps["maintenance_lease"].Calls != 0) {
				t.Fatal(r.Snapshot())
			}
		})
	}
}
