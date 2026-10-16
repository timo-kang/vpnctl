// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func TestDetailsPreserveParentAttributionAndConcurrentIsolation(t *testing.T) {
	t.Setenv("VPNCTL_COST_DETAILS", "1")
	ctx, r := Start(context.Background())
	ctx, finish := Phase(ctx, "maintenance")
	var wg sync.WaitGroup
	for _, name := range []string{"maintenance_kernel", "maintenance_lease"} {
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				work, done := Detail(ctx, name)
				defer done()
				Command(work, false)()
			}(name)
		}
	}
	wg.Wait()
	finish()
	d := r.Snapshot()
	if d.Phases["maintenance"].Calls != 1 || d.Phases["maintenance"].KernelCommands != 16 {
		t.Fatal(d)
	}
	for _, name := range []string{"maintenance_kernel", "maintenance_lease"} {
		p := d.Details.Steps[name]
		if p.Calls != 8 || p.KernelCommands != 8 || p.Duration <= 0 || p.CommandDuration <= 0 {
			t.Fatal(name, p)
		}
	}
	d.Details.Steps["maintenance_kernel"] = PhaseCost{}
	delete(d.Details.Commands, "maintenance/maintenance_kernel/other")
	if r.Snapshot().Details.Steps["maintenance_kernel"].Calls != 8 || len(r.Snapshot().Details.Commands) != 2 {
		t.Fatal("snapshot aliases mutable details")
	}
}

func TestDetailsAreOptInAndUnrelatedContextsStayUninstrumented(t *testing.T) {
	for _, value := range []string{"", "0", "true", "unexpected"} {
		t.Setenv("VPNCTL_COST_DETAILS", value)
		ctx, r := Start(context.Background())
		child, done := Detail(ctx, "maintenance_kernel")
		if child != ctx {
			t.Fatal("disabled detail allocated scope")
		}
		Command(child, false)()
		done()
		data, err := json.Marshal(r.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"details"`) || r.Snapshot().Phases["other"].KernelCommands != 1 {
			t.Fatal(string(data))
		}
	}
	t.Setenv("VPNCTL_COST_DETAILS", "1")
	ctx := context.Background()
	child, done := Detail(ctx, "maintenance_kernel")
	if child != ctx {
		t.Fatal("unrelated context instrumented")
	}
	ProcessCommand(child, false, "secret")(nil)
	done()
}

func TestChildCPUUsesActualProcessStateEvenForFailedExit(t *testing.T) {
	t.Setenv("VPNCTL_COST_DETAILS", "1")
	ctx, r := Start(context.Background())
	c := exec.Command("sh", "-c", "exit 3")
	done := ProcessCommand(ctx, false, "secret-path")
	if err := c.Run(); err == nil || c.ProcessState == nil {
		t.Fatal("expected reaped failure", err)
	}
	done(c.ProcessState)
	p := r.Snapshot().Details.Commands["other//other"]
	if p.Calls != 1 || p.CPUAvailable != 1 || p.CPUUnavailable != 0 || p.User != c.ProcessState.UserTime() || p.System != c.ProcessState.SystemTime() || p.Wall <= 0 || p.MaxWall != p.Wall {
		t.Fatal(p)
	}
}
