// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"context"
	"sync"
	"testing"
)

func TestConcurrentCostAccountingAndSnapshotIsolation(t *testing.T) {
	ctx, r := Start(context.Background())
	_, same := Start(ctx)
	if same != r {
		t.Fatal("nested observation discarded accounting")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, done := Phase(ctx, "probe")
			defer done()
			for i := 0; i < 20; i++ {
				Command(ctx, i%2 == 0)()
			}
		}()
	}
	wg.Wait()
	first := r.Snapshot()
	p := first.Phases["probe"]
	if p.Calls != 8 || p.KernelCommands != 80 || p.InventoryCommands != 80 || p.Duration <= 0 || p.CommandDuration <= 0 || first.Elapsed <= 0 || !first.BootAvailable || first.BootElapsed <= 0 {
		t.Fatal(first, p)
	}
	first.Phases["probe"] = PhaseCost{}
	if r.Snapshot().Phases["probe"].Calls != 8 {
		t.Fatal("snapshot aliases mutable accounting")
	}
	// Uninstrumented supervisor work does not acquire hidden process-wide state.
	other, done := Phase(context.Background(), "maintenance")
	Command(other, false)()
	done()
	if len(r.Snapshot().Phases) != 1 {
		t.Fatal("unrelated operation leaked into observation")
	}
}
