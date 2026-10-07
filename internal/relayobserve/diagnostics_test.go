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

func TestCheckpointClockOrderingBoundsAndIsolation(t *testing.T) {
	ctx, r := Start(context.Background())
	_, nested := Start(ctx)
	if nested != r {
		t.Fatal("nested cycle lost clock domain")
	}
	for i := 0; i < MaxCheckpoints+1; i++ {
		Mark(ctx, "decision_complete")
	}
	d := r.Snapshot()
	if !d.MonotonicAvailable || d.StartedMono <= 0 || d.FinishedMono < d.StartedMono || !d.CheckpointsDropped || len(d.Checkpoints) != MaxCheckpoints {
		t.Fatal(d)
	}
	last := d.StartedMono
	for _, e := range d.Checkpoints {
		if e.At < last || e.At > d.FinishedMono {
			t.Fatal("checkpoint outside its monotonic cycle", e, d)
		}
		last = e.At
	}
	d.Checkpoints[0].Name = "changed"
	if r.Snapshot().Checkpoints[0].Name != "decision_complete" {
		t.Fatal("checkpoint snapshot aliases recorder")
	}
	Mark(context.Background(), "unrelated")
	if len(r.Snapshot().Checkpoints) != MaxCheckpoints {
		t.Fatal("unrelated operation changed checkpoints")
	}
}
