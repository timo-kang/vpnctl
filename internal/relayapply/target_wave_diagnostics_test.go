// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

func TestObservationWaveCheckpointsJoinWorkers(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "completed"
		if canceled {
			name = "canceled"
		}
		t.Run(name, func(t *testing.T) {
			e, _ := waveFixture(t)
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, recorder := relayobserve.Start(parent)
			entered, release := make(chan struct{}, 8), make(chan struct{})
			done := make(chan TargetReport, 1)
			go func() {
				out, _ := e.observeTarget(ctx, "app", "", 2*time.Second, func(ctx context.Context, _ Entry, _ relaycatalog.Target) (targetProof, error) {
					entered <- struct{}{}
					select {
					case <-release:
						return targetProof{handshake: 1, rx: 1, tx: 1}, nil
					case <-ctx.Done():
						return targetProof{}, ctx.Err()
					}
				})
				done <- out
			}()
			// Always join the worker, including when an assertion fails.
			joined := false
			defer func() {
				cancel()
				if !joined {
					<-done
				}
			}()
			for i := 0; i < 8; i++ {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("probe failed to start")
				}
			}
			checkWaveMarks(t, recorder.Snapshot(), []string{"observation_maintenance_started", "observation_maintenance_complete", "observation_wave_started"})
			if canceled {
				cancel()
			} else {
				close(release)
			}
			out := <-done
			joined = true
			if out.Valid == canceled {
				t.Fatal("diagnostics changed cancellation/result validity")
			}
			checkWaveMarks(t, out.Diagnostics, []string{"observation_maintenance_started", "observation_maintenance_complete", "observation_wave_started", "observation_wave_complete"})
		})
	}
}

func checkWaveMarks(t *testing.T, d *relayobserve.Diagnostics, want []string) {
	t.Helper()
	if d == nil || !d.MonotonicAvailable || d.CheckpointsDropped || len(d.Checkpoints) != len(want) {
		t.Fatalf("incorrect wave boundaries: %+v", d)
	}
	previous := d.StartedMono
	for i, mark := range d.Checkpoints {
		if mark.Name != want[i] || mark.At < previous || mark.At > d.FinishedMono {
			t.Fatalf("invalid wave boundary: %+v", mark)
		}
		previous = mark.At
	}
}
