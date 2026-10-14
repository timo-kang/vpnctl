// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpnctl/internal/relayobserve"
)

// Real flock contention must be attributed to the layer that waited. A failed
// admission must not claim that a later layer was opened or that work began.
func TestAdmissionDiagnosticsSeparateQueueAndCacheContention(t *testing.T) {
	for _, queued := range []bool{false, true} {
		name := "cache"
		if queued {
			name = "queue"
		}
		t.Run(name, func(t *testing.T) {
			dir := privateTempDir(t)
			openCache(t, dir).Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var holder *Store
			var err error
			if queued {
				holder, err = OpenQueued(ctx, dir, Options{NodeID: "robot"})
			} else {
				holder, err = Open(dir, Options{NodeID: "robot"})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Close()
			limit, wantErr := 75*time.Millisecond, context.DeadlineExceeded
			if !queued {
				limit, wantErr = 3*time.Second, context.Canceled
			}
			short, stop := context.WithTimeout(ctx, limit)
			defer stop()
			measured, recorder := relayobserve.Start(short)
			if !queued {
				defer cancelCacheAdmissionAtCheckpoint(measured, stop, recorder, "admission_queue_ready")()
			}
			if s, err := OpenQueued(measured, dir, Options{NodeID: "robot"}); s != nil || !errors.Is(err, wantErr) {
				t.Fatalf("contention escaped: store=%v error=%v", s != nil, err)
			}
			d := recorder.Snapshot()
			wait := d.Phases["admission_"+name]
			if wait.Calls != 1 || wait.Duration <= 0 {
				t.Fatalf("missing bounded %s wait: %+v", name, d.Phases)
			}
			if queued && d.Phases["admission_cache"].Calls != 0 {
				t.Fatal("queue failure reported cache work")
			}
			if !queued && d.Phases["admission_queue"].Calls != 1 {
				t.Fatal("lost completed queue acquisition")
			}
			if d.Phases["admission_queue"].Duration+d.Phases["admission_cache"].Duration > d.Elapsed {
				t.Fatal("sequential admission phases overlap")
			}
			wantCheckpoints := 1
			if queued {
				wantCheckpoints = 0
			}
			if len(d.Checkpoints) != wantCheckpoints {
				t.Fatal("missing or extra acquisition boundary", d.Checkpoints)
			}
			for _, checkpoint := range d.Checkpoints {
				if checkpoint.Name != "admission_queue_ready" || queued {
					t.Fatal("failed acquisition reported readiness", checkpoint)
				}
			}
			holder.Close()
			// A failed diagnostic cycle must not retain a ticket or lock.
			measured, recorder = relayobserve.Start(ctx)
			next, err := OpenQueued(measured, dir, Options{NodeID: "robot"})
			if err != nil {
				t.Fatal(err)
			}
			next.Close()
			d = recorder.Snapshot()
			if d.Phases["admission_queue"].Calls != 1 || d.Phases["admission_cache"].Calls != 1 ||
				len(d.Checkpoints) != 2 || d.Checkpoints[0].Name != "admission_queue_ready" || d.Checkpoints[1].Name != "admission_cache_ready" {
				t.Fatalf("recovered admission missing distinct phases: %+v", d)
			}
		})
	}
}

// Cancel only after the queue is acquired; the parent deadline is a watchdog,
// not an assumption about how fast the FIFO scan runs on a shared CI runner.
func cancelCacheAdmissionAtCheckpoint(ctx context.Context, cancel context.CancelFunc, recorder *relayobserve.Recorder, name string) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			for _, mark := range recorder.Snapshot().Checkpoints {
				if mark.Name == name {
					cancel()
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
