// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/uplink"
)

func TestObservationQueueRetriesExactIDsThenRecovers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collected, requests := 0, 0
	var delivered []uplink.Snapshot
	runObservations(ctx, uplink.Config{}, func(context.Context) uplink.Snapshot { collected++; return uplink.Snapshot{ID: fmt.Sprint(collected)} }, func(_ context.Context, s uplink.Snapshot) error {
		requests++
		if requests <= 70 {
			return errors.New("controller unavailable")
		}
		delivered = append(delivered, s)
		if len(delivered) == 8 {
			cancel()
		}
		return nil
	})
	if len(delivered) != 8 || delivered[0].ID != "8" {
		t.Fatalf("dropped oldest / recovery: %+v", delivered)
	}
	for i := 1; i < len(delivered); i++ {
		if delivered[i].ID != fmt.Sprint(8+i) {
			t.Fatal("out of order", delivered)
		}
	}
	if delivered[0].Dropped != 0 {
		t.Fatal("retry mutated sample contents")
	}
}
func TestObservationShutdownCancelsBlockedUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runObservations(ctx, uplink.Config{IntervalSec: 60}, func(context.Context) uplink.Snapshot { return uplink.Snapshot{ID: "one"} }, func(ctx context.Context, _ uplink.Snapshot) error { close(entered); <-ctx.Done(); return ctx.Err() })
	}()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("uploader did not stop")
	}
}

func TestPermanentlyRejectedSnapshotDoesNotBlockNextCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collected := 0
	var last uplink.Snapshot
	runObservations(ctx, uplink.Config{}, func(context.Context) uplink.Snapshot { collected++; return uplink.Snapshot{ID: fmt.Sprint(collected)} }, func(_ context.Context, s uplink.Snapshot) error {
		if s.ID == "1" {
			return &api.HTTPError{StatusCode: 400}
		}
		last = s
		cancel()
		return nil
	})
	if last.ID != "2" || last.Dropped != 1 {
		t.Fatal(last)
	}
}
