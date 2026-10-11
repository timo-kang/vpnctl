//go:build linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLiveLeaseReadSocketCancellation(t *testing.T) {
	_, _, _ = routeQueryKernelFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, deadline := range []bool{false, true} {
		for range 32 {
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
			}
			f, closeSocket, err := flowtableSocket(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- receiveEmptyFlowtableDump(f, 1, 1) }()
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("cancelled read succeeded")
				}
			case <-time.After(time.Second):
				cancel()
				closeSocket()
				<-done
				t.Fatal("cancellation did not stop blocked read")
			}
			cancel()
			closeSocket()
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("socket descriptor counts before=%d after=%d", len(before), len(after))
	}
}

func TestFlowtableCancelledQueryDoesNotOpenSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := liveNoFlowtables(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("query lost cancellation")
	}
}
