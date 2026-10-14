//go:build linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveTargetRouteSocketCancellationJoinsBlockedRead(t *testing.T) {
	// Reuse the independent guard; all kernel tests live in a disposable
	// loopback-only namespace with just CAP_NET_ADMIN, never the shared host.
	_, _, _ = routeQueryKernelFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, deadline := range []bool{false, true} {
		for i := 0; i < 32; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			s, closeSocket, err := targetRouteSocket(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, _, err := s.Receive(); done <- err }()
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
				t.Fatal("cancellation failed to interrupt the blocked read")
			}
			cancel()
			closeSocket()
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("socket descriptors leaked: before=%d after=%d err=%v", len(before), len(after), err)
	}
}
