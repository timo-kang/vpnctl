// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"context"
	"testing"
	"time"
)

func TestRetryBoundsAndReset(t *testing.T) {
	var b backoff
	for i := 0; i < 32; i++ {
		upper := 8 * time.Second
		if i < 5 {
			upper = 250 * time.Millisecond * time.Duration(1<<i)
		}
		if delay := b.next(); delay < upper/2 || delay > upper {
			t.Fatal("retry outside exponential bounds", i, delay)
		}
	}
	b.reset()
	if delay := b.next(); delay < 125*time.Millisecond || delay > 250*time.Millisecond {
		t.Fatal("reset failed", delay)
	}
}
func TestWatchCancellationDuringBackoff(t *testing.T) {
	s, _ := NewState("app")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := Watch(ctx, Options{Directory: "/nonexistent/vpnctl-test"}, s); err != context.DeadlineExceeded {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancel blocked in retry")
	}
}
func TestEpochExhaustionRetiresActiveConnection(t *testing.T) {
	s, _ := NewState("app")
	s.epoch = ^uint64(0) - 1
	old := s.Begin()
	if old != ^uint64(0) || s.Begin() != 0 || s.active {
		t.Fatal("exhausted epoch remained active")
	}
	if s.Accept(old, []byte(`{}`)) == nil {
		t.Fatal("exhausted connection accepted frame")
	}
}
