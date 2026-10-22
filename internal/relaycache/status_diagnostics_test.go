// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/atomicfile"
	"vpnctl/internal/relayobserve"
)

func TestStatusObservedPreservesDurabilityAndFreshness(t *testing.T) {
	s, _, dir := statusCheckpointFixture(t)
	beforeFresh := s.fresh
	now := s.state.ObservedAt.Add(time.Second)
	s.now = func() time.Time { return now }
	writes, write := 0, s.writeState
	s.writeState = func(b []byte) error { writes++; return write(b) }
	// This context is for accounting only; it must not change Status semantics.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, recorder := relayobserve.Start(cancelled)
	for i := 0; i < 2; i++ {
		report, err := s.StatusObserved(ctx)
		if err != nil || !report.UsableCache {
			t.Fatal("observed status", err)
		}
		report.Catalog.Spec.Paths[0].Disabled = true
		now = now.Add(time.Millisecond)
	}
	if writes != 2 || s.fresh != beforeFresh {
		t.Fatal("changed writes or fresh approval", writes)
	}
	phases := recorder.Snapshot().Phases
	for _, name := range []string{"cache_status", "cache_clock_checkpoint", "cache_state_open", "cache_state_encode", "cache_state_persist", "cache_status_report"} {
		if p := phases[name]; p.Calls != 2 || p.Duration <= 0 || p.KernelCommands != 0 || p.InventoryCommands != 0 {
			t.Fatal(name, p)
		}
	}
	committed := s.state.ObservedAt
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.state.ObservedAt.Equal(committed) || !reopened.fresh.at.IsZero() || reopened.state.Catalog.Spec.Paths[0].Disabled {
		t.Fatal("durability, isolation or fresh proof changed")
	}
}

func TestStatusObservedWriteFailureRetainsCommitBoundary(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(fmt.Sprint(replaced), func(t *testing.T) {
			s, _, _ := statusCheckpointFixture(t)
			previous := s.state.ObservedAt
			next := previous.Add(time.Second)
			s.now = func() time.Time { return next }
			write, writes := s.writeState, 0
			s.writeState = func(b []byte) error {
				writes++
				if replaced {
					if err := write(b); err != nil {
						return err
					}
					return &atomicfile.CommitError{Err: syscall.EIO}
				}
				return syscall.EIO
			}
			ctx, recorder := relayobserve.Start(context.Background())
			report, err := s.StatusObserved(ctx)
			if !errors.Is(err, syscall.EIO) || report.UsableCache || !s.uncertain {
				t.Fatal("uncertain write accepted", err)
			}
			if atomicfile.Replaced(err) != replaced {
				t.Fatal("commit boundary changed", err)
			}
			expected := previous
			if replaced {
				expected = next
			}
			if !s.state.ObservedAt.Equal(expected) {
				t.Fatal("incorrect in-memory commit")
			}
			if r, err := s.StatusObserved(ctx); !errors.Is(err, ErrUncertain) || r.UsableCache {
				t.Fatal("uncertain state accepted", err)
			}
			if writes != 1 || recorder.Snapshot().Phases["cache_state_persist"].Calls != 1 {
				t.Fatal("persistence retried or failure duration lost")
			}
		})
	}
}

func TestStatusObservedCannotResurrectExpiryAfterRollback(t *testing.T) {
	s, controller, dir := statusCheckpointFixture(t)
	expired := controller.state.ExpiresAt.Add(time.Second)
	s.now = func() time.Time { return expired }
	ctx, _ := relayobserve.Start(context.Background())
	if r, err := s.StatusObserved(ctx); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal(r.Validity, err)
	}
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return expired.Add(-2 * time.Second) }
	if r, err := reopened.StatusObserved(ctx); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("rollback resurrected authority", r.Validity, err)
	}
}
