// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
	"vpnctl/internal/atomicfile"
	"vpnctl/internal/relayobserve"
)

func TestStorageDiagnosticsPreserveWriteAndCommitBoundary(t *testing.T) {
	for _, failDir := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "directory-sync-error"}[failDir], func(t *testing.T) {
			s, _, dir := statusCheckpointFixture(t)
			before := s.state.ObservedAt
			next := before.Add(time.Second)
			s.now = func() time.Time { return next }
			if failDir {
				s.syncDir = func() error { return syscall.EIO }
			}
			ctx, recorder := relayobserve.Start(context.Background())
			report, err := s.StatusObserved(ctx)
			if failDir {
				if !errors.Is(err, syscall.EIO) || !atomicfile.Replaced(err) || report.UsableCache {
					t.Fatal("lost post-rename failure", err, report)
				}
			} else if err != nil || !report.UsableCache {
				t.Fatal(err, report)
			}
			for _, name := range []string{"cache_file_prepare", "cache_file_write", "cache_file_sync", "cache_file_close", "cache_file_rename", "cache_directory_sync"} {
				p := recorder.Snapshot().Phases[name]
				if p.Calls != 1 || p.Duration <= 0 {
					t.Fatal("missing storage stage", name, p)
				}
			}
			// The injected sync failure follows rename, so the new watermark remains
			// in the file and is verified when a fresh Store opens it.
			if s.diagnosticContext != nil {
				t.Fatal("recorder escaped its public call")
			}
			s.Close()
			reopened, err := Open(dir, Options{NodeID: "robot"})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if !reopened.state.ObservedAt.Equal(next) {
				t.Fatal("write was not durable", reopened.state.ObservedAt)
			}
		})
	}
}

func TestStorageDiagnosticsCoverExpiryCheckpoint(t *testing.T) {
	s, controller, _ := statusCheckpointFixture(t)
	expiry := controller.state.ExpiresAt
	now := expiry.Add(-time.Millisecond)
	s.now = func() time.Time { return now }
	write, calls := s.writeState, 0
	s.writeState = func(b []byte) error { calls++; err := write(b); now = expiry; return err }
	ctx, r := relayobserve.Start(context.Background())
	if report, err := s.StatusObserved(ctx); err != nil || report.Validity != "expired" || report.UsableCache {
		t.Fatal(report, err)
	}
	for _, name := range []string{"cache_state_persist", "cache_file_sync", "cache_directory_sync"} {
		if calls != 2 || r.Snapshot().Phases[name].Calls != 2 {
			t.Fatal("expiry write not accounted", name, calls, r.Snapshot())
		}
	}
	now = expiry.Add(-time.Millisecond)
	if report, err := s.Status(); err != nil || report.UsableCache {
		t.Fatal("expiry resurrected", report, err)
	}
	if r.Snapshot().Phases["cache_file_sync"].Calls != 2 {
		t.Fatal("ordinary call retained recorder")
	}
}
