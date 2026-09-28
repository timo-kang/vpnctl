// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var reclamationCancelSequence atomic.Int64

func TestPathChurnCancellationRollsBackLossAndAdmission(t *testing.T) {
	s, now, old := fullArchivedPaths(t)
	if err := s.EnableReclamation(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := fmt.Sprintf("cancel_reclamation_%d", reclamationCancelSequence.Add(1))
	if err := sqlite.RegisterScalarFunction(fn, 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) { cancel(); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TRIGGER cancel_reclamation BEFORE DELETE ON streams BEGIN SELECT " + fn + "(); END"); err != nil {
		t.Fatal(err)
	}
	next := old[0]
	next.ID, next.Timestamp, next.Uplink = "new", now, "replacement"
	if err = s.Ingest(ctx, "robot", []Observation{next}, now); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation did not abort", err)
	}
	stats, err := s.TieredStats(context.Background())
	if err != nil || stats.ReclaimedStreams != 0 || stats.ReclamationRows != 0 || stats.RawRows != 0 || stats.RollupRows != 256 {
		t.Fatal("cancel left partial reclamation", stats, err)
	}
	if _, err = db.Exec("DROP TRIGGER cancel_reclamation"); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "robot", []Observation{next}, now)
	if err = Check(context.Background(), s.path); err != nil {
		t.Fatal(err)
	}
}

func TestPathChurnCrashRecovery(t *testing.T) {
	if path := os.Getenv("VPNCTL_RECLAMATION_CRASH_DB"); path != "" {
		now, err := time.Parse(time.RFC3339Nano, os.Getenv("VPNCTL_RECLAMATION_CRASH_NOW"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(path, now)
		if err != nil {
			t.Fatal(err)
		}
		db, err := connect(path, false)
		if err != nil {
			t.Fatal(err)
		}
		if err = db.Ping(); err != nil {
			t.Fatal(err)
		} // keep WAL open through post-commit exit
		if os.Getenv("VPNCTL_RECLAMATION_CRASH_STAGE") == "before" {
			if err = sqlite.RegisterScalarFunction("crash_reclamation", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) { os.Exit(77); return nil, nil }); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("CREATE TRIGGER crash_reclamation BEFORE DELETE ON streams BEGIN SELECT crash_reclamation(); END"); err != nil {
				t.Fatal(err)
			}
		}
		o := Observation{ID: "new", Source: "agent-direct", Timestamp: now, PeerID: "peer-00", Path: "direct", Uplink: "new-path", Success: pointer(true), RTTMs: pointer(1.)}
		if err = s.Ingest(context.Background(), "robot", []Observation{o}, now); err != nil {
			t.Fatal(err)
		}
		os.Exit(77)
	}
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			s, now, _ := fullArchivedPaths(t)
			if err := s.EnableReclamation(context.Background()); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPathChurnCrashRecovery$")
			cmd.Env = append(os.Environ(), "VPNCTL_RECLAMATION_CRASH_DB="+s.path, "VPNCTL_RECLAMATION_CRASH_NOW="+now.Format(time.RFC3339Nano), "VPNCTL_RECLAMATION_CRASH_STAGE="+stage)
			output, err := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 77 {
				t.Fatalf("crash child: %v %s", err, output)
			}
			s, err = Open(s.path, now)
			if err != nil {
				t.Fatal(err)
			}
			stats, err := s.TieredStats(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if stage == "after" {
				want = 1
			}
			if stats.ReclaimedStreams != want || stats.ReclaimedSamples != want || stats.RawRows != want || stats.RollupRows != 256-want {
				t.Fatal("wrong crash boundary", stats)
			}
			db, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("DROP TRIGGER IF EXISTS crash_reclamation")
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			o := Observation{ID: "new", Source: "agent-direct", Timestamp: now, PeerID: "peer-00", Path: "direct", Uplink: "new-path", Success: pointer(true), RTTMs: pointer(1.)}
			ingest(t, s, "robot", []Observation{o}, now)
			stats, err = s.TieredStats(context.Background())
			if err != nil || stats.RawRows != 1 || stats.ReclaimedSamples != 1 || stats.ReclaimedStreams != 1 {
				t.Fatal("retry after crash changed population", stats, err)
			}
			if err = Check(context.Background(), s.path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPathChurnRejectsCorruptCoverageAndMigrationFailure(t *testing.T) {
	for _, mutate := range []string{
		"UPDATE reclamation_metadata SET loss_rows=loss_rows+1",
		"UPDATE reclamation_metadata SET next_stream_id=1",
		"UPDATE reclamation_metadata SET evicted_samples=0",
		"UPDATE history_loss SET end_ts=end_ts+1",
		"UPDATE history_loss SET source='invented'",
		"UPDATE history_loss SET samples=samples+1",
		"UPDATE reclamation_metadata SET expired_samples=1",
	} {
		t.Run(mutate, func(t *testing.T) {
			s, now, old := fullArchivedPaths(t)
			ctx := context.Background()
			if err := s.EnableReclamation(ctx); err != nil {
				t.Fatal(err)
			}
			o := old[0]
			o.ID, o.Uplink, o.Timestamp = "new", "new-path", now
			ingest(t, s, "robot", []Observation{o}, now)
			db, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(mutate)
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err = Check(ctx, s.path); err == nil {
				t.Fatal("corrupt metadata passed")
			}
			if _, err = Open(s.path, now); err == nil {
				t.Fatal("corrupt storage opened")
			}
			target := filepath.Join(t.TempDir(), "bad.db")
			if err = Restore(ctx, s.path, target, now); err == nil {
				t.Fatal("corrupt backup restored")
			}
			if _, err = os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("failed restore published", err)
			}
		})
	}
	s, now, _ := fullArchivedPaths(t)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TABLE history_loss(conflict INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err = s.EnableReclamation(context.Background()); err == nil {
		t.Fatal("conflicting migration succeeded")
	}
	if s.ReclamationEnabled() {
		t.Fatal("failed migration published policy")
	}
	info, err := Inspect(context.Background(), s.path)
	if err != nil || info.SchemaVersion != 6 {
		t.Fatal(info, err)
	}
	if _, err = db.Exec("DROP TABLE history_loss"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.EnableReclamation(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = Open(s.path, now); err != nil {
		t.Fatal(err)
	}
}
