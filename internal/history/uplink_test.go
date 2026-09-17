// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/uplink"
)

func uplinkFixture(at time.Time, id string) uplink.Snapshot {
	return uplink.Snapshot{ID: id, At: at, IntervalSec: 60, Underlay: uplink.Up(), Links: []uplink.Link{{ID: "lan", Interface: "eth0", Kind: "ethernet", Check: uplink.Up(), Modem: uplink.Unknown("not_configured"), GatewayState: uplink.Unknown("not_configured"), DNS: uplink.Unknown("not_configured"), Controller: uplink.Up(), ControllerRoute: uplink.Route{Check: uplink.Up(), Interface: "eth0"}}}, Targets: []uplink.Target{{TransportRoute: uplink.Route{Check: uplink.Unknown("not_observed")}, ID: "server", Protocol: "tcp", Route: uplink.Route{Check: uplink.Up(), Interface: "wg0"}, Relay: uplink.Up(), Service: uplink.Check{State: "up", RTTMs: pointer(12.)}, FailureStage: "none"}}}
}
func TestUplinkPersistenceRetryUnknownAndBackup(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	path := filepath.Join(t.TempDir(), "history.db")
	s, e := Open(path, now)
	if e != nil {
		t.Fatal(e)
	}
	v := uplinkFixture(now.Add(-time.Second), "one")
	for i := 0; i < 2; i++ {
		if e = s.IngestUplink(ctx, "robot", v, now); e != nil {
			t.Fatal(e)
		}
	}
	v.Targets[0].Service.RTTMs = pointer(13.)
	if e = s.IngestUplink(ctx, "robot", v, now); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	v.ID = "two"
	v.At = now
	v.Targets[0].Service = uplink.Unknown("permission_denied")
	v.Targets[0].FailureStage = "unknown"
	if e = s.IngestUplink(ctx, "robot", v, now); e != nil {
		t.Fatal(e)
	}
	// Detached snapshots cannot corrupt the controller's cache.
	latest := s.LatestUplinks(now)
	latest["robot"].Targets[0].ID = "corrupted"
	if s.LatestUplinks(now)["robot"].Targets[0].ID != "server" {
		t.Fatal("aliased cache")
	}
	result, e := s.QueryUplinks(ctx, "robot", now, time.Hour, 1)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Snapshots) != 1 || !result.Truncated || result.Summaries[0].Samples != 2 || result.Summaries[0].Unknown != 1 || *result.Summaries[0].AvailabilityPct != 100 || *result.Summaries[0].AvgRTTMs != 12 {
		t.Fatal(result)
	}
	s, e = Open(path, now)
	if e != nil {
		t.Fatal(e)
	}
	if !s.LatestUplinks(now.Add(181 * time.Second))["robot"].Stale {
		t.Fatal("stale data reported fresh")
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if e = Backup(ctx, path, backup); e != nil {
		t.Fatal(e)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if e = Restore(ctx, backup, restored, now); e != nil {
		t.Fatal(e)
	}
	restoredStore, e := Open(restored, now)
	if e != nil {
		t.Fatal(e)
	}
	if restoredStore.LatestUplinks(now)["robot"].ID != "two" {
		t.Fatal("lost uplink history")
	}
	if e = s.Maintain(ctx, now.Add(Retention)); e != nil {
		t.Fatal(e)
	}
	if len(s.LatestUplinks(now.Add(Retention))) != 0 {
		t.Fatal("expired latest retained")
	}
	result, e = s.QueryUplinks(ctx, "robot", now.Add(Retention), Retention, 10)
	if e != nil || len(result.Snapshots) != 0 || len(result.Summaries) != 0 {
		t.Fatal(result, e)
	}
	if e = Check(ctx, path); e != nil {
		t.Fatal(e)
	}
}
func TestUplinkMigrationFromV1PreservesPeerData(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "old.db")
	s, e := Open(path, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Ingest(context.Background(), "robot", []Observation{obs("before-migration", now, pointer(9.))}, now); e != nil {
		t.Fatal(e)
	}
	db, e := connect(path, false)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`DROP TABLE uplink_series;DROP TABLE uplink_results;DROP TABLE uplink_snapshots;DROP TABLE uplink_latest;DROP TABLE uplink_metadata;PRAGMA user_version=1;`)
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	s, e = Open(path, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.IngestUplink(context.Background(), "robot", uplinkFixture(now, "one"), now); e != nil {
		t.Fatal(e)
	}
	if values := s.Latest(now)["robot"]; len(values) != 1 || values[0].SampleCount != 1 || values[0].RTTMs == nil || *values[0].RTTMs != 9 {
		t.Fatal("peer data changed during migration", values)
	}
	if e = Check(context.Background(), path); e != nil {
		t.Fatal(e)
	}
}
func TestUplinkRejectsInvalidAndCapacity(t *testing.T) {
	now := time.Now()
	s, e := Open(filepath.Join(t.TempDir(), "db"), now)
	if e != nil {
		t.Fatal(e)
	}
	v := uplinkFixture(now.Add(time.Second), "future")
	if e = s.IngestUplink(context.Background(), "robot", v, now); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	db, _ := connect(s.path, false)
	_, e = db.Exec("UPDATE uplink_metadata SET row_count=?", MaxUplinkSnapshots)
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	v = uplinkFixture(now, "valid")
	if e = s.IngestUplink(context.Background(), "robot", v, now); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	if len(s.LatestUplinks(now)) != 0 {
		t.Fatal("uncommitted status published")
	}
}

// Add the configured maximum of four targets to the existing 32-node history
// benchmark. Payloads are valid snapshots shared by nodes, with unique cycle IDs.
func seedUplinkScale(t *testing.T, s *Store, now time.Time, step time.Duration) {
	t.Helper()
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	targets := []string{"app", "health", "control", "telemetry"}
	for _, target := range targets {
		if _, e = tx.Exec("INSERT INTO uplink_series SELECT node,?,'tcp' FROM streams", target); e != nil {
			t.Fatal(e)
		}
	}
	count := int(Retention / step)
	for i := 1; i <= count; i++ {
		v := uplinkFixture(now.Add(-Retention).Add(time.Duration(i)*step), fmt.Sprintf("cycle-%d", i))
		v.Targets = nil
		for _, id := range targets {
			target := uplinkFixture(now, "unused").Targets[0]
			target.ID = id
			if i%10 == 0 {
				target.Service = uplink.Down("reachability_timeout")
				target.FailureStage = "server_endpoint"
			}
			v.Targets = append(v.Targets, target)
		}
		payload, digest, e := packSnapshot(v)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec("INSERT INTO uplink_snapshots SELECT node,?,?,?,? FROM streams", v.ID, v.At.UnixMicro(), payload, digest); e != nil {
			t.Fatal(e)
		}
		for _, target := range v.Targets {
			if _, e = tx.Exec("INSERT INTO uplink_results SELECT node,?,?,?,?,?,? FROM streams", v.ID, target.ID, target.Protocol, v.At.UnixMicro(), target.Service.State, target.Service.RTTMs); e != nil {
				t.Fatal(e)
			}
		}
		if i == count {
			if _, e = tx.Exec("INSERT INTO uplink_latest SELECT node,?,?,? FROM streams", v.At.UnixMicro(), v.ID, payload); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = tx.Exec("UPDATE uplink_metadata SET row_count=?", 32*count); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	out, e := s.QueryUplinks(context.Background(), "robot-00", now, Retention, 100)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Summaries) != 4 || out.Summaries[0].Samples != count || len(out.Snapshots) != 100 || !out.Truncated {
		t.Fatal("incomplete staged history", out)
	}
	t.Logf("uplink nodes=32 targets=4 cadence=%s snapshots=%d query=%s", step, count*32, time.Since(start))
}

func TestUplinkSeriesQuotaRollsBackAndOlderReportsDoNotReplaceLatest(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	for i := 0; i < 16; i++ {
		v := uplinkFixture(now.Add(-time.Duration(i)*time.Second), fmt.Sprintf("s-%d", i))
		v.Targets[0].ID = fmt.Sprintf("target-%d", i)
		if e := s.IngestUplink(ctx, "robot", v, now); e != nil {
			t.Fatal(e)
		}
	}
	v := uplinkFixture(now, "rejected")
	v.Targets[0].ID = "seventeenth"
	if e := s.IngestUplink(ctx, "robot", v, now); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	if s.LatestUplinks(now)["robot"].ID != "s-0" {
		t.Fatal("out-of-order or rejected sample replaced current status")
	}
	out, e := s.QueryUplinks(ctx, "robot", now, time.Hour, 100)
	if e != nil || len(out.Snapshots) != 16 || len(out.Summaries) != 16 {
		t.Fatal(out, e)
	}
}
