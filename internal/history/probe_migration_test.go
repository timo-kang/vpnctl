// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Create an actual predecessor schema, not a current schema with a lower version.
func legacyStore(t *testing.T, version int) (*Store, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := connect(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sql := schema
	if version >= 2 {
		sql += uplinkSchema
	}
	if version >= 3 {
		sql += eventSchema
	}
	sql += fmt.Sprintf("PRAGMA user_version=%d;", version)
	if _, err = db.Exec(sql); err != nil {
		t.Fatal(err)
	}
	return &Store{path: path}, time.Now().UTC().Truncate(time.Microsecond)
}

func TestProbeMigrationPreservesRowsAndForeignKeys(t *testing.T) {
	for version := 1; version <= 4; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			old, now := legacyStore(t, version)
			db, err := connect(old.path, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`INSERT INTO streams(id,node,peer,path,relay,uplink) VALUES(7,'robot','peer','direct','','');
INSERT INTO probes(stream,id,ts,rtt) VALUES(7,'success',?,12000),(7,'failure',?,NULL);
UPDATE metadata SET row_count=2`, now.Add(-time.Second).UnixMicro(), now.UnixMicro())
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(t.TempDir(), "old-backup.db")
			if err = Backup(context.Background(), old.path, backup); err != nil {
				t.Fatal(err)
			}
			s, err := Open(old.path, now)
			if err != nil {
				t.Fatal(err)
			}
			b := query(t, s, now)[3]
			if b.Source != "legacy-probe" || b.Count != 2 || b.UnknownCount != 0 || b.Successes != 1 || *b.AvgRTTMs != 12 || *b.LossPct != 50 {
				t.Fatal(b)
			}
			unknown := Observation{ID: "unknown", Timestamp: now, PeerID: "peer", Path: "direct", Source: "agent-direct", Validity: "unknown", Reason: "invalid_probe_target"}
			ingest(t, s, "robot", []Observation{unknown}, now)
			if len(s.Latest(now)["robot"]) != 2 {
				t.Fatal("producer streams combined")
			}
			if err = Check(context.Background(), s.path); err != nil {
				t.Fatal(err)
			}
			current := filepath.Join(t.TempDir(), "new-backup.db")
			if err = Backup(context.Background(), s.path, current); err != nil {
				t.Fatal(err)
			}
			restored := filepath.Join(t.TempDir(), "restored.db")
			if err = Restore(context.Background(), current, restored, now); err != nil {
				t.Fatal(err)
			}
			copy, err := Open(restored, now)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(query(t, s, now), query(t, copy, now)) {
				t.Fatal("restore changed raw outcomes")
			}
			legacyRestore := filepath.Join(t.TempDir(), "legacy-restored.db")
			if err = Restore(context.Background(), backup, legacyRestore, now); err != nil {
				t.Fatal(err)
			}
			migrated, err := Open(legacyRestore, now)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(b, query(t, migrated, now)[3]) {
				t.Fatal("legacy restore lost original data")
			}
		})
	}
}

func TestProbeMigrationRollbackOnBrokenReference(t *testing.T) {
	s, now := legacyStore(t, 4)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`PRAGMA foreign_keys=OFF; INSERT INTO probes(stream,id,ts,rtt) VALUES(99,'orphan',?,NULL); UPDATE metadata SET row_count=1; PRAGMA foreign_keys=ON`, now.UnixMicro()); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(s.path, now); err == nil {
		t.Fatal("orphan reference migrated")
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 4 {
		t.Fatal("migration partially committed", version, err)
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM pragma_table_info('probes')").Scan(&count); err != nil || count != 4 {
		t.Fatal("rollback left new columns", count, err)
	}
}

func TestBackupRejectsCorruptProbeMetadata(t *testing.T) {
	for _, mutation := range []string{
		"UPDATE probes SET unknown=1",                      // success with unknown validity and no reason
		"UPDATE probes SET reason='collector_unavailable'", // successful RTT with an error
		"UPDATE probes SET rtt=NULL,unknown=1,reason=char(10)",
		"UPDATE streams SET source='unrecognized'",
		"UPDATE streams SET source='agent-direct'", // relay stream claiming public candidate probe
	} {
		t.Run(mutation, func(t *testing.T) {
			s, now := newStore(t)
			ingest(t, s, "robot", []Observation{obs("one", now, pointer(10.))}, now)
			db, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(mutation)
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err = Check(context.Background(), s.path); err == nil {
				t.Fatal("invalid backup accepted")
			}
			dest := filepath.Join(t.TempDir(), "restored.db")
			if err = Restore(context.Background(), s.path, dest, now); err == nil {
				t.Fatal("invalid history restored")
			}
			if _, err = os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("failed restore published a file", err)
			}
		})
	}
}
