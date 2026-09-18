// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// Opt in to the full 32-node, five-second, seven-day storage/query budget test.
// Routine/race runs use the same query with 32 nodes at fifteen-minute cadence.
func TestHistoryScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale fixture")
	}
	s, now := newStore(t)
	step := 15 * time.Minute
	if os.Getenv("VPNCTL_HISTORY_SCALE") == "1" {
		step = 5 * time.Second
	}
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	total := 0
	for n := 0; n < 32; n++ {
		res, e := tx.Exec("INSERT INTO streams(node,peer,path,relay,uplink,source) VALUES(?,'server','direct','','','agent-direct')", fmt.Sprintf("robot-%02d", n))
		if e != nil {
			t.Fatal(e)
		}
		id, _ := res.LastInsertId()
		count := int(Retention / step)
		_, e = tx.Exec(`WITH RECURSIVE samples(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM samples WHERE i<?)
    INSERT INTO probes(stream,id,ts,rtt,unknown,reason)
    SELECT ?,printf('%016x%06x',0,i),?+i*?,CASE WHEN i%10=0 THEN NULL ELSE 12000 END,
    CASE WHEN i%20=0 THEN 1 ELSE 0 END,
    CASE WHEN i%20=0 THEN 'collector_unavailable' WHEN i%10=0 THEN 'probe_timeout' ELSE '' END FROM samples`, count, id, now.Add(-Retention).UnixMicro(), step.Microseconds())
		if e != nil {
			t.Fatal(e)
		}
		total += count
	}
	if _, e = tx.Exec("UPDATE metadata SET row_count=?", total); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	db.Close()
	uplinkStep := 15 * time.Minute
	if os.Getenv("VPNCTL_HISTORY_SCALE") == "1" {
		uplinkStep = time.Minute
	}
	seedUplinkScale(t, s, now, uplinkStep)
	info, e := os.Stat(s.path)
	if e != nil {
		t.Fatal(e)
	}
	if info.Size() > 1<<30 {
		t.Fatalf("storage over budget: %d", info.Size())
	}
	for _, window := range []time.Duration{24 * time.Hour, Retention} {
		start := time.Now()
		bs, e := s.Query(context.Background(), "", now, window, DefaultWidth(window))
		elapsed := time.Since(start)
		if e != nil {
			t.Fatalf("window=%s elapsed=%s: %v", window, elapsed, e)
		}
		got := 0
		for _, b := range bs {
			got += b.Count + b.UnknownCount
			if b.Successes > 0 && (b.P95RTTMs == nil || *b.P95RTTMs != 12) {
				t.Fatal(b)
			}
		}
		if got != 32*int(window/step) {
			t.Fatal("incomplete result", got)
		}
		t.Logf("nodes=32 cadence=%s rows=%d db_bytes=%d window=%s query=%s buckets=%d", step, total, info.Size(), window, elapsed, len(bs))
	}
	start := time.Now()
	if _, e = Open(s.path, now); e != nil {
		t.Fatal(e)
	}
	t.Logf("restart replay=%s", time.Since(start))
	if os.Getenv("VPNCTL_HISTORY_SCALE") == "1" {
		t.Run("WAL backpressure", testWALBackpressure)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		start = time.Now()
		if e = s.Maintain(ctx, now.Add(Retention)); e != nil {
			t.Fatal("full retention cleanup", e)
		}
		t.Logf("expired %d rows in %s", total, time.Since(start))
		db, e = connect(s.path, true)
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		var count int
		if e = db.QueryRow("SELECT row_count FROM metadata").Scan(&count); e != nil || count != 0 {
			t.Fatal(count, e)
		}
	}

}

// Pin a genuine SQLite read snapshot and grow a WAL beyond its watermark using
// an out-of-band pressure table. This exercises real checkpoint/busy behavior
// without millions of synthetic API requests. No production schema uses it.
func testWALBackpressure(t *testing.T) {
	s, now := newStore(t)
	ingest(t, s, "robot", []Observation{obs("first", now, pointer(10.0))}, now)
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("CREATE TABLE pressure(data BLOB)"); e != nil {
		t.Fatal(e)
	}
	readDB, e := connect(s.path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer readDB.Close()
	tx, e := readDB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM probes").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO pressure VALUES(zeroblob(68157440))"); e != nil {
		t.Fatal(e)
	}
	sample := obs("second", now, pointer(20.0))
	if e = s.Ingest(context.Background(), "robot", []Observation{sample}, now); !errors.Is(e, ErrCapacity) {
		t.Fatal("pinned oversized WAL was not rejected", e)
	}
	if got := s.Latest(now)["robot"][0]; got.SampleCount != 1 {
		t.Fatal("failed WAL write published", got)
	}
	tx.Rollback()
	ingest(t, s, "robot", []Observation{sample}, now)
	if query(t, s, now)[3].Count != 2 {
		t.Fatal("write did not recover after reader released WAL")
	}
}
