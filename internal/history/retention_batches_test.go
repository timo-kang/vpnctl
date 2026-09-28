// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var retentionCancelSequence atomic.Int64

func TestRetentionMixedAgeBatchesResumeAfterCancellation(t *testing.T) {
	s, now := newStore(t)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const streams, expiredPerStream, freshPerStream = 3, 10003, 2
	cutoff := now.Add(-Retention).UnixMicro()
	for i := 1; i <= streams; i++ {
		if _, err := db.Exec("INSERT INTO streams(id,node,peer,path,relay,uplink) VALUES(?,'node',?,'unknown','','')", i, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
		_, err := db.Exec(`WITH RECURSIVE samples(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM samples WHERE i<?)
INSERT INTO probes(stream,id,ts,rtt,unknown,reason) SELECT ?,printf('%06d',i),?,1000,0,'' FROM samples`, expiredPerStream, i, cutoff)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < freshPerStream; j++ {
			if _, err := db.Exec("INSERT INTO probes(stream,id,ts,rtt,unknown,reason) VALUES(?,?,?,1000,0,'')", i, fmt.Sprintf("fresh-%d", j), now.Add(-time.Duration(j)*time.Second).UnixMicro()); err != nil {
				t.Fatal(err)
			}
		}
	}
	const total = streams * (expiredPerStream + freshPerStream)
	if _, err := db.Exec("UPDATE metadata SET row_count=?", total); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := fmt.Sprintf("cancel_retention_%d", retentionCancelSequence.Add(1))
	var batches atomic.Int32
	if err := sqlite.RegisterScalarFunction(fn, 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		if batches.Add(1) == 2 {
			cancel()
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Reconnect so SQLite loads the newly registered function.
	db.Close()
	db, err = connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TRIGGER cancel_retention BEFORE UPDATE ON metadata BEGIN SELECT " + fn + "(); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(ctx, now); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
	var rows, counted int
	if err := db.QueryRow("SELECT (SELECT count(*) FROM probes),row_count FROM metadata").Scan(&rows, &counted); err != nil || rows != total-10000 || counted != rows {
		t.Fatal("lost committed progress or partial batch", rows, counted, err)
	}
	if _, err := db.Exec("DROP TRIGGER cancel_retention"); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT (SELECT count(*) FROM probes),row_count FROM metadata").Scan(&rows, &counted); err != nil || rows != streams*freshPerStream || counted != rows {
		t.Fatal("later streams missed or fresh rows deleted", rows, counted, err)
	}
	if err := Check(context.Background(), s.path); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.path, now)
	if err != nil {
		t.Fatal(err)
	}
	if latest := reopened.Latest(now)["node"]; len(latest) != streams {
		t.Fatal("fresh stream lost", latest)
	}
}

func TestRetentionFailedBatchRollbackAndReuse(t *testing.T) {
	s, now := newStore(t)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("INSERT INTO streams(id,node,peer,path,relay,uplink) VALUES(1,'node','peer','unknown','','')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`WITH RECURSIVE samples(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM samples WHERE i<20001)
INSERT INTO probes(stream,id,ts,rtt,unknown,reason) SELECT 1,printf('%06d',i),?,1000,0,'' FROM samples`, now.Add(-Retention).UnixMicro()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE metadata SET row_count=20001"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER fail_cleanup BEFORE UPDATE ON metadata BEGIN SELECT RAISE(ABORT,'injected metadata failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(context.Background(), now); err == nil {
		t.Fatal("injected failure succeeded")
	}
	var rows, counted int
	if err := db.QueryRow("SELECT (SELECT count(*) FROM probes),row_count FROM metadata").Scan(&rows, &counted); err != nil || rows != 20001 || counted != rows {
		t.Fatal("failed batch was not atomic", rows, counted, err)
	}
	if _, err := db.Exec("DROP TRIGGER fail_cleanup"); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT (SELECT count(*) FROM probes),row_count FROM metadata").Scan(&rows, &counted); err != nil || rows != 0 || counted != 0 {
		t.Fatal("cleanup count incorrect", rows, counted, err)
	}
	if err := s.Ingest(context.Background(), "node", []Observation{{ID: "new", PeerID: "peer", Path: "unknown", Timestamp: now, Success: pointer(true), RTTMs: pointer(1.)}}, now); err != nil {
		t.Fatal(err)
	}
	if err := Check(context.Background(), s.path); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionRemovesEmptyLegacyStreamsWithoutExpiredProbes(t *testing.T) {
	s, now := newStore(t)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("INSERT INTO streams(node,peer,path,relay,uplink) VALUES('node','empty','unknown','','')"); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM streams").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}
