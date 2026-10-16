// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Delay the real SQLite driver, not Storage.Ingest or a fake successful write.
// database/sql checks cancellation before entering driver.Tx.Commit; after that
// point cancellation cannot promise rollback of an already committing request.
type ingestBoundaryConnector struct {
	driver           driver.Driver
	dsn, boundary    string
	entered, release chan struct{}
	once             sync.Once
}

func (c *ingestBoundaryConnector) Driver() driver.Driver { return c.driver }
func (c *ingestBoundaryConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &ingestBoundaryConn{Conn: raw, ConnPrepareContext: raw.(driver.ConnPrepareContext), ExecerContext: raw.(driver.ExecerContext), QueryerContext: raw.(driver.QueryerContext), boundary: c}, nil
}
func (c *ingestBoundaryConnector) pause(boundary string) {
	if c.boundary == boundary {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
}

type ingestBoundaryConn struct {
	driver.Conn
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	boundary *ingestBoundaryConnector
}

func (c *ingestBoundaryConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.boundary.pause("before_begin")
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &ingestBoundaryTx{Tx: tx, boundary: c.boundary}, nil
}

type ingestBoundaryTx struct {
	driver.Tx
	boundary *ingestBoundaryConnector
}

func (tx *ingestBoundaryTx) Commit() error {
	tx.boundary.pause("inside_commit")
	return tx.Tx.Commit()
}

func TestCanceledIngestNeedsCommitDrainBeforePersistenceBaseline(t *testing.T) {
	for _, boundary := range []string{"before_begin", "inside_commit"} {
		t.Run(boundary, func(t *testing.T) {
			s, now := newStore(t)
			var initial []Observation
			for i := 0; i < 4; i++ {
				o := Observation{ID: fmt.Sprint(i), Timestamp: now.Add(time.Duration(i-5) * time.Second), PeerID: "peer", Path: "unknown", Source: "monitor-overlay", Success: pointer(i < 3)}
				if i < 3 {
					o.RTTMs = pointer(1.0)
				}
				initial = append(initial, o)
			}
			ingest(t, s, "robot", initial, now)
			count := func(store *Store) (int, int) {
				t.Helper()
				attempts, successes := 0, 0
				for _, b := range query(t, store, now) {
					attempts += b.Count
					successes += b.Successes
				}
				return attempts, successes
			}
			base, err := connect(s.path, false)
			if err != nil {
				t.Fatal(err)
			}
			u := url.URL{Scheme: "file", Path: s.path}
			q := u.Query()
			q.Set("mode", "rw")
			q.Add("_pragma", "foreign_keys(1)")
			q.Add("_pragma", "synchronous(FULL)")
			u.RawQuery = q.Encode()
			gate := &ingestBoundaryConnector{driver: base.Driver(), dsn: u.String(), boundary: boundary, entered: make(chan struct{}), release: make(chan struct{})}
			base.Close()
			s.uploadDB = sql.OpenDB(gate)
			s.uploadDB.SetMaxOpenConns(1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var once sync.Once
			release := func() { once.Do(func() { close(gate.release) }) }
			pending := Observation{ID: "pending", Timestamp: now.Add(-time.Second), PeerID: "peer", Path: "unknown", Source: "monitor-overlay", Success: pointer(false)}
			done := make(chan error, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				done <- s.Ingest(ctx, "robot", []Observation{pending}, now)
			}()
			defer func() {
				cancel()
				release()
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Error("ingest did not join during cleanup")
				}
			}()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("ingest did not reach controlled boundary")
			}
			cancel()
			// A valid read can still precede the server-side commit even after
			// the producer has canceled its request and stopped waiting for it.
			if attempts, successes := count(s); attempts != 4 || successes != 3 {
				t.Fatal("pre-drain baseline", attempts, successes)
			}
			release()
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("ingest did not finish")
			}
			want := 4
			if boundary == "inside_commit" {
				want = 5
				if err != nil {
					t.Fatal("entered SQLite commit failed", err)
				}
			} else {
				// Cancellation can interrupt the driver's BEGIN itself. SQLite
				// returns SQLITE_INTERRUPT without wrapping context.Canceled;
				// both reject the write, which the drained/reopened counts below
				// must prove. Do not accept unrelated database failures.
				var interrupted *sqlite.Error
				if !errors.Is(err, context.Canceled) && !(errors.As(err, &interrupted) && interrupted.Code() == sqlite3.SQLITE_INTERRUPT) {
					t.Fatal("pre-transaction cancellation", err)
				}
			}
			if attempts, successes := count(s); attempts != want || successes != 3 {
				t.Fatal("drained baseline", attempts, successes)
			}
			reopened, err := Open(s.path, now)
			if err != nil {
				t.Fatal(err)
			}
			if attempts, successes := count(reopened); attempts != want || successes != 3 {
				t.Fatal("restart changed drained baseline", attempts, successes)
			}
			if boundary == "inside_commit" {
				ingest(t, reopened, "robot", []Observation{pending}, now)
				if attempts, successes := count(reopened); attempts != want || successes != 3 {
					t.Fatal("retry duplicated committed observation", attempts, successes)
				}
			}
		})
	}
}
