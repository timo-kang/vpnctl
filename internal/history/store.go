// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"vpnctl/internal/quality"
)

const applicationID = 0x76706368
const schema = `
CREATE TABLE streams (
 id INTEGER PRIMARY KEY, node TEXT NOT NULL, peer TEXT NOT NULL, path TEXT NOT NULL,
 relay TEXT NOT NULL, uplink TEXT NOT NULL,
 UNIQUE(node,peer,path,relay,uplink)
);
CREATE TABLE probes (
 stream INTEGER NOT NULL REFERENCES streams(id), id TEXT NOT NULL,
 ts INTEGER NOT NULL, rtt INTEGER,
 PRIMARY KEY(stream,id)
) WITHOUT ROWID;
CREATE INDEX probe_time ON probes(ts);
CREATE INDEX probe_stream_time ON probes(stream,ts);
CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), row_count INTEGER NOT NULL);
INSERT INTO metadata VALUES(1,0);
PRAGMA application_id=1987076968;
PRAGMA user_version=1;
`

// Store opens short-lived connections: it owns no background goroutines or
// descriptors. Status reads use only published snapshots, never SQLite locks.
// Writers and expensive history queries are separately bounded and cancellable.
type Store struct {
	path        string
	writer      chan struct{}
	query       chan struct{}
	mu          sync.RWMutex
	latest      map[int64]Measurement
	lastCleanup time.Time // writer-owned
}

func connect(path string, readOnly bool) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
	}
	q.Add("_pragma", "busy_timeout(1000)")
	q.Add("_pragma", "foreign_keys(1)")
	if !readOnly {
		q.Add("_pragma", "synchronous(FULL)")
		q.Add("_pragma", "wal_autocheckpoint(1000)")
		q.Add("_pragma", "journal_size_limit(16777216)")
		q.Add("_pragma", "max_page_count(262144)")
	} // 1 GiB at 4096 bytes/page
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func Open(path string, now time.Time) (*Store, error) {
	if !filepath.IsAbs(path) {
		var err error
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// Refuse symlinks/special files and create private data from the first byte.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if err = f.Close(); err != nil {
			return nil, err
		}
	} else if !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<30 {
		return nil, fmt.Errorf("history must be a regular file")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	db, err := connect(path, false)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var pageSize int
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, err
	}
	if pageSize != 4096 {
		return nil, fmt.Errorf("history requires 4096-byte pages")
	}
	var version, app int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return nil, err
	}
	if version == 0 && app == 0 {
		var tables int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return nil, err
		}
		if tables != 0 {
			return nil, fmt.Errorf("not an empty history database")
		}
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, schema); e != nil {
			tx.Rollback()
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	} else if version != 1 || app != applicationID {
		return nil, fmt.Errorf("unsupported history schema: version=%d application=%d", version, app)
	}
	var journal string
	if err = db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil {
		return nil, err
	}
	if journal != "wal" {
		return nil, fmt.Errorf("WAL unavailable: %s", journal)
	}
	s := &Store{path: path, writer: make(chan struct{}, 1), query: make(chan struct{}, 1), latest: make(map[int64]Measurement)}
	// A fresh process replays retained observations; never restores a stale 'good'
	// flag. Empty/old history remains explicitly unknown at read time.
	if err = s.maintainDB(ctx, db, now); err != nil {
		return nil, err
	}
	streams, err := readStreams(ctx, db, "")
	if err != nil {
		return nil, err
	}
	if len(streams) > MaxStreams {
		return nil, ErrCapacity
	}
	for _, st := range streams {
		m, e := replay(ctx, db, st.id, st.Stream)
		if e != nil {
			return nil, e
		}
		s.latest[st.id] = m
	}
	return s, nil
}

func acquire(ctx context.Context, ch chan struct{}) error {
	select {
	case ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type streamRow struct {
	id int64
	Stream
}

func readStreams(ctx context.Context, db reader, node string) ([]streamRow, error) {
	query := "SELECT id,node,peer,path,relay,uplink FROM streams"
	var args []any
	if node != "" {
		query += " WHERE node=?"
		args = append(args, node)
	}
	query += " ORDER BY node,peer,path,relay,uplink LIMIT 257"
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []streamRow
	for rows.Next() {
		var s streamRow
		if err = rows.Scan(&s.id, &s.NodeID, &s.PeerID, &s.Path, &s.RelayID, &s.Uplink); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Ingest atomically validates/deduplicates the complete batch before publishing
// status. Retried identical IDs are idempotent; conflicting IDs abort the batch.
func (s *Store) Ingest(ctx context.Context, node string, observations []Observation, now time.Time) error {
	if len(observations) == 0 || len(observations) > MaxBatch {
		return fmt.Errorf("%w: batch must contain 1..%d probes", ErrInvalid, MaxBatch)
	}
	now = now.UTC().Truncate(time.Microsecond)
	observations = append([]Observation(nil), observations...)
	for i := range observations {
		observations[i].Timestamp = observations[i].Timestamp.UTC().Truncate(time.Microsecond)
	}
	for _, o := range observations {
		if err := Validate(node, o, now); err != nil {
			return err
		}
	}
	if err := acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	if now.Sub(s.lastCleanup) >= time.Minute {
		if err = s.maintainDB(ctx, db, now); err != nil {
			return err
		}
	}
	if err = s.limitWAL(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	affected := map[int64]Stream{}
	added := int64(0)
	for _, o := range observations {
		st := Stream{node, o.PeerID, o.Path, o.RelayID, o.Uplink}
		var id int64
		err = tx.QueryRowContext(ctx, "SELECT id FROM streams WHERE node=? AND peer=? AND path=? AND relay=? AND uplink=?", node, o.PeerID, o.Path, o.RelayID, o.Uplink).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			var total, own int
			if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(node=?),0) FROM streams", node).Scan(&total, &own); err != nil {
				return err
			}
			if total >= MaxStreams || own >= MaxNodeStreams {
				return ErrCapacity
			}
			res, e := tx.ExecContext(ctx, "INSERT INTO streams(node,peer,path,relay,uplink) VALUES(?,?,?,?,?)", node, o.PeerID, o.Path, o.RelayID, o.Uplink)
			if e != nil {
				return e
			}
			id, err = res.LastInsertId()
		}
		if err != nil {
			return err
		}
		var rtt any
		if o.RTTMs != nil {
			rtt = int64(math.Round(*o.RTTMs * 1000))
		}
		res, e := tx.ExecContext(ctx, "INSERT INTO probes(stream,id,ts,rtt) VALUES(?,?,?,?) ON CONFLICT(stream,id) DO NOTHING", id, o.ID, o.Timestamp.UnixMicro(), rtt)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			var ts int64
			var old sql.NullInt64
			if e = tx.QueryRowContext(ctx, "SELECT ts,rtt FROM probes WHERE stream=? AND id=?", id, o.ID).Scan(&ts, &old); e != nil {
				return e
			}
			if ts != o.Timestamp.UnixMicro() || old.Valid != (rtt != nil) || (old.Valid && old.Int64 != rtt.(int64)) {
				return ErrConflict
			}
		}
		added += n
		affected[id] = st
	}
	var count int64
	if err = tx.QueryRowContext(ctx, "SELECT row_count FROM metadata WHERE id=1").Scan(&count); err != nil {
		return err
	}
	if count+added > MaxRows {
		return ErrCapacity
	}
	// Replay before commit: pathological per-stream sample density is rejected
	// atomically, not acknowledged before discovering an unusable snapshot.
	updates := map[int64]Measurement{}
	for id, st := range affected {
		m, e := replay(ctx, tx, id, st)
		if e != nil {
			return e
		}
		updates[id] = m
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET row_count=row_count+? WHERE id=1", added); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.mu.Lock()
	for id, m := range updates {
		s.latest[id] = m
	}
	s.mu.Unlock()
	return nil
}

type reader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func replay(ctx context.Context, db reader, id int64, st Stream) (Measurement, error) {
	var last sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT max(ts) FROM probes WHERE stream=?", id).Scan(&last); err != nil {
		return Measurement{}, err
	}
	samples := []quality.Sample{}
	if last.Valid {
		rows, err := db.QueryContext(ctx, "SELECT ts,rtt FROM probes WHERE stream=? AND ts>? AND ts<=? ORDER BY ts,id LIMIT ?", id, last.Int64-int64(2*time.Minute/time.Microsecond), last.Int64, MaxWindowSamples+1)
		if err != nil {
			return Measurement{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var ts int64
			var rtt sql.NullInt64
			if err = rows.Scan(&ts, &rtt); err != nil {
				return Measurement{}, err
			}
			samples = append(samples, quality.Sample{Timestamp: time.UnixMicro(ts).UTC(), RTTus: rtt.Int64, Success: rtt.Valid})
		}
		if err = rows.Err(); err != nil {
			return Measurement{}, err
		}
		if len(samples) > MaxWindowSamples {
			return Measurement{}, ErrCapacity
		}
	}
	q := quality.ReplayQuality(samples)
	q.PeerIP = st.PeerID
	var lastSuccess sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT max(ts) FROM probes WHERE stream=? AND rtt IS NOT NULL", id).Scan(&lastSuccess); err != nil {
		return Measurement{}, err
	}
	if lastSuccess.Valid {
		at := time.UnixMicro(lastSuccess.Int64).UTC()
		q.LastSuccessAt = &at
	}
	return Measurement{Stream: st, PeerQuality: q}, nil
}

func (s *Store) Latest(now time.Time) map[string][]Measurement {
	out := make(map[string][]Measurement)
	s.mu.RLock()
	if now.IsZero() {
		now = time.Now()
	}
	for _, m := range s.latest {
		m.PeerQuality = quality.FreshQuality(m.PeerQuality, now)
		out[m.NodeID] = append(out[m.NodeID], m)
	}
	s.mu.RUnlock()
	for node := range out {
		sort.Slice(out[node], func(i, j int) bool {
			a, b := out[node][i], out[node][j]
			if a.ObservedAt == nil {
				return false
			}
			if b.ObservedAt == nil {
				return true
			}
			if !a.ObservedAt.Equal(*b.ObservedAt) {
				return a.ObservedAt.After(*b.ObservedAt)
			}
			return fmt.Sprint(a.Stream) < fmt.Sprint(b.Stream)
		})
	}
	return out
}

func (s *Store) Maintain(ctx context.Context, now time.Time) error {
	if err := acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	return s.maintainDB(ctx, db, now)
}
func (s *Store) maintainDB(ctx context.Context, db *sql.DB, now time.Time) error {
	// Commit expired rows in bounded batches. A long outage/clock jump can expire
	// the entire database; cancelling one enormous DELETE would otherwise undo
	// every bit of cleanup and exhaust each subsequent request's budget again.
	for {
		if err := s.limitWAL(ctx, db); err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM probes WHERE (stream,id) IN
    (SELECT stream,id FROM probes WHERE ts<=? LIMIT 10000)`, now.Add(-Retention).UnixMicro())
		if err != nil {
			tx.Rollback()
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE metadata SET row_count=row_count-? WHERE id=1", n); err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM streams WHERE NOT EXISTS(SELECT 1 FROM probes WHERE stream=streams.id)"); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		s.mu.Lock()
		for id, m := range s.latest {
			if m.ObservedAt == nil || !m.ObservedAt.After(now.Add(-Retention)) {
				delete(s.latest, id)
			}
		}
		s.mu.Unlock()
		if n < 10000 {
			s.lastCleanup = now
			return nil
		}
	}
}

// A long reader pins WAL frames. Backpressure above this watermark prevents an
// unbounded log; the next write checkpoints once that reader has released it.
// One bounded transaction may cross the watermark before the following check.
func (s *Store) limitWAL(ctx context.Context, db *sql.DB) error {
	info, err := os.Stat(s.path + "-wal")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() <= 64<<20 {
		return nil
	}
	var busy, frames, checkpointed int
	if err = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return ErrCapacity
	}
	return nil
}
