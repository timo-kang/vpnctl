// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"vpnctl/internal/uplink"
)

const MaxUplinkSnapshots = 400_000
const MaxNodeUplinkSnapshots = 20_160
const uplinkSchema = `
CREATE TABLE uplink_snapshots(node TEXT NOT NULL, id TEXT NOT NULL, ts INTEGER NOT NULL,
 payload BLOB NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(node,id)) WITHOUT ROWID;
CREATE INDEX uplink_time ON uplink_snapshots(ts);
CREATE INDEX uplink_node_time ON uplink_snapshots(node,ts,id);
CREATE TABLE uplink_results(node TEXT NOT NULL,id TEXT NOT NULL,target TEXT NOT NULL,protocol TEXT NOT NULL,
 ts INTEGER NOT NULL,state TEXT NOT NULL,rtt REAL,PRIMARY KEY(node,id,target),
 FOREIGN KEY(node,id) REFERENCES uplink_snapshots(node,id) ON DELETE CASCADE) WITHOUT ROWID;
CREATE INDEX uplink_result_time ON uplink_results(node,ts);
CREATE TABLE uplink_series(node TEXT NOT NULL,target TEXT NOT NULL,protocol TEXT NOT NULL,PRIMARY KEY(node,target,protocol)) WITHOUT ROWID;
CREATE INDEX uplink_result_identity ON uplink_results(node,target,protocol);
CREATE TABLE uplink_latest(node TEXT PRIMARY KEY,ts INTEGER NOT NULL,id TEXT NOT NULL,payload BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE uplink_metadata(id INTEGER PRIMARY KEY CHECK(id=1),row_count INTEGER NOT NULL);
INSERT INTO uplink_metadata VALUES(1,0);
PRAGMA user_version=2;
`

type UplinkSummary struct {
	TargetID        string   `json:"target_id"`
	Protocol        string   `json:"protocol"`
	Samples         int      `json:"samples"`
	Successes       int      `json:"successes"`
	Failures        int      `json:"failures"`
	Unknown         int      `json:"unknown"`
	AvailabilityPct *float64 `json:"availability_pct"`
	AvgRTTMs        *float64 `json:"avg_rtt_ms"`
}
type UplinkHistory struct {
	SchemaVersion int               `json:"schema_version"`
	NodeID        string            `json:"node_id"`
	Start         time.Time         `json:"start"`
	End           time.Time         `json:"end"`
	Summaries     []UplinkSummary   `json:"summaries"`
	Snapshots     []uplink.Snapshot `json:"snapshots"` // newest first, limited; summaries cover whole window
	Truncated     bool              `json:"truncated"`
}

func packSnapshot(s uplink.Snapshot) ([]byte, []byte, error) {
	raw, e := json.Marshal(s)
	if e != nil {
		return nil, nil, e
	}
	if len(raw) > uplink.MaxSnapshotBytes {
		return nil, nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, e = z.Write(raw); e != nil {
		return nil, nil, e
	}
	if e = z.Close(); e != nil {
		return nil, nil, e
	}
	return out.Bytes(), digest[:], nil
}
func unpackSnapshot(b []byte) (uplink.Snapshot, error) {
	var s uplink.Snapshot
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return s, e
	}
	defer z.Close()
	raw, e := io.ReadAll(io.LimitReader(z, uplink.MaxSnapshotBytes+1))
	if e != nil || len(raw) > uplink.MaxSnapshotBytes {
		return s, fmt.Errorf("invalid stored uplink payload")
	}
	e = json.Unmarshal(raw, &s)
	return s, e
}
func (s *Store) IngestUplink(ctx context.Context, node string, snapshot uplink.Snapshot, now time.Time) error {
	snapshot.At = snapshot.At.UTC().Truncate(time.Microsecond)
	if !validLabel(node, true) {
		return ErrInvalid
	}
	if err := snapshot.Validate(now); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	payload, digest, err := packSnapshot(snapshot)
	if err != nil {
		return err
	}
	var previousSnapshot *uplink.Snapshot
	s.mu.RLock()
	if value, ok := s.uplinks[node]; ok {
		copy := value
		previousSnapshot = &copy
	}
	s.mu.RUnlock()
	if err = acquire(ctx, s.writer); err != nil {
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
	var previous []byte
	err = tx.QueryRowContext(ctx, "SELECT digest FROM uplink_snapshots WHERE node=? AND id=?", node, snapshot.ID).Scan(&previous)
	if err == nil {
		if !bytes.Equal(previous, digest) {
			return ErrConflict
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	var count, nodes, exists int
	if err = tx.QueryRowContext(ctx, "SELECT row_count FROM uplink_metadata WHERE id=1").Scan(&count); err != nil {
		return err
	}
	if count >= MaxUplinkSnapshots {
		return ErrCapacity
	}
	var nodeCount int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM uplink_snapshots WHERE node=?", node).Scan(&nodeCount); err != nil {
		return err
	}
	if nodeCount >= MaxNodeUplinkSnapshots {
		return ErrCapacity
	}

	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(node=?),0) FROM uplink_latest", node).Scan(&nodes, &exists); err != nil {
		return err
	}
	if exists == 0 && nodes >= 128 {
		return ErrCapacity
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO uplink_snapshots VALUES(?,?,?,?,?)", node, snapshot.ID, snapshot.At.UnixMicro(), payload, digest); err != nil {
		return err
	}
	for _, t := range snapshot.Targets {
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO uplink_series VALUES(?,?,?)", node, t.ID, t.Protocol); err != nil {
			return err
		}

		if _, err = tx.ExecContext(ctx, "INSERT INTO uplink_results VALUES(?,?,?,?,?,?,?)", node, snapshot.ID, t.ID, t.Protocol, snapshot.At.UnixMicro(), t.Service.State, t.Service.RTTMs); err != nil {
			return err
		}
	}
	var series, nodeSeries int
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(node=?),0) FROM uplink_series", node).Scan(&series, &nodeSeries); err != nil {
		return err
	}
	if series > 256 || nodeSeries > 16 {
		return ErrCapacity
	}
	if _, err = tx.ExecContext(ctx, "UPDATE uplink_metadata SET row_count=row_count+1 WHERE id=1"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uplink_latest VALUES(?,?,?,?) ON CONFLICT(node) DO UPDATE SET ts=excluded.ts,id=excluded.id,payload=excluded.payload
 WHERE (excluded.ts,excluded.id)>(uplink_latest.ts,uplink_latest.id)`, node, snapshot.At.UnixMicro(), snapshot.ID, payload); err != nil {
		return err
	}
	isLatest := previousSnapshot == nil || snapshot.At.After(previousSnapshot.At) || snapshot.At.Equal(previousSnapshot.At) && snapshot.ID > previousSnapshot.ID
	if isLatest {
		for _, event := range deriveUplinkEvents(node, previousSnapshot, snapshot) {
			event.ID = eventID(event)
			if _, err = insertEventTx(ctx, tx, node, event); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	latestSnapshot, ok := s.uplinks[node]
	if !ok || snapshot.At.After(latestSnapshot.At) || snapshot.At.Equal(latestSnapshot.At) && snapshot.ID > latestSnapshot.ID {
		detached, e := unpackSnapshot(payload)
		if e != nil {
			return e
		}
		s.uplinks[node] = detached
	}
	return nil
}
func (s *Store) LatestUplinks(now time.Time) map[string]uplink.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if now.IsZero() {
		now = time.Now()
	}
	out := map[string]uplink.Snapshot{}
	for node, snapshot := range s.uplinks {
		if !snapshot.At.After(now.Add(-Retention)) {
			continue
		}
		// Only small, bounded status snapshots; no SQLite or slow I/O under this lock.
		raw, _ := json.Marshal(snapshot)
		var detached uplink.Snapshot
		_ = json.Unmarshal(raw, &detached)
		out[node] = detached.Fresh(now)
	}
	return out
}
func (s *Store) loadUplinks(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "SELECT node,payload FROM uplink_latest LIMIT 129")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var node string
		var payload []byte
		if err = rows.Scan(&node, &payload); err != nil {
			return err
		}
		snapshot, e := unpackSnapshot(payload)
		if e != nil {
			return e
		}
		s.uplinks[node] = snapshot
	}
	if len(s.uplinks) > 128 {
		return ErrCapacity
	}
	return rows.Err()
}
func (s *Store) maintainUplinks(ctx context.Context, db *sql.DB, now time.Time) error {
	for {
		if err := s.limitWAL(ctx, db); err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM uplink_snapshots WHERE (node,id) IN (SELECT node,id FROM uplink_snapshots WHERE ts<=? LIMIT 1000)`, now.Add(-Retention).UnixMicro())
		if err != nil {
			tx.Rollback()
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE uplink_metadata SET row_count=row_count-? WHERE id=1", n); err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM uplink_latest WHERE ts<=?", now.Add(-Retention).UnixMicro()); err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM uplink_series WHERE NOT EXISTS(SELECT 1 FROM uplink_results r WHERE r.node=uplink_series.node AND r.target=uplink_series.target AND r.protocol=uplink_series.protocol)"); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if n < 1000 {
			s.mu.Lock()
			for node, v := range s.uplinks {
				if !v.At.After(now.Add(-Retention)) {
					delete(s.uplinks, node)
				}
			}
			s.mu.Unlock()
			return nil
		}
	}
}
func (s *Store) QueryUplinks(ctx context.Context, node string, end time.Time, window time.Duration, limit int) (UplinkHistory, error) {
	out := UplinkHistory{SchemaVersion: 1, NodeID: node, Start: end.Add(-window), End: end, Summaries: []UplinkSummary{}, Snapshots: []uplink.Snapshot{}}
	if !validLabel(node, true) || window <= 0 || window > Retention || limit < 1 || limit > 1000 {
		return out, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	if err := acquire(ctx, s.query); err != nil {
		return out, err
	}
	defer func() { <-s.query }()
	db, err := connect(s.path, true)
	if err != nil {
		return out, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT target,protocol,count(*),sum(state='up'),sum(state='down'),sum(state='unknown'),avg(rtt)
 FROM uplink_results WHERE node=? AND ts>? AND ts<=? GROUP BY target,protocol ORDER BY target,protocol LIMIT 257`, node, out.Start.UnixMicro(), end.UnixMicro())
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v UplinkSummary
		var avg sql.NullFloat64
		if err = rows.Scan(&v.TargetID, &v.Protocol, &v.Samples, &v.Successes, &v.Failures, &v.Unknown, &avg); err != nil {
			rows.Close()
			return out, err
		}
		if avg.Valid {
			v.AvgRTTMs = &avg.Float64
		}
		if n := v.Successes + v.Failures; n > 0 {
			v.AvailabilityPct = pointer(float64(v.Successes) * 100 / float64(n))
		}
		out.Summaries = append(out.Summaries, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(out.Summaries) > 256 {
		return out, ErrCapacity
	}
	rows, err = tx.QueryContext(ctx, "SELECT payload FROM uplink_snapshots WHERE node=? AND ts>? AND ts<=? ORDER BY ts DESC,id DESC LIMIT ?", node, out.Start.UnixMicro(), end.UnixMicro(), limit+1)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var payload []byte
		if err = rows.Scan(&payload); err != nil {
			rows.Close()
			return out, err
		}
		v, e := unpackSnapshot(payload)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Snapshots = append(out.Snapshots, v.Fresh(end))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(out.Snapshots) > limit {
		out.Truncated = true
		out.Snapshots = out.Snapshots[:limit]
	}
	return out, tx.Commit()
}
