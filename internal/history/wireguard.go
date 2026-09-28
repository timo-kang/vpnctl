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
	"errors"
	"fmt"
	"io"
	"time"

	"vpnctl/internal/wgstats"
)

const MaxWireGuardRows = 400_000
const MaxNodeWireGuardRows = 10_080
const MaxWireGuardBytes = 128 << 20
const MaxWireGuardNodes = 64
const wireGuardSchema = `
CREATE TABLE wireguard_reports(node TEXT NOT NULL,id TEXT NOT NULL,ts INTEGER NOT NULL,payload BLOB NOT NULL,digest BLOB NOT NULL,PRIMARY KEY(node,id)) WITHOUT ROWID;
CREATE INDEX wireguard_time ON wireguard_reports(ts,node,id);
CREATE INDEX wireguard_node_time ON wireguard_reports(node,ts,id);
CREATE TABLE wireguard_metadata(id INTEGER PRIMARY KEY CHECK(id=1),rows INTEGER NOT NULL,bytes INTEGER NOT NULL,evicted INTEGER NOT NULL,expired INTEGER NOT NULL,loss_start INTEGER,loss_end INTEGER);
INSERT INTO wireguard_metadata VALUES(1,0,0,0,0,NULL,NULL);
CREATE TRIGGER wireguard_insert AFTER INSERT ON wireguard_reports BEGIN UPDATE wireguard_metadata SET rows=rows+1,bytes=bytes+length(new.payload) WHERE id=1; END;
CREATE TRIGGER wireguard_delete AFTER DELETE ON wireguard_reports BEGIN UPDATE wireguard_metadata SET rows=rows-1,bytes=bytes-length(old.payload) WHERE id=1; END;
`

// Versions 15..19 preserve each v5..9 probe format/feature combination.
func probeSchemaVersion(v int) int {
	if v >= 15 && v <= 19 {
		return v - 10
	}
	return v
}
func supportedHistoryVersion(v int) bool { return v >= 1 && v <= 9 || v >= 15 && v <= 19 }
func preserveWireGuardVersion(ctx context.Context, tx *sql.Tx, enabled bool, base int) error {
	if enabled {
		base += 10
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", base))
	return err
}
func packWireGuard(r wgstats.Report) ([]byte, []byte, error) {
	b, e := json.Marshal(r)
	if e != nil {
		return nil, nil, e
	}
	if len(b) > wgstats.MaxReportBytes {
		return nil, nil, ErrInvalid
	}
	digest := sha256.Sum256(b)
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, e = z.Write(b); e != nil {
		return nil, nil, e
	}
	if e = z.Close(); e != nil {
		return nil, nil, e
	}
	return out.Bytes(), digest[:], nil
}
func unpackWireGuard(b []byte) (wgstats.Report, error) {
	var r wgstats.Report
	if len(b) > wgstats.MaxReportBytes {
		return r, ErrInvalid
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return r, e
	}
	defer z.Close()
	raw, e := io.ReadAll(io.LimitReader(z, wgstats.MaxReportBytes+1))
	if e != nil {
		return r, e
	}
	if len(raw) > wgstats.MaxReportBytes {
		return r, ErrInvalid
	}
	e = json.Unmarshal(raw, &r)
	return r, e
}
func (s *Store) IngestWireGuard(ctx context.Context, r wgstats.Report, now time.Time) error {
	r = r.Clone()
	if e := r.Validate(now); e != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, e)
	}
	payload, digest, err := packWireGuard(r)
	if err != nil {
		return err
	}
	if err = acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = s.limitWAL(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabling := !s.wgEnabled.Load()
	if enabling {
		if _, err = tx.ExecContext(ctx, wireGuardSchema); err != nil {
			return err
		}
		var v int
		if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
			return err
		}
		if err = preserveWireGuardVersion(ctx, tx, true, v); err != nil {
			return err
		}
	}
	node := r.Reporter.NodeID
	var oldDigest []byte
	err = tx.QueryRowContext(ctx, "SELECT digest FROM wireguard_reports WHERE node=? AND id=?", node, r.ID).Scan(&oldDigest)
	if err == nil {
		if bytes.Equal(oldDigest, digest) {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var last int64
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT coalesce(max(ts),0),count(*) FROM wireguard_reports WHERE node=?", node).Scan(&last, &count); err != nil {
		return err
	}
	// Retries keep their original body. Out-of-order new records cannot advance
	// the published baseline, or generate a rate across reversed collection time.
	if last >= r.ObservedAt.UnixMicro() {
		return ErrConflict
	}
	var nodes int
	if count == 0 {
		if err = tx.QueryRowContext(ctx, "SELECT count(DISTINCT node) FROM wireguard_reports").Scan(&nodes); err != nil {
			return err
		}
		if nodes >= MaxWireGuardNodes {
			return &QuotaError{"wireguard_nodes", MaxWireGuardNodes}
		}
	}
	var rows, used int
	if err = tx.QueryRowContext(ctx, "SELECT rows,bytes FROM wireguard_metadata WHERE id=1").Scan(&rows, &used); err != nil {
		return err
	}
	evictedNodes := map[string]bool{}
	for attempts := 0; rows >= MaxWireGuardRows || used+len(payload) > MaxWireGuardBytes || count >= MaxNodeWireGuardRows; attempts++ {
		if attempts == 64 {
			return &QuotaError{"wireguard_bytes", MaxWireGuardBytes}
		}
		query := "SELECT node,id,ts,length(payload) FROM wireguard_reports"
		var args []any
		if count >= MaxNodeWireGuardRows {
			query += " WHERE node=?"
			args = append(args, node)
		}
		query += " ORDER BY ts,node,id LIMIT 1"
		var n, id string
		var ts int64
		var size int
		if err = tx.QueryRowContext(ctx, query, args...).Scan(&n, &id, &ts, &size); err != nil {
			return err
		}
		if err = deleteWireGuard(ctx, tx, n, id, ts, "evicted"); err != nil {
			return err
		}
		evictedNodes[n] = true
		rows--
		used -= size
		if n == node {
			count--
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO wireguard_reports VALUES(?,?,?,?,?)", node, r.ID, r.ObservedAt.UnixMicro(), payload, digest); err != nil {
		return err
	}
	var forgotten []string
	for n := range evictedNodes {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM wireguard_reports WHERE node=?)", n).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			forgotten = append(forgotten, n)
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.wgEnabled.Store(true)
	s.mu.Lock()
	for _, n := range forgotten {
		delete(s.wgRecent, n)
	}
	if s.wgRecent == nil {
		s.wgRecent = map[string][]wgstats.Report{}
	}
	old := s.wgRecent[node]
	s.wgRecent[node] = []wgstats.Report{r}
	if len(old) > 0 {
		s.wgRecent[node] = append(s.wgRecent[node], old[0])
	}
	s.mu.Unlock()
	return nil
}
func deleteWireGuard(ctx context.Context, tx *sql.Tx, node, id string, ts int64, reason string) error {
	if _, e := tx.ExecContext(ctx, "DELETE FROM wireguard_reports WHERE node=? AND id=?", node, id); e != nil {
		return e
	}
	// reason is an internal constant, never request data. Range is a fleet-wide
	// envelope, not a claim that every record inside that interval was deleted.
	_, e := tx.ExecContext(ctx, "UPDATE wireguard_metadata SET "+reason+"="+reason+"+1,loss_start=min(coalesce(loss_start,?),?),loss_end=max(coalesce(loss_end,?),?) WHERE id=1", ts, ts, ts, ts)
	return e
}
func (s *Store) maintainWireGuard(ctx context.Context, db *sql.DB, now time.Time) error {
	if !s.wgEnabled.Load() {
		return nil
	}
	for {
		if e := s.limitWAL(ctx, db); e != nil {
			return e
		}
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, "SELECT node,id,ts FROM wireguard_reports WHERE ts<=? ORDER BY ts LIMIT 1000", now.Add(-wgstats.Retention).UnixMicro())
		if e != nil {
			tx.Rollback()
			return e
		}
		type expired struct {
			node, id string
			ts       int64
		}
		var list []expired
		for rows.Next() {
			var x expired
			if e = rows.Scan(&x.node, &x.id, &x.ts); e != nil {
				break
			}
			list = append(list, x)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e == nil {
			for _, x := range list {
				if e = deleteWireGuard(ctx, tx, x.node, x.id, x.ts, "expired"); e != nil {
					break
				}
			}
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		if len(list) < 1000 {
			break
		}
	}
	s.mu.Lock()
	for node, r := range s.wgRecent {
		if len(r) == 0 || !r[0].ObservedAt.After(now.Add(-wgstats.Retention)) {
			delete(s.wgRecent, node)
		}
	}
	s.mu.Unlock()
	return nil
}
func (s *Store) loadWireGuard(ctx context.Context, db *sql.DB) error {
	if !s.wgEnabled.Load() {
		return nil
	}
	rows, e := db.QueryContext(ctx, "SELECT DISTINCT node FROM wireguard_reports LIMIT ?", MaxWireGuardNodes+1)
	if e != nil {
		return e
	}
	var nodes []string
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			break
		}
		nodes = append(nodes, n)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	if len(nodes) > MaxWireGuardNodes {
		return ErrCapacity
	}
	s.wgRecent = map[string][]wgstats.Report{}
	for _, n := range nodes {
		r, e := readWireGuard(ctx, db, n, time.Time{}, time.Time{}, 2)
		if e != nil {
			return e
		}
		s.wgRecent[n] = r
	}
	return nil
}
func readWireGuard(ctx context.Context, db reader, node string, start, end time.Time, limit int) ([]wgstats.Report, error) {
	query := "SELECT payload,digest,id,ts FROM wireguard_reports WHERE node=?"
	args := []any{node}
	if !start.IsZero() {
		query += " AND ts>?"
		args = append(args, start.UnixMicro())
	}
	if !end.IsZero() {
		query += " AND ts<=?"
		args = append(args, end.UnixMicro())
	}
	query += " ORDER BY ts DESC,id DESC LIMIT ?"
	args = append(args, limit)
	rows, e := db.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []wgstats.Report{}
	bytesUsed := 0
	for rows.Next() {
		var b, digest []byte
		var id string
		var ts int64
		if e = rows.Scan(&b, &digest, &id, &ts); e != nil {
			return nil, e
		}
		r, e := unpackWireGuard(b)
		if e != nil {
			return nil, e
		}
		encoded, e := json.Marshal(r)
		if e != nil {
			return nil, e
		}
		sum := sha256.Sum256(encoded)
		if r.Validate(r.ObservedAt) != nil || r.Reporter.NodeID != node || r.ID != id || r.ObservedAt.UnixMicro() != ts || !bytes.Equal(sum[:], digest) {
			return nil, fmt.Errorf("invalid WireGuard history record")
		}
		bytesUsed += len(encoded)
		if bytesUsed > 8<<20 {
			break
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) LatestWireGuard(now time.Time) map[string]wgstats.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := map[string]wgstats.Snapshot{}
	for node, recent := range s.wgRecent {
		if len(recent) == 0 || !recent[0].ObservedAt.After(now.Add(-wgstats.Retention)) {
			continue
		}
		var prev *wgstats.Report
		if len(recent) > 1 {
			prev = &recent[1]
		}
		out[node] = wgstats.CompareReport(recent[0], prev, now)
	}
	return out
}

type WireGuardStorage struct {
	Enabled          bool       `json:"enabled"`
	Scope            string     `json:"scope"`
	Rows             int        `json:"rows"`
	Bytes            int        `json:"compressed_bytes"`
	MaxRows          int        `json:"max_rows"`
	MaxBytes         int        `json:"max_compressed_bytes"`
	MaxNodeRows      int        `json:"max_node_rows"`
	RetentionSeconds float64    `json:"retention_seconds"`
	Evicted          uint64     `json:"evicted_reports,string"`
	Expired          uint64     `json:"expired_reports,string"`
	LossStart        *time.Time `json:"loss_start"`
	LossEnd          *time.Time `json:"loss_end"`
}
type WireGuardHistory struct {
	SchemaVersion int                `json:"schema_version"`
	NodeID        string             `json:"node_id"`
	Start         time.Time          `json:"start"`
	End           time.Time          `json:"end"`
	Storage       WireGuardStorage   `json:"storage"`
	Snapshots     []wgstats.Snapshot `json:"snapshots"`
	Truncated     bool               `json:"truncated"`
}

func wireGuardLimits() WireGuardStorage {
	return WireGuardStorage{Scope: "fleet", MaxRows: MaxWireGuardRows, MaxBytes: MaxWireGuardBytes, MaxNodeRows: MaxNodeWireGuardRows, RetentionSeconds: wgstats.Retention.Seconds()}
}
func wireGuardStorage(ctx context.Context, db reader) (WireGuardStorage, error) {
	s := wireGuardLimits()
	s.Enabled = true
	var start, end sql.NullInt64
	e := db.QueryRowContext(ctx, "SELECT rows,bytes,evicted,expired,loss_start,loss_end FROM wireguard_metadata WHERE id=1").Scan(&s.Rows, &s.Bytes, &s.Evicted, &s.Expired, &start, &end)
	if start.Valid {
		v := time.UnixMicro(start.Int64).UTC()
		s.LossStart = &v
	}
	if end.Valid {
		v := time.UnixMicro(end.Int64).UTC()
		s.LossEnd = &v
	}
	return s, e
}
func (s *Store) QueryWireGuard(ctx context.Context, node string, now time.Time, window time.Duration, limit int) (WireGuardHistory, error) {
	out := WireGuardHistory{Storage: wireGuardLimits(), SchemaVersion: 1, NodeID: node, Start: now.Add(-window), End: now, Snapshots: []wgstats.Snapshot{}}
	if !validLabel(node, true) || window <= 0 || window > wgstats.Retention || limit < 1 || limit > 100 {
		return out, ErrInvalid
	}
	if !s.wgEnabled.Load() {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	if e := acquire(ctx, s.query); e != nil {
		return out, e
	}
	defer func() { <-s.query }()
	db, e := connect(s.path, true)
	if e != nil {
		return out, e
	}
	defer db.Close()
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	out.Storage, e = wireGuardStorage(ctx, tx)
	if e != nil {
		return out, e
	}
	rs, e := readWireGuard(ctx, tx, node, out.Start, now, limit+1)
	if e != nil {
		return out, e
	}
	var total int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM wireguard_reports WHERE node=? AND ts>? AND ts<=?", node, out.Start.UnixMicro(), now.UnixMicro()).Scan(&total); e != nil {
		return out, e
	}
	out.Truncated = len(rs) > limit
	// Bound the response by bytes as well as count, including computed views.
	bytesUsed := 0
	for i, r := range rs {
		if i == limit {
			break
		}
		var prev *wgstats.Report
		if i+1 < len(rs) {
			prev = &rs[i+1]
		}
		v := wgstats.CompareReport(r, prev, r.ObservedAt)
		b, e := json.Marshal(v)
		if e != nil {
			return out, e
		}
		if bytesUsed+len(b) > 4<<20 {
			out.Truncated = true
			break
		}
		bytesUsed += len(b)
		out.Snapshots = append(out.Snapshots, v)
	}
	out.Truncated = total > len(out.Snapshots)
	return out, tx.Commit()
}
func checkWireGuard(ctx context.Context, db *sql.DB) error {
	meta, e := wireGuardStorage(ctx, db)
	if e != nil {
		return e
	}
	var count, size, nodes int
	if e = db.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(payload)),0),count(DISTINCT node) FROM wireguard_reports").Scan(&count, &size, &nodes); e != nil {
		return e
	}
	if meta.LossStart != nil && (meta.LossEnd == nil || meta.LossStart.After(*meta.LossEnd)) || meta.LossStart == nil && meta.LossEnd != nil || (meta.Evicted+meta.Expired > 0) != (meta.LossStart != nil) {
		return fmt.Errorf("invalid WireGuard loss envelope")
	}
	if count != meta.Rows || size != meta.Bytes || count > MaxWireGuardRows || size > MaxWireGuardBytes || nodes > MaxWireGuardNodes {
		return fmt.Errorf("invalid WireGuard storage counts")
	}
	var bad bool
	if e = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM wireguard_reports GROUP BY node HAVING count(*)>?)", MaxNodeWireGuardRows).Scan(&bad); e != nil {
		return e
	}
	if bad {
		return fmt.Errorf("WireGuard node capacity")
	}
	rows, e := db.QueryContext(ctx, "SELECT node,id,ts,payload,digest FROM wireguard_reports")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var node, id string
		var ts int64
		var payload, digest []byte
		if e = rows.Scan(&node, &id, &ts, &payload, &digest); e != nil {
			return e
		}
		r, e := unpackWireGuard(payload)
		if e != nil {
			return e
		}
		_, got, e := packWireGuard(r)
		if e != nil || r.Validate(r.ObservedAt) != nil || r.Reporter.NodeID != node || r.ID != id || r.ObservedAt.UnixMicro() != ts || !bytes.Equal(got, digest) {
			return fmt.Errorf("invalid WireGuard history record")
		}
	}
	return rows.Err()
}
