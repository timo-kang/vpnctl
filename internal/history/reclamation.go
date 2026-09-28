// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	MaxReclamationRows = 65536
	maxReclaimRows     = 1024
	maxReclaimBytes    = 4 << 20
)

const reclamationSchema = `
CREATE TABLE reclamation_metadata (
 id INTEGER PRIMARY KEY CHECK(id=1),
 next_stream_id INTEGER NOT NULL CHECK(typeof(next_stream_id)='integer' AND next_stream_id>0),
 evicted_streams INTEGER NOT NULL CHECK(typeof(evicted_streams)='integer' AND evicted_streams>=0),
 evicted_samples INTEGER NOT NULL CHECK(typeof(evicted_samples)='integer' AND evicted_samples>=0),
 expired_samples INTEGER NOT NULL CHECK(typeof(expired_samples)='integer' AND expired_samples>=0),
 loss_rows INTEGER NOT NULL CHECK(loss_rows>=0)
);
INSERT INTO reclamation_metadata SELECT 1,coalesce(max(id),0)+1,0,0,0,0 FROM streams;
CREATE TABLE history_loss (
 node TEXT NOT NULL, source TEXT NOT NULL, end_ts INTEGER NOT NULL,
 samples INTEGER NOT NULL CHECK(typeof(samples)='integer' AND samples>0),
 PRIMARY KEY(node,source,end_ts)
) WITHOUT ROWID;
CREATE INDEX history_loss_time ON history_loss(end_ts);
PRAGMA user_version=7;
`

func (s *Store) ReclamationEnabled() bool { return s.reclamation.Load() }

// EnableReclamation is an explicit offline migration from v6. The CLI takes
// the ownership lock and a checked backup first. Opening v6 never enables it.
func (s *Store) EnableReclamation(ctx context.Context) error {
	if err := acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	if s.ReclamationEnabled() {
		return nil
	}
	if !s.Tiered() {
		return fmt.Errorf("enable tiered history before path reclamation")
	}
	if err := Check(ctx, s.path); err != nil {
		return err
	}
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, reclamationSchema); err != nil {
		return err
	}
	version := 7
	if s.JitterEnabled() {
		version = 9
	}
	if err = preserveWireGuardVersion(ctx, tx, s.wgEnabled.Load(), version); err != nil {
		return err
	}
	if err = checkProbeSpace(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.reclamation.Store(true)
	return nil
}

type reclaimCandidate struct {
	id, rows, bytes int64
	node, source    string
}

type pathReclaimer struct {
	protected             map[Stream]struct{}
	candidates            []reclaimCandidate
	loaded                bool
	removed               []int64
	rows, bytes, lossRows int64
}

// A bounded candidate list is loaded once per ingest, avoiding a fleet scan
// for every stream in a batch. Prefer the submitting node's old paths. A node
// quota can only be relieved by reclaiming that node's own archived paths.
func (r *pathReclaimer) reclaim(ctx context.Context, tx *sql.Tx, node string, ownOnly bool, seal int64) (string, bool, error) {
	if !r.loaded {
		if err := tx.QueryRowContext(ctx, "SELECT loss_rows FROM reclamation_metadata WHERE id=1").Scan(&r.lossRows); err != nil {
			return "", false, err
		}
		query := `SELECT s.id,s.node,s.source,s.peer,s.path,s.relay,s.uplink,count(a.end_ts),coalesce(sum(length(a.payload)),0)
FROM streams s JOIN probe_live l ON l.stream=s.id LEFT JOIN rollups a ON a.stream=s.id
WHERE l.observed<=? AND NOT EXISTS(SELECT 1 FROM probes p WHERE p.stream=s.id)`
		args := []any{seal}
		if ownOnly {
			query += " AND s.node=?"
			args = append(args, node)
		}
		query += `
GROUP BY s.id HAVING count(a.end_ts)<=? AND coalesce(sum(length(a.payload)),0)<=?
ORDER BY (s.node=?) DESC,l.observed,s.id LIMIT ?`
		// At most MaxBatch paths are protected by the incoming upload. Fetch
		// enough candidates to skip all of them without hiding eligible paths.
		args = append(args, maxReclaimRows, maxReclaimBytes, node, 2*MaxBatch)
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return "", false, err
		}
		for rows.Next() {
			var c reclaimCandidate
			var st Stream
			if err = rows.Scan(&c.id, &c.node, &c.source, &st.PeerID, &st.Path, &st.RelayID, &st.Uplink, &c.rows, &c.bytes); err != nil {
				break
			}
			st.NodeID, st.Source = c.node, c.source
			if _, protected := r.protected[st]; protected {
				continue
			}
			r.candidates = append(r.candidates, c)
		}
		e := rows.Err()
		rows.Close()
		if err != nil {
			return "", false, err
		}
		if e != nil {
			return "", false, e
		}
		r.loaded = true
	}
	if len(r.candidates) == 0 || (ownOnly && r.candidates[0].node != node) {
		return "", false, nil
	}
	c := r.candidates[0]
	if r.rows+c.rows > maxReclaimRows {
		return "", false, &QuotaError{Resource: "reclamation_work", Limit: maxReclaimRows}
	}
	if r.bytes+c.bytes > maxReclaimBytes {
		return "", false, &QuotaError{Resource: "reclamation_work_bytes", Limit: maxReclaimBytes}
	}
	r.candidates = r.candidates[1:]
	rows, err := tx.QueryContext(ctx, "SELECT end_ts,payload FROM rollups WHERE stream=? ORDER BY end_ts", c.id)
	if err != nil {
		return "", false, err
	}
	type loss struct{ end, samples int64 }
	var losses []loss
	var samples int64
	for rows.Next() {
		var end int64
		var data []byte
		if err = rows.Scan(&end, &data); err != nil {
			break
		}
		a, e := DecodeProbeAggregate(data)
		if e != nil {
			err = fmt.Errorf("corrupt reclaimed aggregate: %v", e)
			break
		}
		n := a.attempts + a.unknown
		if n <= 0 || end > seal {
			err = fmt.Errorf("invalid reclaimed aggregate interval or population")
			break
		}
		losses = append(losses, loss{end, n})
		samples += n
	}
	e := rows.Err()
	rows.Close()
	if err != nil {
		return "", false, err
	}
	if e != nil {
		return "", false, e
	}
	for _, l := range losses {
		res, e := tx.ExecContext(ctx, `INSERT INTO history_loss(node,source,end_ts,samples) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, c.node, c.source, l.end, l.samples)
		if e != nil {
			return "", false, e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return "", false, e
		}
		if n == 0 {
			if _, e = tx.ExecContext(ctx, "UPDATE history_loss SET samples=samples+? WHERE node=? AND source=? AND end_ts=?", l.samples, c.node, c.source, l.end); e != nil {
				return "", false, e
			}
		}
		r.lossRows += n
	}
	if r.lossRows > MaxReclamationRows {
		return "", false, &QuotaError{Resource: "reclamation_rows", Limit: MaxReclamationRows}
	}
	for _, q := range []string{"DELETE FROM rollups WHERE stream=?", "DELETE FROM probe_live WHERE stream=?", "DELETE FROM streams WHERE id=?"} {
		if _, err = tx.ExecContext(ctx, q, c.id); err != nil {
			return "", false, err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tier_metadata SET rollup_rows=rollup_rows-?,rollup_bytes=rollup_bytes-? WHERE id=1", c.rows, c.bytes); err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE reclamation_metadata SET evicted_streams=evicted_streams+1,evicted_samples=evicted_samples+?,loss_rows=? WHERE id=1", samples, r.lossRows); err != nil {
		return "", false, err
	}
	r.rows += c.rows
	r.bytes += c.bytes
	r.removed = append(r.removed, c.id)
	return c.node, true, nil
}

// HistoryCoverage describes deliberate reclamation losses in the entire
// requested node/source window, not just this page. Do not sum it across pages.
// Partial identifies reclamation losses; false does not imply a producer ran.
type HistoryCoverage struct {
	Partial           bool       `json:"partial"`
	DiscardedSamples  int64      `json:"discarded_samples"`
	FirstAffected     *time.Time `json:"first_affected,omitempty"`
	LastAffected      *time.Time `json:"last_affected,omitempty"`
	ResolutionSeconds int64      `json:"resolution_seconds"`
}

func (v HistoryCoverage) Valid(start, end time.Time) bool {
	if v.ResolutionSeconds != 3600 || v.DiscardedSamples < 0 || v.Partial != (v.DiscardedSamples > 0) {
		return false
	}
	if !v.Partial {
		return v.FirstAffected == nil && v.LastAffected == nil
	}
	return v.FirstAffected != nil && v.LastAffected != nil &&
		!v.FirstAffected.Before(start) && !v.LastAffected.After(end) && v.FirstAffected.Before(*v.LastAffected) &&
		v.FirstAffected.Equal(v.FirstAffected.UTC().Truncate(time.Hour)) && v.LastAffected.Equal(v.LastAffected.UTC().Truncate(time.Hour))
}

func queryCoverage(ctx context.Context, db reader, node, source string, start, end time.Time) (*HistoryCoverage, error) {
	q := "SELECT coalesce(sum(samples),0),min(end_ts),max(end_ts) FROM history_loss WHERE end_ts>? AND end_ts<=?"
	args := []any{start.UnixMicro(), end.UnixMicro()}
	if node != "" {
		q += " AND node=?"
		args = append(args, node)
	}
	if source != "" {
		q += " AND source=?"
		args = append(args, source)
	}
	v := &HistoryCoverage{ResolutionSeconds: 3600}
	var first, last sql.NullInt64
	if err := db.QueryRowContext(ctx, q, args...).Scan(&v.DiscardedSamples, &first, &last); err != nil {
		return nil, err
	}
	v.Partial = v.DiscardedSamples > 0
	if first.Valid {
		v.FirstAffected = pointer(time.UnixMicro(first.Int64).UTC().Add(-time.Hour))
		v.LastAffected = pointer(time.UnixMicro(last.Int64).UTC())
	}
	return v, nil
}

func expireReclamation(ctx context.Context, tx *sql.Tx, expired int64) (int64, error) {
	var count, samples int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(samples),0) FROM (SELECT samples FROM history_loss WHERE end_ts<=? ORDER BY end_ts,node,source LIMIT ?)`, expired, expireBatch).Scan(&count, &samples); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM history_loss WHERE (node,source,end_ts) IN (SELECT node,source,end_ts FROM history_loss WHERE end_ts<=? ORDER BY end_ts,node,source LIMIT ?)`, expired, expireBatch)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n != count {
		return 0, fmt.Errorf("reclamation expiry population changed")
	}
	_, err = tx.ExecContext(ctx, "UPDATE reclamation_metadata SET loss_rows=loss_rows-?,expired_samples=expired_samples+? WHERE id=1", n, samples)
	return n, err
}

func checkReclamation(ctx context.Context, db reader) error {
	var next, evicted, samples, expired, stored, actual, population, maximum, compacted int64
	if err := db.QueryRowContext(ctx, `SELECT next_stream_id,evicted_streams,evicted_samples,expired_samples,loss_rows,
(SELECT count(*) FROM history_loss),(SELECT coalesce(sum(samples),0) FROM history_loss),
(SELECT coalesce(max(id),0) FROM streams),(SELECT compacted_samples FROM tier_metadata WHERE id=1)
FROM reclamation_metadata WHERE id=1`).Scan(&next, &evicted, &samples, &expired, &stored, &actual, &population, &maximum, &compacted); err != nil {
		return err
	}
	if next <= maximum || evicted < 0 || samples < 0 || expired < 0 || expired > samples || (samples > 0 && evicted == 0) || samples > compacted || population != samples-expired || stored != actual || stored < 0 || stored > MaxReclamationRows {
		return fmt.Errorf("invalid path reclamation metadata")
	}
	rows, err := db.QueryContext(ctx, "SELECT node,source,end_ts,samples,(SELECT sealed_until FROM tier_metadata WHERE id=1) FROM history_loss")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var node, source string
		var end, n, seal int64
		if err := rows.Scan(&node, &source, &end, &n, &seal); err != nil {
			return err
		}
		if !validLabel(node, true) || (source != "legacy-probe" && source != "cli-ping" && source != "agent-direct" && source != "monitor-overlay") || end <= 0 || end > seal || end%time.Hour.Microseconds() != 0 || n <= 0 {
			return fmt.Errorf("invalid path reclamation loss record")
		}
	}
	return rows.Err()
}
