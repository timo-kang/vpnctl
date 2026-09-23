// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"vpnctl/internal/quality"
)

const (
	TieredMaxStreams      = 8192
	TieredMaxNodeStreams  = 256
	MaxRollupRows         = 524288
	MaxRollupStorageBytes = 256 << 20
	ProbeStorageBudget    = 768 << 20
	compactBatch          = 512
	compactSteps          = 64
	expireBatch           = 10000
)

const tierSchema = `
CREATE INDEX probe_hour_stream ON probes((ts-1)/3600000000,stream,ts);
CREATE TABLE rollups (
 stream INTEGER NOT NULL REFERENCES streams(id), end_ts INTEGER NOT NULL,
 payload BLOB NOT NULL, PRIMARY KEY(stream,end_ts)
) WITHOUT ROWID;
CREATE INDEX rollup_time ON rollups(end_ts);
CREATE TABLE probe_live (
 stream INTEGER PRIMARY KEY REFERENCES streams(id), observed INTEGER NOT NULL,
 payload BLOB NOT NULL, digest BLOB NOT NULL
);
CREATE TABLE tier_metadata (
 id INTEGER PRIMARY KEY CHECK(id=1), sealed_until INTEGER NOT NULL,
 expired_until INTEGER NOT NULL, rollup_rows INTEGER NOT NULL,
 rollup_bytes INTEGER NOT NULL, compacted_samples INTEGER NOT NULL,
 last_compaction INTEGER NOT NULL
);
INSERT INTO tier_metadata VALUES(1,0,0,0,0,0,0);
PRAGMA user_version=6;
`

var ErrSealed = errors.New("history interval is sealed")

// SealedError is a permanent rejection of the entire batch, including retries.
// IDs are deduplicated only while their raw rows exist. IDs are scoped to a
// stream; no promise of detecting a changed-timestamp ID after sealing is made.
type SealedError struct{ Until time.Time }

func (e *SealedError) Error() string {
	return fmt.Sprintf("%s through %s", ErrSealed, e.Until.Format(time.RFC3339))
}
func (e *SealedError) Unwrap() error { return ErrSealed }
func (s *Store) Tiered() bool        { return s.tiered.Load() }
func (s *Store) streamLimit() int {
	if s.Tiered() {
		return TieredMaxStreams
	}
	return MaxStreams
}
func (s *Store) nodeStreamLimit() int {
	if s.Tiered() {
		return TieredMaxNodeStreams
	}
	return MaxNodeStreams
}

// EnableTiering is an offline, one-way migration. The CLI holds the controller
// ownership lock and creates a checked backup before calling it. Schema, live
// snapshots and the initial seal commit together; no raw rows are deleted here.
func (s *Store) EnableTiering(ctx context.Context, now time.Time) error {
	if err := acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	if s.Tiered() {
		return nil
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
	// Preflight conservative density: every accepted hour can be represented
	// even if all its RTTs are distinct. Leave the v5 database intact on failure.
	var dense int
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM probes GROUP BY stream,(ts-1)/3600000000 HAVING count(*)>?)`, MaxAggregateRTTValues).Scan(&dense)
	if err != nil {
		return err
	}
	if dense != 0 {
		return fmt.Errorf("tiering preflight: an hour exceeds %d samples", MaxAggregateRTTValues)
	}
	if err = checkProbeSpace(ctx, tx); err != nil {
		return err
	}
	streams, err := readStreams(ctx, tx, "")
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, tierSchema); err != nil {
		return err
	}
	if err = checkProbeSpace(ctx, tx); err != nil {
		return err
	}
	for _, st := range streams {
		m, e := replay(ctx, tx, st.id, st.Stream)
		if e != nil {
			return e
		}
		if m.ObservedAt != nil {
			if e = saveLive(ctx, tx, st.id, m); e != nil {
				return e
			}
		}
	}
	seal := now.UTC().Add(-CandidateRawRetention).Truncate(time.Hour).UnixMicro()
	if seal <= 0 {
		return fmt.Errorf("%w: tiering requires a positive current time", ErrInvalid)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tier_metadata SET sealed_until=? WHERE id=1", seal); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.tierSeal.Store(seal)
	s.tiered.Store(true)
	return nil
}

func checkProbeSpace(ctx context.Context, db reader) error {
	var pages, free int64
	if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
		return err
	}
	if (pages-free)*4096 >= ProbeStorageBudget {
		return &QuotaError{Resource: "database_used_bytes", Limit: ProbeStorageBudget}
	}
	return nil
}

func saveLive(ctx context.Context, tx *sql.Tx, id int64, m Measurement) error {
	if m.ObservedAt == nil {
		return fmt.Errorf("missing live observation")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	_, err = tx.ExecContext(ctx, `INSERT INTO probe_live VALUES(?,?,?,?) ON CONFLICT(stream) DO UPDATE SET observed=excluded.observed,payload=excluded.payload,digest=excluded.digest`, id, m.ObservedAt.UnixMicro(), payload, sum[:])
	return err
}

func decodeLive(payload, digest []byte, observed int64, st Stream) (Measurement, error) {
	var m Measurement
	sum := sha256.Sum256(payload)
	if len(payload) > 16384 || !bytes.Equal(sum[:], digest) || json.Unmarshal(payload, &m) != nil || m.Stream != st || m.ObservedAt == nil || m.ObservedAt.UnixMicro() != observed {
		return m, fmt.Errorf("invalid live history snapshot")
	}
	// Level is intentionally excluded from the public JSON representation.
	switch m.Quality {
	case "unknown":
		m.Level = quality.QualityUnknown
	case "offline":
		m.Level = quality.QualityOffline
	case "poor":
		m.Level = quality.QualityPoor
	case "degraded":
		m.Level = quality.QualityDegraded
	case "good":
		m.Level = quality.QualityGood
	default:
		return m, fmt.Errorf("invalid live history quality")
	}
	return m, nil
}

func (s *Store) replay(ctx context.Context, db reader, id int64, st Stream) (Measurement, error) {
	m, err := replay(ctx, db, id, st)
	if err != nil || !s.Tiered() {
		return m, err
	}
	var payload, digest []byte
	var observed int64
	err = db.QueryRowContext(ctx, "SELECT observed,payload,digest FROM probe_live WHERE stream=?", id).Scan(&observed, &payload, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	old, err := decodeLive(payload, digest, observed, st)
	if err != nil {
		return m, err
	}
	if m.ObservedAt == nil {
		return old, nil
	}
	var seal int64
	if err = db.QueryRowContext(ctx, "SELECT sealed_until FROM tier_metadata WHERE id=1").Scan(&seal); err != nil {
		return m, err
	}
	// Partial compaction may have removed some of the old replay window. The
	// durable snapshot, not that incomplete window, owns inactive live state.
	if m.ObservedAt.UnixMicro() <= seal {
		return old, nil
	}
	if old.LastSuccessAt != nil && (m.LastSuccessAt == nil || old.LastSuccessAt.After(*m.LastSuccessAt)) {
		m.LastSuccessAt = old.LastSuccessAt
	}
	return m, nil
}

// Maintenance yields the writer between bounded transactions. The seal can be
// ahead of compaction progress: raw and partial rollups are disjoint populations
// in every committed snapshot. Seals/expiry never move backwards with the clock.
func (s *Store) maintainTiered(ctx context.Context, now time.Time) error {
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	// Reclaim other categories before allocating aggregates: a full shared DB
	// must not prevent expired events/uplinks from freeing compaction space.
	if err = acquire(ctx, s.writer); err != nil {
		return err
	}
	err = s.maintainUplinks(ctx, db, now)
	if err == nil {
		err = s.maintainEvents(ctx, db, now)
	}
	<-s.writer
	if err != nil {
		return err
	}
	for i := 0; i < compactSteps; i++ {
		if err = acquire(ctx, s.writer); err != nil {
			return err
		}
		more, e := s.compactStep(ctx, db, now)
		<-s.writer
		if e != nil {
			return e
		}
		if !more {
			break
		}
	}
	if err = acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expired int64
	if err = tx.QueryRowContext(ctx, "SELECT expired_until FROM tier_metadata WHERE id=1").Scan(&expired); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM probe_live WHERE observed<=?", expired); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM streams WHERE NOT EXISTS(SELECT 1 FROM probes WHERE stream=streams.id) AND NOT EXISTS(SELECT 1 FROM rollups WHERE stream=streams.id) AND NOT EXISTS(SELECT 1 FROM probe_live WHERE stream=streams.id)`); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.mu.Lock()
	for id, m := range s.latest {
		if m.ObservedAt == nil || m.ObservedAt.UnixMicro() <= expired {
			delete(s.latest, id)
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Store) compactStep(ctx context.Context, db *sql.DB, now time.Time) (bool, error) {
	if err := s.limitWAL(ctx, db); err != nil {
		return false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	seal := now.UTC().Add(-CandidateRawRetention).Truncate(time.Hour).UnixMicro()
	expired := now.UTC().Add(-Retention).Truncate(time.Hour).UnixMicro()
	if _, err = tx.ExecContext(ctx, "UPDATE tier_metadata SET sealed_until=max(sealed_until,?),expired_until=max(expired_until,?) WHERE id=1", seal, expired); err != nil {
		return false, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT sealed_until,expired_until FROM tier_metadata WHERE id=1").Scan(&seal, &expired); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM probes WHERE (stream,id) IN (SELECT stream,id FROM probes WHERE ts<=? ORDER BY ts LIMIT ?)`, expired, expireBatch)
	if err != nil {
		return false, err
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET row_count=row_count-? WHERE id=1", removed); err != nil {
		return false, err
	}
	var expiredRows, expiredBytes int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(payload)),0) FROM (SELECT payload FROM rollups WHERE end_ts<=? ORDER BY end_ts,stream LIMIT ?)`, expired, expireBatch).Scan(&expiredRows, &expiredBytes); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM rollups WHERE (stream,end_ts) IN (SELECT stream,end_ts FROM rollups WHERE end_ts<=? ORDER BY end_ts,stream LIMIT ?)`, expired, expireBatch); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tier_metadata SET rollup_rows=rollup_rows-?,rollup_bytes=rollup_bytes-? WHERE id=1", expiredRows, expiredBytes); err != nil {
		return false, err
	}
	var first int64
	err = tx.QueryRowContext(ctx, "SELECT ts FROM probes WHERE ts>? AND ts<=? ORDER BY ts LIMIT 1", expired, seal).Scan(&first)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.Commit()
		if err == nil {
			s.tierSeal.Store(seal)
		}
		return removed == expireBatch || expiredRows == expireBatch, err
	}
	if err != nil {
		return false, err
	}
	end := (first-1)/time.Hour.Microseconds()*time.Hour.Microseconds() + time.Hour.Microseconds()
	hour := (first - 1) / time.Hour.Microseconds()
	// Pack small stream/hour populations into one bounded transaction. The
	// expression index avoids rescanning/sorting an entire fleet hour per batch.
	rows, err := tx.QueryContext(ctx, `SELECT stream,rtt,unknown FROM probes WHERE (ts-1)/3600000000=? ORDER BY stream,ts,id LIMIT ?`, hour, compactBatch)
	if err != nil {
		return false, err
	}
	n := int64(0)
	groups := map[int64]*ProbeAggregate{}
	var order []int64
	for rows.Next() {
		var stream int64
		var rtt sql.NullInt64
		var unknown bool
		if err = rows.Scan(&stream, &rtt, &unknown); err != nil {
			break
		}
		success := pointer(rtt.Valid)
		var ms *float64
		if rtt.Valid {
			ms = pointer(float64(rtt.Int64) / 1000)
		}
		if unknown {
			success = nil
		}
		a := groups[stream]
		if a == nil {
			a = &ProbeAggregate{}
			groups[stream] = a
			order = append(order, stream)
		}
		if err = a.Add(success, ms); err != nil {
			break
		}
		n++
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if rowErr != nil {
		return false, rowErr
	}
	var added, byteDelta int64
	for _, stream := range order {
		var payload []byte
		err = tx.QueryRowContext(ctx, "SELECT payload FROM rollups WHERE stream=? AND end_ts=?", stream, end).Scan(&payload)
		oldBytes := len(payload)
		a := groups[stream]
		if errors.Is(err, sql.ErrNoRows) {
			added++
		} else if err != nil {
			return false, err
		} else {
			old, e := DecodeProbeAggregate(payload)
			if e != nil {
				return false, e
			}
			if e = a.Merge(old); e != nil {
				return false, e
			}
		}
		payload, err = a.MarshalBinary()
		if err != nil {
			return false, err
		}
		byteDelta += int64(len(payload) - oldBytes)
		if _, err = tx.ExecContext(ctx, `INSERT INTO rollups VALUES(?,?,?) ON CONFLICT(stream,end_ts) DO UPDATE SET payload=excluded.payload`, stream, end, payload); err != nil {
			return false, err
		}
	}
	var rowCount, byteCount int64
	if err = tx.QueryRowContext(ctx, "SELECT rollup_rows,rollup_bytes FROM tier_metadata WHERE id=1").Scan(&rowCount, &byteCount); err != nil {
		return false, err
	}
	if rowCount+added > MaxRollupRows {
		return false, &QuotaError{Resource: "rollup_rows", Limit: MaxRollupRows}
	}
	if byteCount+byteDelta > MaxRollupStorageBytes {
		return false, &QuotaError{Resource: "rollup_bytes", Limit: MaxRollupStorageBytes}
	}
	res, err = tx.ExecContext(ctx, `DELETE FROM probes WHERE (stream,id) IN (SELECT stream,id FROM probes WHERE (ts-1)/3600000000=? ORDER BY stream,ts,id LIMIT ?)`, hour, compactBatch)
	if err != nil {
		return false, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if deleted != n {
		return false, fmt.Errorf("compaction population changed")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET row_count=row_count-? WHERE id=1", n); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE tier_metadata SET rollup_rows=rollup_rows+?,rollup_bytes=rollup_bytes+?,compacted_samples=compacted_samples+?,last_compaction=? WHERE id=1`, added, byteDelta, n, now.UnixMicro()); err != nil {
		return false, err
	}
	err = tx.Commit()
	if err == nil {
		s.tierSeal.Store(seal)
	}
	return true, err
}

type TieredStats struct {
	SealedUntil      time.Time `json:"sealed_until"`
	ExpiredUntil     time.Time `json:"expired_until"`
	RawRows          int64     `json:"raw_rows"`
	RollupRows       int64     `json:"rollup_rows"`
	RollupBytes      int64     `json:"rollup_bytes"`
	CompactedSamples int64     `json:"compacted_samples"`
	PendingSamples   int64     `json:"pending_samples"`
	LastCompaction   time.Time `json:"last_compaction"`
	DatabaseBytes    int64     `json:"database_bytes"`
	UsedBytes        int64     `json:"used_bytes"`
	FreeBytes        int64     `json:"free_bytes"`
	WALBytes         int64     `json:"wal_bytes"`
}

type StorageInspection struct {
	SchemaVersion int          `json:"schema_version"`
	Tiering       *TieredStats `json:"tiering,omitempty"`
}

// Inspect is read-only: unlike Open it neither creates a file, migrates a schema
// nor applies retention. Controller ownership is still enforced by the CLI.
func Inspect(ctx context.Context, path string) (StorageInspection, error) {
	var out StorageInspection
	db, err := connect(path, true)
	if err != nil {
		return out, err
	}
	defer db.Close()
	var app int
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return out, err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&out.SchemaVersion); err != nil {
		return out, err
	}
	if app != applicationID || out.SchemaVersion < 1 || out.SchemaVersion > 6 {
		return out, fmt.Errorf("unsupported history database")
	}
	if out.SchemaVersion == 6 {
		s := &Store{path: path}
		s.tiered.Store(true)
		stats, e := s.TieredStats(ctx)
		if e != nil {
			return out, e
		}
		out.Tiering = &stats
	}
	return out, nil
}

func (s *Store) TieredStats(ctx context.Context) (TieredStats, error) {
	var v TieredStats
	if !s.Tiered() {
		return v, fmt.Errorf("tiering is not enabled")
	}
	db, err := connect(s.path, true)
	if err != nil {
		return v, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	var seal, expired, last, pages, free int64
	err = tx.QueryRowContext(ctx, `SELECT sealed_until,expired_until,rollup_rows,rollup_bytes,compacted_samples,last_compaction,(SELECT row_count FROM metadata WHERE id=1),(SELECT count(*) FROM probes WHERE ts<=sealed_until) FROM tier_metadata WHERE id=1`).Scan(&seal, &expired, &v.RollupRows, &v.RollupBytes, &v.CompactedSamples, &last, &v.RawRows, &v.PendingSamples)
	if err != nil {
		return v, err
	}
	v.SealedUntil = time.UnixMicro(seal).UTC()
	v.ExpiredUntil = time.UnixMicro(expired).UTC()
	if last != 0 {
		v.LastCompaction = time.UnixMicro(last).UTC()
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return v, err
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
		return v, err
	}
	v.DatabaseBytes = pages * 4096
	v.FreeBytes = free * 4096
	v.UsedBytes = v.DatabaseBytes - v.FreeBytes
	if info, e := os.Stat(s.path + "-wal"); e == nil {
		v.WALBytes = info.Size()
	} else if !os.IsNotExist(e) {
		return v, e
	}
	return v, nil
}
