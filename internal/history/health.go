// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"
)

const HealthInterval = 30 * time.Second
const HealthStaleAfter = 90 * time.Second
const HealthTimeout = 2 * time.Second

// StorageHealth is a cached observation, never a synchronous integrity check.
// A failed or stale collection has no usable values, even if the previous read
// succeeded. LastSuccessAt is retained only to diagnose collection outages.
type StorageHealth struct {
	SchemaVersion     int                  `json:"schema_version"`
	Validity          string               `json:"validity"`
	Reason            string               `json:"reason"`
	Stale             bool                 `json:"stale"`
	ObservedAt        *time.Time           `json:"observed_at"`
	LastSuccessAt     *time.Time           `json:"last_success_at"`
	IntervalSeconds   float64              `json:"interval_seconds"`
	StaleAfterSeconds float64              `json:"stale_after_seconds"`
	Values            *StorageHealthValues `json:"values"`
}

type StorageHealthValues struct {
	StorageInspection
	DatabaseBytes            int64      `json:"database_bytes"` // committed SQLite pages, including WAL
	DatabaseFileBytes        int64      `json:"database_file_bytes"`
	UsedBytes                int64      `json:"used_bytes"`
	FreeBytes                int64      `json:"free_bytes"` // reusable DB pages, NOT filesystem capacity
	WALBytes                 int64      `json:"wal_bytes"`
	RawRows                  int64      `json:"raw_rows"`
	Streams                  int64      `json:"streams"`
	UplinkRows               int64      `json:"uplink_rows"`
	EventRows                int64      `json:"event_rows"`
	CompactionEligibleRows   *int64     `json:"compaction_eligible_rows"`
	OldestCompactionEligible *time.Time `json:"oldest_compaction_eligible"`
}

func UnknownStorageHealth(reason string) StorageHealth {
	return StorageHealth{SchemaVersion: 1, Validity: "unknown", Reason: reason, Stale: true, IntervalSeconds: HealthInterval.Seconds(), StaleAfterSeconds: HealthStaleAfter.Seconds()}
}

func (h StorageHealth) Clone() StorageHealth {
	cloneTime := func(p *time.Time) *time.Time {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	h.ObservedAt, h.LastSuccessAt = cloneTime(h.ObservedAt), cloneTime(h.LastSuccessAt)
	if h.Values != nil {
		v := *h.Values
		v.OldestCompactionEligible = cloneTime(v.OldestCompactionEligible)
		if v.CompactionEligibleRows != nil {
			n := *v.CompactionEligibleRows
			v.CompactionEligibleRows = &n
		}
		if v.Tiering != nil {
			t := *v.Tiering
			v.Tiering = &t
		}
		if v.WireGuard != nil {
			w := *v.WireGuard
			w.LossStart, w.LossEnd = cloneTime(w.LossStart), cloneTime(w.LossEnd)
			v.WireGuard = &w
		}
		h.Values = &v
	}
	return h
}

func (h StorageHealth) Fresh(now time.Time) StorageHealth {
	h = h.Clone()
	if h.ObservedAt == nil {
		return h
	}
	if now.Before(*h.ObservedAt) || !now.Before(h.ObservedAt.Add(HealthStaleAfter)) {
		h.Stale, h.Validity, h.Reason, h.Values = true, "unknown", "stale", nil
		if now.Before(*h.ObservedAt) {
			h.Reason = "clock_regressed"
		}
	}
	return h
}

func (s *Store) StorageHealth(now time.Time) StorageHealth {
	if v := s.health.Load(); v != nil {
		return v.Fresh(now)
	}
	return UnknownStorageHealth("not_collected")
}

// RefreshStorageHealth has a separate single-reader budget. It never takes the
// upload writer or public history query slots, and never holds an admission lock.
func (s *Store) RefreshStorageHealth(ctx context.Context, now time.Time) error {
	if !s.healthBusy.CompareAndSwap(false, true) {
		return fmt.Errorf("storage health collection already running")
	}
	defer s.healthBusy.Store(false)
	ctx, cancel := context.WithTimeout(ctx, HealthTimeout)
	defer cancel()
	h := UnknownStorageHealth("collection_failed")
	h.Stale, h.ObservedAt = false, &now
	if prev := s.health.Load(); prev != nil {
		h.LastSuccessAt = prev.Clone().LastSuccessAt
	}
	values, err := s.readStorageHealth(ctx, now)
	if err == nil {
		h.Validity, h.Reason, h.Values, h.LastSuccessAt = "observed", "", &values, &now
	}
	s.health.Store(&h)
	return err
}

func (s *Store) readStorageHealth(ctx context.Context, now time.Time) (StorageHealthValues, error) {
	var v StorageHealthValues
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
	var app int
	if err = tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return v, err
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v.SchemaVersion); err != nil {
		return v, err
	}
	if app != applicationID || !supportedHistoryVersion(v.SchemaVersion) {
		return v, fmt.Errorf("unsupported history database")
	}
	if err = tx.QueryRowContext(ctx, `SELECT row_count,(SELECT count(*) FROM streams) FROM metadata WHERE id=1`).Scan(&v.RawRows, &v.Streams); err != nil {
		return v, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT row_count FROM uplink_metadata WHERE id=1`).Scan(&v.UplinkRows); err != nil {
		return v, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT row_count FROM event_metadata WHERE id=1`).Scan(&v.EventRows); err != nil {
		return v, err
	}
	var pages, free, pageSize int64
	for _, q := range []struct {
		sql    string
		target *int64
	}{{"PRAGMA page_count", &pages}, {"PRAGMA freelist_count", &free}, {"PRAGMA page_size", &pageSize}} {
		if err = tx.QueryRowContext(ctx, q.sql).Scan(q.target); err != nil {
			return v, err
		}
	}
	v.DatabaseBytes, v.FreeBytes = pages*pageSize, free*pageSize
	v.UsedBytes = v.DatabaseBytes - v.FreeBytes
	base := probeSchemaVersion(v.SchemaVersion)
	if base >= 6 {
		stats, e := s.readTieredStats(ctx, tx)
		if e != nil {
			return v, e
		}
		v.Tiering = &stats
		var count int64
		var oldest sql.NullInt64
		cutoff := now.UTC().Add(-CandidateRawRetention).Truncate(time.Hour).UnixMicro()
		if err = tx.QueryRowContext(ctx, "SELECT count(*),min(ts) FROM probes WHERE ts<=?", cutoff).Scan(&count, &oldest); err != nil {
			return v, err
		}
		v.CompactionEligibleRows = &count
		if oldest.Valid {
			at := time.UnixMicro(oldest.Int64).UTC()
			v.OldestCompactionEligible = &at
		}
	}
	wg := wireGuardLimits()
	if v.SchemaVersion >= 15 {
		wg, err = wireGuardStorage(ctx, tx)
		if err != nil {
			return v, err
		}
	}
	v.WireGuard = &wg
	info, err := os.Stat(s.path)
	if err != nil {
		return v, err
	}
	v.DatabaseFileBytes = info.Size()
	if info, e := os.Stat(s.path + "-wal"); e == nil {
		v.WALBytes = info.Size()
	} else if !os.IsNotExist(e) {
		return v, e
	}
	return v, ctx.Err()
}
