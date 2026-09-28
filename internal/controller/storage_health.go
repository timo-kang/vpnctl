// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"vpnctl/internal/history"
)

type storageHealthSource interface {
	StorageHealth(time.Time) history.StorageHealth
	RefreshStorageHealth(context.Context, time.Time) error
}

func (s *Server) storageHealth(now time.Time) history.StorageHealth {
	if st, ok := s.history.(storageHealthSource); ok {
		return st.StorageHealth(now)
	}
	return history.UnknownStorageHealth("unavailable")
}

func (s *Server) handleStorageHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	writeJSON(w, 200, s.storageHealth(time.Now()))
}

func (s *Server) startStorageHealth() func() {
	st, ok := s.history.(storageHealthSource)
	if !ok {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(history.HealthInterval)
		defer ticker.Stop()
		for {
			if err := st.RefreshStorageHealth(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
				slog.Warn("history storage health collection failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

type storageHealthCollector struct {
	read func() history.StorageHealth
	desc map[string]*prometheus.Desc
}

func newStorageHealthCollector(read func() history.StorageHealth) *storageHealthCollector {
	c := &storageHealthCollector{read: read, desc: map[string]*prometheus.Desc{}}
	for name, help := range map[string]string{
		"collection_valid":               "One for a fresh successful cached storage collection; not an integrity verdict",
		"collection_timestamp_seconds":   "Last storage collection attempt timestamp; NaN before collection",
		"last_success_timestamp_seconds": "Last successful storage collection timestamp; NaN before success",
		"database_bytes":                 "Committed SQLite page bytes, including pages in WAL; NaN when unknown",
		"database_file_bytes":            "Physical SQLite main file bytes at collection time; NaN when unknown",
		"used_bytes":                     "Allocated SQLite pages minus reusable pages; NaN when unknown",
		"free_bytes":                     "Reusable SQLite page bytes, not filesystem free space; NaN when unknown",
		"wal_bytes":                      "Physical SQLite WAL bytes at collection time; NaN when unknown",
		"raw_rows":                       "Retained raw probe rows; NaN when unknown",
		"streams":                        "Retained probe streams; NaN when unknown",
		"uplink_rows":                    "Retained uplink reports; NaN when unknown",
		"event_rows":                     "Retained events; NaN when unknown",
		"rollup_rows":                    "Retained probe rollup rows; NaN when unavailable",
		"rollup_bytes":                   "Retained probe rollup payload bytes; NaN when unavailable",
		"compaction_eligible_rows":       "Raw rows older than the current hour-aligned raw retention cutoff; NaN when unavailable",
		"oldest_compaction_eligible_timestamp_seconds": "Oldest raw row eligible for compaction; NaN when none or unavailable",
		"last_compaction_timestamp_seconds":            "Last committed compaction time; NaN before compaction or when unavailable",
		"reclaimed_samples":                            "Persisted lifetime reclaimed probe population gauge; NaN when unavailable",
		"wireguard_rows":                               "Retained WireGuard reports; NaN when unknown",
		"wireguard_bytes":                              "Retained compressed WireGuard payload bytes; NaN when unknown",
		"wireguard_evicted_reports":                    "Persisted lifetime reclaimed WireGuard report gauge; NaN when unknown",
	} {
		c.desc[name] = prometheus.NewDesc("vpnctl_history_storage_"+name, help, nil, nil)
	}
	return c
}
func (c *storageHealthCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.desc {
		ch <- d
	}
}
func (c *storageHealthCollector) Collect(ch chan<- prometheus.Metric) {
	h := c.read()
	values := map[string]float64{}
	for name := range c.desc {
		values[name] = math.NaN()
	}
	values["collection_valid"] = 0
	stamp := func(at *time.Time) float64 {
		if at == nil || at.IsZero() {
			return math.NaN()
		}
		return float64(at.UnixMicro()) / 1e6
	}
	values["collection_timestamp_seconds"] = stamp(h.ObservedAt)
	values["last_success_timestamp_seconds"] = stamp(h.LastSuccessAt)
	if v := h.Values; h.Validity == "observed" && !h.Stale && v != nil {
		values["collection_valid"] = 1
		for k, n := range map[string]int64{"database_bytes": v.DatabaseBytes, "database_file_bytes": v.DatabaseFileBytes, "used_bytes": v.UsedBytes, "free_bytes": v.FreeBytes, "wal_bytes": v.WALBytes, "raw_rows": v.RawRows, "streams": v.Streams, "uplink_rows": v.UplinkRows, "event_rows": v.EventRows} {
			values[k] = float64(n)
		}
		if t := v.Tiering; t != nil {
			values["rollup_rows"], values["rollup_bytes"] = float64(t.RollupRows), float64(t.RollupBytes)
			values["last_compaction_timestamp_seconds"] = stamp(&t.LastCompaction)
			if t.ReclamationEnabled {
				values["reclaimed_samples"] = float64(t.ReclaimedSamples)
			}
		}
		if v.CompactionEligibleRows != nil {
			values["compaction_eligible_rows"] = float64(*v.CompactionEligibleRows)
		}
		values["oldest_compaction_eligible_timestamp_seconds"] = stamp(v.OldestCompactionEligible)
		if w := v.WireGuard; w != nil && w.Enabled {
			values["wireguard_rows"], values["wireguard_bytes"], values["wireguard_evicted_reports"] = float64(w.Rows), float64(w.Bytes), float64(w.Evicted)
		}
	}
	for name, value := range values {
		ch <- prometheus.MustNewConstMetric(c.desc[name], prometheus.GaugeValue, value)
	}
}
