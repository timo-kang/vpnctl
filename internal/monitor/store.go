// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS probes (
    timestamp INTEGER NOT NULL,
    peer_key  TEXT NOT NULL,
    peer_ip   TEXT NOT NULL,
    rtt_us    INTEGER,
    success   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probes_time ON probes(timestamp);
CREATE INDEX IF NOT EXISTS idx_probes_peer ON probes(peer_key, timestamp);
`

// ProbeResult holds a single ICMP/UDP probe measurement.
type ProbeResult struct {
	Timestamp time.Time
	PeerKey   string // PublicKey prefix
	PeerIP    string
	RTTus     int64 // microseconds; 0 if failed
	Success   bool
}

// PeerSummary holds aggregated stats for a single peer over a time window.
type PeerSummary struct {
	PeerKey  string
	PeerIP   string
	Count    int
	AvgRTTus int64
	MinRTTus int64
	MaxRTTus int64
	LossPct  float64
	LastSeen time.Time
}

// Store is a SQLite-backed store for probe results.
type Store struct {
	db *sql.DB
}

// OpenStore opens or creates a SQLite database at path and initialises the schema.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Insert persists a single ProbeResult.
func (s *Store) Insert(r ProbeResult) error {
	ts := r.Timestamp.UnixMicro()
	success := 0
	if r.Success {
		success = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO probes (timestamp, peer_key, peer_ip, rtt_us, success) VALUES (?, ?, ?, ?, ?)`,
		ts, r.PeerKey, r.PeerIP, r.RTTus, success,
	)
	return err
}

// Query returns all probe results for peerKey within the given time window.
func (s *Store) Query(peerKey string, window time.Duration) ([]ProbeResult, error) {
	since := time.Now().Add(-window).UnixMicro()
	rows, err := s.db.Query(
		`SELECT timestamp, peer_key, peer_ip, rtt_us, success
		 FROM probes WHERE peer_key = ? AND timestamp >= ? ORDER BY timestamp`,
		peerKey, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProbes(rows)
}

// QueryAll returns all probe results for all peers within the given time window.
func (s *Store) QueryAll(window time.Duration) ([]ProbeResult, error) {
	since := time.Now().Add(-window).UnixMicro()
	rows, err := s.db.Query(
		`SELECT timestamp, peer_key, peer_ip, rtt_us, success
		 FROM probes WHERE timestamp >= ? ORDER BY timestamp`,
		since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProbes(rows)
}

// Cleanup deletes probe records older than retention and returns the count of deleted rows.
func (s *Store) Cleanup(retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention).UnixMicro()
	result, err := s.db.Exec(`DELETE FROM probes WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Summarize returns aggregated per-peer statistics over the given time window.
func (s *Store) Summarize(window time.Duration) ([]PeerSummary, error) {
	since := time.Now().Add(-window).UnixMicro()
	rows, err := s.db.Query(`
		SELECT peer_key, peer_ip,
		    COUNT(*) as cnt,
		    COALESCE(AVG(CASE WHEN success=1 THEN rtt_us END), 0) as avg_rtt,
		    COALESCE(MIN(CASE WHEN success=1 THEN rtt_us END), 0) as min_rtt,
		    COALESCE(MAX(CASE WHEN success=1 THEN rtt_us END), 0) as max_rtt,
		    100.0 * SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) / COUNT(*) as loss_pct,
		    MAX(timestamp) as last_ts
		FROM probes WHERE timestamp >= ? GROUP BY peer_key ORDER BY peer_ip`,
		since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []PeerSummary
	for rows.Next() {
		var ps PeerSummary
		var avgRTT float64
		var minRTT, maxRTT int64
		var lastTs int64

		if err := rows.Scan(
			&ps.PeerKey, &ps.PeerIP,
			&ps.Count,
			&avgRTT, &minRTT, &maxRTT,
			&ps.LossPct,
			&lastTs,
		); err != nil {
			return nil, err
		}
		ps.AvgRTTus = int64(avgRTT)
		ps.MinRTTus = minRTT
		ps.MaxRTTus = maxRTT
		ps.LastSeen = time.UnixMicro(lastTs).UTC()
		summaries = append(summaries, ps)
	}
	return summaries, rows.Err()
}

func scanProbes(rows *sql.Rows) ([]ProbeResult, error) {
	var results []ProbeResult
	for rows.Next() {
		var r ProbeResult
		var ts int64
		var success int
		if err := rows.Scan(&ts, &r.PeerKey, &r.PeerIP, &r.RTTus, &success); err != nil {
			return nil, err
		}
		r.Timestamp = time.UnixMicro(ts).UTC()
		r.Success = success != 0
		results = append(results, r)
	}
	return results, rows.Err()
}
