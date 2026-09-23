// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	prng "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is an isolated steady-state capacity experiment, not the production
// schema, ingestion endpoint or migration. In particular it does not prove the
// cost/atomicity of converting an existing raw database. See the design record.
const candidateSchema = `
CREATE TABLE streams(id INTEGER PRIMARY KEY,node TEXT NOT NULL,peer TEXT NOT NULL,
 path TEXT NOT NULL,relay TEXT NOT NULL,uplink TEXT NOT NULL,source TEXT NOT NULL,
 UNIQUE(node,peer,path,relay,uplink,source));
CREATE TABLE probes(stream INTEGER NOT NULL REFERENCES streams(id),id TEXT NOT NULL,
 ts INTEGER NOT NULL,rtt INTEGER,unknown INTEGER NOT NULL,reason TEXT NOT NULL,
 PRIMARY KEY(stream,id)) WITHOUT ROWID;
CREATE INDEX probe_time ON probes(ts);
CREATE INDEX probe_stream_time ON probes(stream,ts);
CREATE TABLE candidate_rollups(stream INTEGER NOT NULL REFERENCES streams(id),
 end_ts INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(stream,end_ts)) WITHOUT ROWID;
CREATE INDEX candidate_rollup_time ON candidate_rollups(end_ts);
`

type candidateStream struct {
	id int64
	Stream
}

type candidateCounts struct{ attempted, unknown, successes int }

func TestTieredHistoryCandidate(t *testing.T) {
	if testing.Short() {
		t.Skip("tiered capacity experiment")
	}
	full := os.Getenv("VPNCTL_HISTORY_TIERED_SCALE") == "1"
	nodes := []int{1, 3, 8, 32}
	if full {
		nodes = []int{32}
	}
	for _, size := range nodes {
		for _, mesh := range []bool{false, true} {
			t.Run(fmt.Sprintf("nodes_%d_mesh_%t", size, mesh), func(t *testing.T) {
				candidateCapacity(t, size, mesh, full)
			})
		}
	}
}

func candidateCapacity(t *testing.T, nodes int, mesh, full bool) {
	end := time.Now().UTC().Truncate(time.Hour)
	horizon, cadence := 8*time.Hour, 15*time.Minute
	if full {
		horizon, cadence = Retention, time.Minute
	}
	path := filepath.Join(t.TempDir(), "candidate.db")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := connect(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("PRAGMA journal_mode=WAL;" + candidateSchema); err != nil {
		t.Fatal(err)
	}
	// Two sources, with four generations of reported uplink labels over time.
	// Samples switch generations; we do not multiply the actual probe cadence.
	sources := []string{"agent-direct", "monitor-overlay"}
	const generations = 4
	streams := make(map[[4]int]candidateStream)
	for node := 0; node < nodes; node++ {
		for peer := 0; peer < nodes; peer++ {
			if node == peer || (!mesh && node != 0 && peer != 0) {
				continue
			}
			for source, name := range sources {
				for generation := 0; generation < generations; generation++ {
					st := Stream{NodeID: fmt.Sprintf("robot-%02d", node), PeerID: fmt.Sprintf("robot-%02d", peer), Source: name, Path: "direct", Uplink: fmt.Sprintf("uplink-%d", generation)}
					if name == "monitor-overlay" {
						st.Path, st.RelayID = "relay", "controller"
					}
					res, err := db.Exec("INSERT INTO streams(node,peer,path,relay,uplink,source) VALUES(?,?,?,?,?,?)", st.NodeID, st.PeerID, st.Path, st.RelayID, st.Uplink, st.Source)
					if err != nil {
						t.Fatal(err)
					}
					id, err := res.LastInsertId()
					if err != nil {
						t.Fatal(err)
					}
					streams[[4]int{node, peer, source, generation}] = candidateStream{id, st}
				}
			}
		}
	}
	rng := prng.New(prng.NewPCG(71, uint64(nodes)))
	expected := make(map[Stream]candidateCounts)
	var rawRows, rollupRows, represented int64
	var peakWAL int64
	started := time.Now()
	for hour := 0; hour < int(horizon/time.Hour); hour++ {
		hourEnd := end.Add(-horizon).Add(time.Duration(hour+1) * time.Hour)
		raw := hourEnd.After(end.Add(-CandidateRawRetention))
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		// Bound transactions; an hour of full mesh raw samples is too large a
		// single transaction for the 64 MiB WAL budget with random B-tree keys.
		func() {
			defer func() {
				if tx != nil {
					tx.Rollback()
				}
			}()
			insertRaw, err := tx.Prepare("INSERT INTO probes(stream,id,ts,rtt,unknown,reason) VALUES(?,?,?,?,?,?)")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if insertRaw != nil {
					insertRaw.Close()
				}
			}()
			insertRollup, err := tx.Prepare("INSERT INTO candidate_rollups(stream,end_ts,payload) VALUES(?,?,?)")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if insertRollup != nil {
					insertRollup.Close()
				}
			}()
			commit := func() error {
				insertRaw.Close()
				insertRollup.Close()
				if err := tx.Commit(); err != nil {
					return err
				}
				if info, err := os.Stat(path + "-wal"); err == nil {
					peakWAL = max(peakWAL, info.Size())
				}
				return nil
			}
			mutations := 0
			// All relations are exercised. Map iteration and shuffled timestamps
			// produce out-of-order arrivals; retained IDs are true 128-bit random.
			for key, st := range streams {
				if key[3] != hour%generations {
					continue
				}
				var aggregate ProbeAggregate
				count := expected[st.Stream]
				for _, minute := range rng.Perm(int(time.Hour / cadence)) {
					at := hourEnd.Add(-time.Hour).Add(time.Duration(minute+1) * cadence)
					outcome := rng.IntN(10)
					var success *bool
					var rtt *float64
					reason := ""
					if outcome == 0 {
						count.unknown++
						reason = strings.Repeat("u", 64)
					} else {
						success = pointer(outcome != 1)
						count.attempted++
						if *success {
							// Wide, microsecond-resolution RTTs avoid unrealistically
							// tiny histograms from a constant RTT performance fixture.
							rtt = pointer(float64(rng.IntN(60_000_001)) / 1000)
							count.successes++
						} else {
							reason = strings.Repeat("f", 64)
						}
					}
					if raw {
						var id [16]byte
						if _, err := rand.Read(id[:]); err != nil {
							t.Fatal(err)
						}
						var value any
						if rtt != nil {
							value = int64(math.Round(*rtt * 1000))
						}
						if _, err := insertRaw.Exec(st.id, base64.RawURLEncoding.EncodeToString(id[:]), at.UnixMicro(), value, success == nil, reason); err != nil {
							t.Fatal(err)
						}
						rawRows++
						mutations++
					} else if err := aggregate.Add(success, rtt); err != nil {
						t.Fatal(err)
					}
					represented++
				}
				expected[st.Stream] = count
				if !raw {
					payload, err := aggregate.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					if _, err = insertRollup.Exec(st.id, hourEnd.UnixMicro(), payload); err != nil {
						t.Fatal(err)
					}
					rollupRows++
					mutations++
				}
				if mutations >= MaxBatch {
					if err := commit(); err != nil {
						t.Fatal(err)
					}
					tx, err = db.Begin()
					if err != nil {
						t.Fatal(err)
					}
					insertRaw, err = tx.Prepare("INSERT INTO probes(stream,id,ts,rtt,unknown,reason) VALUES(?,?,?,?,?,?)")
					if err != nil {
						t.Fatal(err)
					}
					insertRollup, err = tx.Prepare("INSERT INTO candidate_rollups(stream,end_ts,payload) VALUES(?,?,?)")
					if err != nil {
						t.Fatal(err)
					}
					mutations = 0
				}
			}
			if err = commit(); err != nil {
				t.Fatal(err)
			}
		}()
		if info, err := os.Stat(path + "-wal"); err == nil {
			peakWAL = max(peakWAL, info.Size())
		}
		// This experiment uses checkpoints between bounded fixture hours. It
		// does not claim production ingest/compaction WAL backpressure coverage.
		if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			t.Fatal(err)
		}
	}
	// Include the existing real uplink tables and four targets per node in the
	// same file, rather than assigning the entire 1 GiB budget to probe history.
	if _, err = db.Exec(uplinkSchema); err != nil {
		t.Fatal(err)
	}
	if nodes == 32 {
		step := 15 * time.Minute
		if full {
			step = time.Minute
		}
		seedUplinkScale(t, &Store{path: path, query: make(chan struct{}, 1)}, end, step)
	}
	if _, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	// Leave 256 MiB of the 1 GiB file cap for events, metadata and growth. This
	// is headroom, not proof that every independent production quota can be full.
	if err != nil || info.Size() > 768<<20 || peakWAL > 64<<20 {
		t.Fatal("candidate exceeds disk/WAL budget", info, peakWAL, err)
	}
	t.Logf("nodes=%d mesh=%t sources=2 uplink_generations=4 streams=%d cadence=%s represented=%d raw_rows=%d rollup_rows=%d db_bytes=%d peak_probe_fixture_wal=%d seed=%s", nodes, mesh, len(streams), cadence, represented, rawRows, rollupRows, info.Size(), peakWAL, time.Since(started))
	// Close/reopen so no in-memory aggregate or connection-local state can
	// accidentally make a missing on-disk result appear complete.
	db.Close()
	db, err = connect(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	windows := []time.Duration{horizon}
	if full {
		windows = []time.Duration{24 * time.Hour, Retention}
	}
	for _, window := range windows {
		allStart, maxQuery := time.Now(), time.Duration(0)
		maxResponse := 0
		var readSamples int
		for node := 0; node < nodes; node++ {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
			buckets, err := queryCandidate(ctx, db, fmt.Sprintf("robot-%02d", node), end, window)
			cancel()
			if err != nil {
				t.Fatal("candidate query failed", node, window, err)
			}
			encoded, err := json.Marshal(buckets)
			if err != nil || len(encoded) > 16<<20 || time.Since(start) > QueryTimeout {
				t.Fatal("candidate response budget exceeded", node, len(encoded), time.Since(start), err)
			}
			maxQuery = max(maxQuery, time.Since(start))
			maxResponse = max(maxResponse, len(encoded))
			actual := make(map[Stream]candidateCounts)
			for _, b := range buckets {
				c := actual[b.Stream]
				c.attempted += b.Count
				c.unknown += b.UnknownCount
				c.successes += b.Successes
				actual[b.Stream] = c
				readSamples += b.Count + b.UnknownCount
				if b.Count == 0 && (b.AvailabilityPct != nil || b.LossPct != nil || b.AvgRTTMs != nil) {
					t.Fatal("empty/unknown bucket declared reachable", b)
				}
			}
			if window == horizon {
				for st, want := range expected {
					if st.NodeID == fmt.Sprintf("robot-%02d", node) && actual[st] != want {
						t.Fatalf("lost relation/source/path population: %v want=%+v got=%+v", st, want, actual[st])
					}
				}
			}
		}
		want := int(represented) * int(window/cadence) / int(horizon/cadence)
		if readSamples != want {
			t.Fatal("incomplete window", window, readSamples, want)
		}
		t.Logf("window=%s max_node_query_and_json=%s max_node_json_bytes=%d all_nodes_serial=%s population=%d", window, maxQuery, maxResponse, time.Since(allStart), readSamples)
	}
}

// Prototype only: queries one reporter and whole UTC hours, including empty
// buckets. Production activation additionally needs API paging, partial-boundary
// handling, authorization rechecks and a durable deduplication cutoff.
func queryCandidate(ctx context.Context, db *sql.DB, node string, end time.Time, window time.Duration) ([]Bucket, error) {
	if window%time.Hour != 0 || !end.Equal(end.Truncate(time.Hour)) {
		return nil, fmt.Errorf("candidate query requires whole UTC hours")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id,node,peer,path,relay,uplink,source FROM streams WHERE node=? ORDER BY id", node)
	if err != nil {
		return nil, err
	}
	var streams []candidateStream
	for rows.Next() {
		var st candidateStream
		if err := rows.Scan(&st.id, &st.NodeID, &st.PeerID, &st.Path, &st.RelayID, &st.Uplink, &st.Source); err != nil {
			rows.Close()
			return nil, err
		}
		streams = append(streams, st)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	start := end.Add(-window)
	var out []Bucket
	for _, st := range streams {
		buckets := make([]ProbeAggregate, int(window/time.Hour))
		rows, err := tx.QueryContext(ctx, "SELECT end_ts,payload FROM candidate_rollups WHERE stream=? AND end_ts>? AND end_ts<=?", st.id, start.UnixMicro(), end.UnixMicro())
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ts int64
			var payload []byte
			if err = rows.Scan(&ts, &payload); err == nil {
				var a *ProbeAggregate
				a, err = DecodeProbeAggregate(payload)
				if err == nil {
					err = buckets[(ts-start.UnixMicro()-1)/time.Hour.Microseconds()].Merge(a)
				}
			}
			if err != nil {
				rows.Close()
				return nil, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		rows, err = tx.QueryContext(ctx, "SELECT ts,rtt,unknown FROM probes WHERE stream=? AND ts>? AND ts<=?", st.id, start.UnixMicro(), end.UnixMicro())
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ts int64
			var rtt sql.NullInt64
			var unknown bool
			if err = rows.Scan(&ts, &rtt, &unknown); err != nil {
				rows.Close()
				return nil, err
			}
			var success *bool
			var ms *float64
			if !unknown {
				success = pointer(rtt.Valid)
				if rtt.Valid {
					ms = pointer(float64(rtt.Int64) / 1000)
				}
			}
			if err = buckets[(ts-start.UnixMicro()-1)/time.Hour.Microseconds()].Add(success, ms); err != nil {
				rows.Close()
				return nil, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		for i := range buckets {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			out = append(out, buckets[i].Bucket(st.Stream, start.Add(time.Duration(i)*time.Hour)))
		}
	}
	return out, ctx.Err()
}
