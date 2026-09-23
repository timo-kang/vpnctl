// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// This fixture stages EVERY observation as a raw row in the production schema,
// then runs the real atomic compactor. It intentionally bypasses HTTP/producer
// scheduling to make 20 million observations affordable; the mTLS matrix covers
// that boundary separately. It never seeds an aggregate payload directly.
func TestTieredStorageTransitionScale(t *testing.T) {
	if testing.Short() {
		t.Skip("storage transition scale")
	}
	full := os.Getenv("VPNCTL_HISTORY_TRANSITION_SCALE") == "1"
	nodes, hours, cadence := 8, 10, 15*time.Minute
	if full {
		nodes, hours, cadence = 32, 168, time.Minute
	}
	s, end := newStore(t)
	end = end.Truncate(time.Hour)
	start := end.Add(-time.Duration(hours) * time.Hour)
	ctx := context.Background()
	if err := s.EnableTiering(ctx, start); err != nil {
		t.Fatal(err)
	}
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	streams := map[[4]int]candidateStream{}
	byStream := map[Stream][4]int{}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for node := 0; node < nodes; node++ {
		for peer := 0; peer < nodes; peer++ {
			if node == peer {
				continue
			}
			for source, name := range []string{"agent-direct", "monitor-overlay"} {
				for gen := 0; gen < 4; gen++ {
					st := Stream{NodeID: fmt.Sprintf("robot-%02d", node), PeerID: fmt.Sprintf("robot-%02d", peer), Source: name, Path: "direct", Uplink: fmt.Sprintf("uplink-%d", gen)}
					if source == 1 {
						st.Path = "relay"
						st.RelayID = "controller"
					}
					res, e := tx.Exec("INSERT INTO streams(node,peer,path,relay,uplink,source) VALUES(?,?,?,?,?,?)", st.NodeID, st.PeerID, st.Path, st.RelayID, st.Uplink, st.Source)
					if e != nil {
						t.Fatal(e)
					}
					id, e := res.LastInsertId()
					if e != nil {
						t.Fatal(e)
					}
					key := [4]int{node, peer, source, gen}
					streams[key] = candidateStream{id, st}
					byStream[st] = key
				}
			}
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var peakWAL, total, transactions int64
	started := time.Now()
	samples := int(time.Hour / cadence)
	measure := func() {
		info, e := os.Stat(s.path + "-wal")
		if e == nil {
			peakWAL = max(peakWAL, info.Size())
			if peakWAL > 64<<20 {
				t.Fatalf("WAL exceeded budget: %d", peakWAL)
			}
		} else if !os.IsNotExist(e) {
			t.Fatal(e)
		}
	}
	for hour := 0; hour < hours; hour++ {
		hourEnd := start.Add(time.Duration(hour+1) * time.Hour)
		tx, err = db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		pending := 0
		// Cryptographically random 128-bit hex IDs are longer than the current
		// base64url producer IDs, making retained row/index size conservative.
		for key, st := range streams {
			if key[3] != hour%4 {
				continue
			}
			seed := int64(key[0]*1000003 + key[1]*10007 + key[2]*1009 + hour*97)
			_, err = tx.Exec(`WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
INSERT INTO probes(stream,id,ts,rtt,unknown,reason)
SELECT ?,lower(hex(randomblob(16))),?+i*?,CASE WHEN i%10 IN (0,1) THEN NULL ELSE (?+i*104729)%60000001 END, i%10=0,CASE WHEN i%10 IN (0,1) THEN ? ELSE '' END FROM n ORDER BY i DESC`, samples, st.id, hourEnd.Add(-time.Hour).UnixMicro(), cadence.Microseconds(), seed, strings.Repeat("x", 64))
			if err != nil {
				t.Fatal(err)
			}
			pending += samples
			total += int64(samples)
			if pending >= MaxBatch {
				if _, err = tx.Exec("UPDATE metadata SET row_count=row_count+?", pending); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				measure()
				pending = 0
				tx, err = db.Begin()
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err = tx.Exec("UPDATE metadata SET row_count=row_count+?", pending); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		measure()
		for {
			more, e := s.compactStep(ctx, db, hourEnd)
			if e != nil {
				t.Fatal(e)
			}
			transactions++
			measure()
			if !more {
				break
			}
		}
		if (hour+1)%24 == 0 {
			t.Logf("hours=%d raw_observations=%d elapsed=%s", hour+1, total, time.Since(started))
		}
	}
	// Persist the same live snapshots that Ingest writes. Every generation has
	// a retained recent window; this fixture does not claim to test producers.
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range streams {
		m, e := replay(ctx, tx, st.id, st.Stream)
		if e != nil {
			t.Fatal(e)
		}
		if m.ObservedAt != nil {
			if e = saveLive(ctx, tx, st.id, m); e != nil {
				t.Fatal(e)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	measure()
	// Uplink rows share the same production DB. Their seed transaction's WAL
	// is deliberately excluded, as in the original candidate experiment.
	db.Close()
	seedUplinkScale(t, s, end, cadence)
	stats, err := s.TieredStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DatabaseBytes > ProbeStorageBudget {
		t.Fatalf("DB exceeds target: %+v", stats)
	}
	if stats.RawRows+stats.CompactedSamples != total || stats.PendingSamples != 0 {
		t.Fatal("population accounting", stats, total)
	}
	s, err = Open(s.path, end)
	if err != nil {
		t.Fatal("reopen", err)
	}
	var population int64
	var maxQuery time.Duration
	var maxReporter time.Duration
	var maxJSON int
	pageCount := 0
	for node := 0; node < nodes; node++ {
		reporterStarted := time.Now()
		req := PageRequest{Node: fmt.Sprintf("robot-%02d", node), End: end, Window: time.Duration(hours) * time.Hour, Width: time.Hour}
		for {
			began := time.Now()
			page, e := s.QueryPage(ctx, req)
			if e != nil {
				t.Fatal(e)
			}
			data, e := json.Marshal(page)
			if e != nil {
				t.Fatal(e)
			}
			elapsed := time.Since(began)
			maxQuery = max(maxQuery, elapsed)
			maxJSON = max(maxJSON, len(data))
			if elapsed > QueryTimeout || len(data) > MaxHistoryResponseBytes {
				t.Fatal("page budget", elapsed, len(data))
			}
			pageCount++
			for _, b := range page.Buckets {
				key, exists := byStream[b.Stream]
				if !exists {
					t.Fatal("query invented stream", b.Stream)
				}
				hour := int(b.Time.Sub(start) / time.Hour)
				want := Bucket{Stream: b.Stream, Time: b.Time}
				var rtts []int64
				var sum int64
				if key[3] == hour%4 {
					seed := int64(key[0]*1000003 + key[1]*10007 + key[2]*1009 + hour*97)
					for i := 1; i <= samples; i++ {
						if i%10 == 0 {
							want.UnknownCount++
							continue
						}
						want.Count++
						if i%10 != 1 {
							rtt := (seed + int64(i)*104729) % 60000001
							rtts = append(rtts, rtt)
							sum += rtt
							want.Successes++
						}
					}
				}
				// Independent raw-sample oracle: no aggregate Add/Merge/Bucket.
				if want.Count > 0 {
					want.AvailabilityPct = pointer(100 * float64(want.Successes) / float64(want.Count))
					want.LossPct = pointer(100 - *want.AvailabilityPct)
				}
				if len(rtts) > 0 {
					sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
					want.AvgRTTMs = pointer(float64(sum) / float64(len(rtts)) / 1000)
					want.P95RTTMs = pointer(float64(rtts[(95*len(rtts)+99)/100-1]) / 1000)
				}
				if !reflect.DeepEqual(want, b) {
					t.Fatalf("population/statistics differ for %+v at %s", b.Stream, b.Time)
				}
				population += int64(b.Count + b.UnknownCount)
			}
			if page.NextCursor == "" {
				break
			}
			req.Cursor = page.NextCursor
		}
		elapsed := time.Since(reporterStarted)
		maxReporter = max(maxReporter, elapsed)
		if elapsed > QueryTimeout {
			t.Fatal("reporter page sequence exceeds budget", node, elapsed)
		}
	}
	if population != total {
		t.Fatal(population, total)
	}
	t.Logf("nodes=%d streams=%d observations=%d raw=%d rollups=%d db_bytes=%d peak_compaction_and_raw_wal=%d transactions=%d pages=%d max_page_query_json=%s max_reporter_pages_with_oracle=%s max_page_json=%d elapsed=%s", nodes, len(streams), total, stats.RawRows, stats.RollupRows, stats.DatabaseBytes, peakWAL, transactions, pageCount, maxQuery, maxReporter, maxJSON, time.Since(started))
	if full {
		testTieredSharedSpaceRetry(t, s, end)
	}
}

func testTieredSharedSpaceRetry(t *testing.T, s *Store, now time.Time) {
	ctx := context.Background()
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Out-of-band pages model competing DB categories; never a schema used by
	// the service. Logical probe admission must leave the shared 1 GiB ceiling.
	if _, err = db.Exec("CREATE TABLE shared_pressure(data BLOB)"); err != nil {
		t.Fatal(err)
	}
	for {
		stats, e := s.TieredStats(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if stats.UsedBytes >= ProbeStorageBudget {
			break
		}
		if _, e = db.Exec("INSERT INTO shared_pressure VALUES(zeroblob(8388608))"); e != nil {
			t.Fatal(e)
		}
	}
	var node string
	var o Observation
	var ts int64
	var rtt sql.NullInt64
	var unknown bool
	err = db.QueryRow(`SELECT s.node,p.id,p.ts,p.rtt,p.unknown,p.reason,s.peer,s.path,s.relay,s.uplink,s.source FROM probes p JOIN streams s ON s.id=p.stream LIMIT 1`).Scan(&node, &o.ID, &ts, &rtt, &unknown, &o.Reason, &o.PeerID, &o.Path, &o.RelayID, &o.Uplink, &o.Source)
	if err != nil {
		t.Fatal(err)
	}
	o.Timestamp = time.UnixMicro(ts).UTC()
	if unknown {
		o.Validity = "unknown"
	} else {
		o.Success = pointer(rtt.Valid)
		if rtt.Valid {
			o.RTTMs = pointer(float64(rtt.Int64) / 1000)
		}
	}
	if err = s.Ingest(ctx, node, []Observation{o}, now); err != nil {
		t.Fatal("shared budget broke idempotent retry", err)
	}
	o.ID = "new-at-shared-budget"
	assertProbeQuota(t, s.Ingest(ctx, node, []Observation{o}, now), "database_used_bytes", ProbeStorageBudget)
	if _, err = db.Exec("DROP TABLE shared_pressure"); err != nil {
		t.Fatal(err)
	}
	if err = s.Ingest(ctx, node, []Observation{o}, now); err != nil {
		t.Fatal("freed shared pages did not restore admission", err)
	}
}
