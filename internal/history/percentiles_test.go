// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPercentilesAcrossReplayTieringAndRestore(t *testing.T) {
	for _, schema := range []int{5, 6, 7} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			now := time.Date(2026, 9, 28, 12, 30, 0, 0, time.UTC)
			ctx := context.Background()
			s, err := Open(filepath.Join(t.TempDir(), "history.db"), now)
			if err != nil {
				t.Fatal(err)
			}
			var batch []Observation
			for i := 0; i < 115; i++ {
				o := Observation{ID: fmt.Sprint(i), Source: "monitor-overlay", PeerID: "peer", Path: "unknown", Timestamp: now.Add(-time.Second + time.Duration(i)*time.Millisecond)}
				switch {
				case i < 5:
					o.Validity, o.Reason = "unknown", "collector_unavailable"
				case i < 105:
					o.Success, o.RTTMs = pointer(true), pointer(float64(i-5))
				default:
					o.Success = pointer(false)
				}
				batch = append(batch, o)
			}
			// Reverse arrival and identical resubmission must not change ranks or
			// live replay's deterministic timestamp order.
			for i, j := 0, len(batch)-1; i < j; i, j = i+1, j-1 {
				batch[i], batch[j] = batch[j], batch[i]
			}
			ingest(t, s, "node", batch, now)
			ingest(t, s, "node", batch, now)
			live := s.Latest(now)["node"][0]
			if *live.P50RTTMs != 49 || *live.P95RTTMs != 94 || *live.P99RTTMs != 98 || live.SampleCount != 110 {
				t.Fatal("live success population", live)
			}
			end := now.Truncate(time.Hour).Add(time.Hour)
			before, err := s.Query(ctx, "node", end, time.Hour, time.Hour)
			if err != nil || len(before) != 1 {
				t.Fatal(before, err)
			}
			b := before[0]
			if b.Count != 110 || b.Successes != 100 || b.UnknownCount != 5 || *b.P50RTTMs != 49 || *b.P95RTTMs != 94 || *b.P99RTTMs != 98 {
				t.Fatal("raw population", b)
			}
			if schema >= 6 {
				if err := s.EnableTiering(ctx, now); err != nil {
					t.Fatal(err)
				}
				if schema == 7 {
					if err := s.EnableReclamation(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if err := s.Maintain(ctx, now.Add(7*time.Hour)); err != nil {
					t.Fatal(err)
				}
				stats, err := s.TieredStats(ctx)
				if err != nil || stats.RawRows != 0 || stats.RollupRows != 1 {
					t.Fatal("not actually archived", stats, err)
				}
			}
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := Backup(ctx, s.path, backup); err != nil {
				t.Fatal(err)
			}
			restored := filepath.Join(t.TempDir(), "restored.db")
			if err := Restore(ctx, backup, restored, now.Add(7*time.Hour)); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(restored, now.Add(7*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			after, err := reopened.Query(ctx, "node", end, time.Hour, time.Hour)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("percentiles changed on archive/restore", after, err)
			}
			q := reopened.Latest(now.Add(7 * time.Hour))["node"][0]
			if !q.Stale || *q.P50RTTMs != 49 || *q.P95RTTMs != 94 || *q.P99RTTMs != 98 {
				t.Fatal("saved live percentiles changed", q)
			}
		})
	}
}

func TestLegacyArchivedLivePercentilesRemainUnavailable(t *testing.T) {
	s, now, _, _ := tieredFixture(t)
	ctx := context.Background()
	if err := s.Maintain(ctx, now.Add(7*time.Hour)); err != nil {
		t.Fatal(err)
	}
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	var payload []byte
	if err := db.QueryRow("SELECT stream,payload FROM probe_live LIMIT 1").Scan(&id, &payload); err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err := json.Unmarshal(payload, &old); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms"} {
		delete(old, key)
	}
	payload, err = json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if _, err := db.Exec("UPDATE probe_live SET payload=?,digest=? WHERE stream=?", payload, digest[:], id); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.path, now.Add(7*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	q := reopened.Latest(now.Add(7 * time.Hour))["robot"][0]
	if q.SampleCount == 0 || !q.Stale || q.P50RTTMs != nil || q.P95RTTMs != nil || q.P99RTTMs != nil {
		t.Fatal("legacy live snapshot invented percentiles", q)
	}
}
