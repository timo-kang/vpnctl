//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

func applicationLogRecord(id uint64) []byte {
	r := relayapply.TargetReconcileResult{SchemaVersion: 1, Applied: true, Selection: relayselect.Decision{Generation: id, TargetID: "app"}}
	for i := 0; i < 8; i++ {
		r.Selection.Candidates = append(r.Selection.Candidates, relayselect.Candidate{TargetObservation: relayobserve.TargetObservation{PathID: fmt.Sprintf("p%d", i), State: "reachable", Reason: "tcp_connect_verified", Fingerprint: strings.Repeat("a", 64), UnderlayGeneration: strings.Repeat("b", 64)}, Eligible: true})
	}
	b, _ := json.Marshal(r)
	return append(b, '\n')
}

func BenchmarkLatestApplicationResultGrowingLog(b *testing.B) {
	for _, records := range []int{10, 1000} {
		b.Run(fmt.Sprint(records), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "application.jsonl")
			var contents []byte
			for n := 0; n < records; n++ {
				contents = append(contents, applicationLogRecord(uint64(n+1))...)
			}
			if err := os.WriteFile(path, contents, 0600); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if got := latestApplicationResult(path); got.Selection.Generation != uint64(records) {
					b.Fatal("latest complete record missing")
				}
			}
		})
	}
}

func TestLatestApplicationResultRequiresCompleteRecords(t *testing.T) {
	first, second := applicationLogRecord(1), applicationLogRecord(2)
	for _, test := range []struct {
		name, log  string
		generation uint64
	}{
		{"empty", "", 0},
		{"one", string(first), 1},
		{"two", string(first) + string(second), 2},
		{"partial-next", string(first) + string(second[:len(second)-1]), 1},
		{"partial-only", string(first[:len(first)-1]), 0},
		{"warnings", string(first) + "warning\n{broken\n{\"schema_version\":2}\n", 1},
		{"blocked-is-latest", string(first) + "{\"schema_version\":1,\"applied\":false,\"selection\":{\"generation\":3}}\n", 3},
		{"oversized-record", string(first) + strings.Repeat("x", applicationLogRecordLimit+1) + "\n", 0},
		{"incomplete-tail", string(first) + strings.Repeat("x", 2*applicationLogRecordLimit+2), 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "app.jsonl")
			if err := os.WriteFile(path, []byte(test.log), 0600); err != nil {
				t.Fatal(err)
			}
			got := latestApplicationResult(path)
			if got.Selection.Generation != test.generation {
				t.Fatalf("generation=%d want=%d", got.Selection.Generation, test.generation)
			}
			if test.name == "blocked-is-latest" && got.Applied {
				t.Fatal("old success hid latest blocked state")
			}
		})
	}
	if latestApplicationResult(filepath.Join(t.TempDir(), "missing")).SchemaVersion != 0 {
		t.Fatal("missing log yielded proof")
	}
}

type measuredApplicationLog struct {
	*strings.Reader
	bytes int
}

func (r *measuredApplicationLog) ReadAt(b []byte, offset int64) (int, error) {
	r.bytes += len(b)
	return r.Reader.ReadAt(b, offset)
}
func TestLatestApplicationResultReadCostBoundedByTail(t *testing.T) {
	record := string(applicationLogRecord(7))
	log := strings.Repeat(record, 1000) + record[:len(record)-2]
	r := &measuredApplicationLog{Reader: strings.NewReader(log)}
	if got := readLatestApplicationResult(r, int64(len(log))); got.Selection.Generation != 7 {
		t.Fatal("latest full record lost across tail boundary")
	}
	if r.bytes > 2*applicationLogRecordLimit+1 || r.bytes >= len(log)/2 {
		t.Fatal("poll rescanned history", r.bytes, len(log))
	}
	if got := readLatestApplicationResult(strings.NewReader(record), int64(len(record)+1)); got.SchemaVersion != 0 {
		t.Fatal("concurrent truncation yielded proof")
	}
	if got := readLatestApplicationResult(strings.NewReader(record), 33*1024*1024); got.SchemaVersion != 0 {
		t.Fatal("oversized log yielded proof")
	}
}

func TestManagerPacketTraceCoversWholeFixture(t *testing.T) {
	r := &managerAutoTrace{}
	// Six 5 Hz samplers, 20 minutes, plus their initial samples.
	for n := 0; n < 6*(20*60*5+1); n++ {
		r.add(managerAutoEvent{Kind: "rf-lan", OK: true})
	}
	if _, failure := r.position(); failure != "" {
		t.Fatal("valid full-duration trace overflow", failure)
	}
	for n := len(r.events); n <= managerPacketTraceLimit; n++ {
		r.add(managerAutoEvent{})
	}
	if count, failure := r.position(); count != managerPacketTraceLimit || failure != "packet trace capacity exceeded" {
		t.Fatal("unbounded or silently truncated trace", count, failure)
	}
	r.failure = "original payload failure"
	r.add(managerAutoEvent{})
	if _, failure := r.position(); failure != "original payload failure" {
		t.Fatal("overflow hid earlier failure")
	}
}
