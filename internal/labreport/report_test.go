// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package labreport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	dir, manifest    string
	trace, resources []map[string]any
	verdict          map[string]any
	start            time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir(), start: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)}
	at := func(n int) time.Time { return f.start.Add(time.Duration(n) * time.Second) }
	f.manifest = filepath.Join(f.dir, "run.txt")
	write(t, f.manifest, []byte("suite_commit="+strings.Repeat("a", 40)+"\nsuite_dirty=false\n"+strings.Repeat("b", 64)+"  vpnctl\n"+strings.Repeat("c", 64)+"  suite\n"))
	f.trace = append(f.trace, map[string]any{"kind": "start", "at": at(0), "nodes": 3, "duration_seconds": 60})
	counts := map[string]int{}
	for i, p := range phases {
		n := 2 + 5*i
		f.trace = append(f.trace, map[string]any{"kind": "fault_start", "at": at(n), "phase": p})
		switch p {
		case "controller_restart", "underlay_loss":
			f.trace = append(f.trace, map[string]any{"at": at(n + 1), "phase": p, "node": "node-0", "error": "injected outage"})
		case "target_restart":
			f.trace = append(f.trace, map[string]any{"at": at(n + 1), "phase": p, "node": "node-0", "latest_uplink_failure_stage": "server_endpoint"})
		case "node_remove_rejoin":
			v := normal(at(n+1), "node_removed", "node-0")
			v["registered_nodes"] = 2
			f.trace = append(f.trace, v)
		}
		f.trace = append(f.trace, map[string]any{"kind": "fault_recovered", "at": at(n + 2), "phase": p, "duration_seconds": 2})
		counts[p] = 1
	}
	for i, node := range []string{"node-0", "node-1", "node-2"} {
		f.trace = append(f.trace, normal(at(58+i), "final", node))
	}
	f.trace = append(f.trace, map[string]any{"kind": "workload_end", "at": at(61), "elapsed_seconds": 61})
	for i := 0; i <= 61; i++ {
		f.resources = append(f.resources, map[string]any{"at": at(i), "resources": map[string]string{"memory.current": "1000"}})
	}
	f.verdict = map[string]any{"schema_version": 1, "completed": true, "started_at": at(0), "finished_at": at(62), "requested_seconds": 60, "nodes": 3, "phases": counts, "wall_clock_24h": false, "m2_gate": "pending_review"}
	return f
}
func normal(at time.Time, phase, node string) map[string]any {
	lat := map[string]float64{}
	for _, op := range operations {
		lat[op] = 1
	}
	return map[string]any{"at": at, "phase": phase, "node": node, "registered_nodes": 3, "heartbeat_unknown": 0, "heartbeat_max_age_seconds": 1, "wireguard_observed_at": at.Add(-time.Second), "wireguard_peers": 3, "probe_sources": map[string]int{"agent-direct": 1, "monitor-overlay": 1}, "api_latency_ms": lat, "storage": map[string]any{"validity": "observed", "stale": false, "observed_at": at.Add(-time.Second), "values": map[string]int64{"database_bytes": 4096, "wal_bytes": 0}}}
}
func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) save(t *testing.T) {
	t.Helper()
	for name, rows := range map[string][]map[string]any{"trace.jsonl": f.trace, "resources.jsonl": f.resources} {
		var b []byte
		for _, row := range rows {
			v, e := json.Marshal(row)
			if e != nil {
				t.Fatal(e)
			}
			b = append(b, v...)
			b = append(b, '\n')
		}
		write(t, filepath.Join(f.dir, name), b)
	}
	b, e := json.Marshal(f.verdict)
	if e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(f.dir, "verdict.json"), b)
}
func finding(r Report, code string) bool {
	for _, v := range r.Findings {
		if v.Code == code {
			return true
		}
	}
	return false
}
func TestAnalyzeCompleteIsNotQualification(t *testing.T) {
	f := newFixture(t)
	f.save(t)
	zero := 0
	r := Analyze(f.dir, f.manifest, &zero)
	if r.Status != "complete" || r.M2Gate != "pending_review" || r.WallClock24h || len(r.Findings) != 0 || r.Population != "not_reconcilable_from_soak_trace" {
		t.Fatalf("%+v", r)
	}
	if r.ExpectedFaultErrors != 2 || r.ObservedSeconds != 61 || r.ResourceSamples != 62 || r.LatencyMS["final"]["storage"].Count != 3 {
		t.Fatalf("wrong evidence: %+v", r)
	}
	for _, in := range r.Inputs {
		b, e := os.ReadFile(filepath.Join(f.dir, in.Name))
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		if in.Scope != "full_read" || in.Bytes != int64(len(b)) || in.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("bad hash %+v", in)
		}
	}
}

func TestAnalyzeOptionalPeerDiagnosticLatency(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func(map[string]float64)
	}{
		{name: "bounded optional operation"},
		{name: "diagnostic deadline is not readiness", edit: func(lat map[string]float64) { lat["peer_diagnostic"] = 2100 }},
		{name: "required request still required", code: "request_latency_missing", edit: func(lat map[string]float64) { delete(lat, "storage") }},
		{name: "required deadline still enforced", code: "normal_request_deadline", edit: func(lat map[string]float64) { lat["storage"] = 2001 }},
		{name: "negative diagnostic rejected", code: "trace.jsonl_invalid_record", edit: func(lat map[string]float64) { lat["peer_diagnostic"] = -1 }},
		{name: "unknown operation rejected", code: "trace.jsonl_invalid_record", edit: func(lat map[string]float64) { delete(lat, "peer_diagnostic"); lat["unknown"] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// Node removal legitimately has an older WG sample than the current
			// registry. The runner adds an optional diagnostic to this sample.
			for _, row := range f.trace {
				if row["phase"] != "node_removed" {
					continue
				}
				lat := row["api_latency_ms"].(map[string]float64)
				lat["peer_diagnostic"] = 3
				if tc.edit != nil {
					tc.edit(lat)
				}
			}
			f.save(t)
			zero := 0
			r := Analyze(f.dir, f.manifest, &zero)
			if tc.code != "" {
				if r.Status == "complete" || !finding(r, tc.code) {
					t.Fatalf("want %s: %+v", tc.code, r)
				}
			} else if r.Status != "complete" || len(r.Findings) != 0 || r.LatencyMS["node_removed"]["peer_diagnostic"].Count != 1 {
				t.Fatalf("optional diagnostic broke analysis: %+v", r)
			}
		})
	}
}

func TestAnalyzeRejectsMissingAndContradictoryEvidence(t *testing.T) {
	tests := []struct {
		name, code, status string
		edit               func(*fixture)
		file               func(*testing.T, *fixture)
		noExit             bool
	}{
		{name: "no exit", code: "process_exit_missing", status: "incomplete", noExit: true},
		{name: "no verdict", code: "verdict.json_unreadable", status: "incomplete", file: func(t *testing.T, f *fixture) {
			if e := os.Remove(filepath.Join(f.dir, "verdict.json")); e != nil {
				t.Fatal(e)
			}
		}},
		{name: "false pass", code: "runner_reported_failure", status: "failed", edit: func(f *fixture) { f.verdict["completed"] = false }},
		{name: "forged 24h", code: "verdict_wall_clock_mismatch", status: "failed", edit: func(f *fixture) { f.verdict["wall_clock_24h"] = true }},
		{name: "wrong duration", code: "workload_duration_short_or_mismatched", status: "failed", edit: func(f *fixture) { f.trace[len(f.trace)-1]["elapsed_seconds"] = 86400 }},
		{name: "no end", code: "workload_end_missing", status: "incomplete", edit: func(f *fixture) { f.trace = f.trace[:len(f.trace)-1] }},
		{name: "no final node", code: "final_node_coverage_missing", status: "incomplete", edit: func(f *fixture) { f.trace[len(f.trace)-2]["node"] = "node-0" }},
		{name: "outage not observed", code: "fault_observation_missing_controller_restart", status: "incomplete", edit: func(f *fixture) { delete(f.trace[2], "error") }},
		{name: "target not diagnosed", code: "fault_observation_missing_target_restart", status: "incomplete", edit: func(f *fixture) {
			for _, r := range f.trace {
				delete(r, "latest_uplink_failure_stage")
			}
		}},
		{name: "unmatched recovery", code: "trace.jsonl_invalid_record", status: "failed", edit: func(f *fixture) { f.trace[3]["phase"] = "ca_rotation" }},
		{name: "clock rollback", code: "trace_clock_regressed", status: "failed", edit: func(f *fixture) { f.trace[2]["at"] = f.start }},
		{name: "heartbeat unknown", code: "normal_heartbeat_or_registry_invalid", status: "failed", edit: func(f *fixture) { f.trace[len(f.trace)-2]["heartbeat_unknown"] = 1 }},
		{name: "unknown storage", code: "normal_storage_unknown", status: "failed", edit: func(f *fixture) { f.trace[len(f.trace)-2]["storage"] = map[string]any{"validity": "unknown"} }},
		{name: "stale WG", code: "normal_wireguard_stale", status: "failed", edit: func(f *fixture) { f.trace[len(f.trace)-2]["wireguard_observed_at"] = f.start.Add(-time.Minute) }},
		{name: "missing producer", code: "normal_producer_coverage_missing", status: "incomplete", edit: func(f *fixture) { f.trace[len(f.trace)-2]["probe_sources"] = map[string]int{"agent-direct": 1} }},
		{name: "slow read", code: "normal_request_deadline", status: "failed", edit: func(f *fixture) { f.trace[len(f.trace)-2]["api_latency_ms"].(map[string]float64)["storage"] = 2001 }},
		{name: "missing latency", code: "request_latency_missing", status: "incomplete", edit: func(f *fixture) { delete(f.trace[len(f.trace)-2]["api_latency_ms"].(map[string]float64), "storage") }},
		{name: "normal error", code: "unexpected_observation_error", status: "failed", edit: func(f *fixture) { f.trace[len(f.trace)-2]["error"] = "timeout" }},
		{name: "resource gap", code: "resource_gap", status: "incomplete", edit: func(f *fixture) { f.resources = append(f.resources[:2], f.resources[10:]...) }},
		{name: "resource stopped", code: "resource_end_coverage_missing", status: "incomplete", edit: func(f *fixture) { f.resources = f.resources[:20] }},
		{name: "resource memory absent", code: "resource_memory_missing", status: "incomplete", edit: func(f *fixture) { f.resources[4]["resources"] = map[string]string{} }},
		{name: "resource rollback", code: "resource_clock_regressed", status: "failed", edit: func(f *fixture) { f.resources[4]["at"] = f.start }},
		{name: "truncated JSON", code: "trace.jsonl_invalid_record", status: "failed", file: func(t *testing.T, f *fixture) {
			p := filepath.Join(f.dir, "trace.jsonl")
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			write(t, p, append(b, []byte(`{"at":`)...))
		}},
		{name: "dirty manifest", code: "suite_has_uncommitted_changes", status: "incomplete", file: func(t *testing.T, f *fixture) {
			b, e := os.ReadFile(f.manifest)
			if e != nil {
				t.Fatal(e)
			}
			write(t, f.manifest, []byte(strings.Replace(string(b), "suite_dirty=false", "suite_dirty=true", 1)))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.edit != nil {
				tc.edit(f)
			}
			f.save(t)
			if tc.file != nil {
				tc.file(t, f)
			}
			zero := 0
			exit := &zero
			if tc.noExit {
				exit = nil
			}
			r := Analyze(f.dir, f.manifest, exit)
			if r.Status != tc.status || !finding(r, tc.code) || r.M2Gate != "pending_review" {
				t.Fatalf("%s want %s/%s got %s %+v", tc.name, tc.status, tc.code, r.Status, r.Findings)
			}
		})
	}
}
func TestAnalyzeCountersAreLowerBounds(t *testing.T) {
	f := newFixture(t)
	// A process reset between observations cannot recover its missing suffix.
	rows := []map[string]any{}
	for i, n := range []uint64{10, 13, 2, 5} {
		r := normal(f.start.Add(time.Duration(35+i)*time.Second), "steady", "node-0")
		r["delivery"] = map[string]any{"enabled": true, "delivery": map[string]any{"delivered": n}}
		rows = append(rows, r)
	}
	at := len(f.trace) - 4
	f.trace = append(append(append([]map[string]any{}, f.trace[:at]...), rows...), f.trace[at:]...)
	f.save(t)
	zero := 0
	r := Analyze(f.dir, f.manifest, &zero)
	c := r.Counters["node-0"]["probe_delivered"]
	if r.Status != "complete" || c.Last != 5 || c.Increments != 8 || c.Decreases != 1 {
		t.Fatalf("%+v / %+v", c, r.Findings)
	}
}
func TestAnalyzeNonzeroExitAndInputBounds(t *testing.T) {
	f := newFixture(t)
	f.save(t)
	code := 9
	r := Analyze(f.dir, f.manifest, &code)
	if r.Status != "failed" || !finding(r, "process_exit_nonzero") {
		t.Fatal(r)
	}
	a := analyzer{seen: map[string]bool{}}
	p := filepath.Join(t.TempDir(), "trace.jsonl")
	write(t, p, []byte("{}\n{}\n{}\n"))
	a.scan(p, 1, func([]byte) error { return nil })
	if !finding(a.r, "trace.jsonl_record_limit_or_empty") {
		t.Fatal(a.r)
	}
	if a.r.Inputs[0].Bytes != 9 || a.r.Inputs[0].Scope != "full_read" {
		t.Fatal(a.r.Inputs)
	}
}
func TestNearestRankQuantiles(t *testing.T) {
	if d := Summarize(nil); d.Count != 0 || d.P99 != nil {
		t.Fatal(d)
	}
	values := []float64{8, 1, 4, 2}
	before := append([]float64(nil), values...)
	d := Summarize(values)
	if *d.P50 != 2 || *d.P95 != 8 || *d.P99 != 8 || *d.Max != 8 || !reflect.DeepEqual(values, before) {
		t.Fatal(d)
	}
}

func TestObservationTimestampIsReadSequenceStart(t *testing.T) {
	f := newFixture(t)
	final := f.trace[len(f.trace)-2]
	at := final["at"].(time.Time)
	final["wireguard_observed_at"] = at.Add(3 * time.Millisecond)
	final["storage"].(map[string]any)["observed_at"] = at.Add(3 * time.Millisecond)
	f.save(t)
	zero := 0
	r := Analyze(f.dir, f.manifest, &zero)
	if r.Status != "complete" {
		t.Fatal(r.Findings)
	}
	final["wireguard_observed_at"] = at.Add(time.Second)
	f.save(t)
	r = Analyze(f.dir, f.manifest, &zero)
	if r.Status != "failed" || !finding(r, "normal_wireguard_stale") {
		t.Fatal(r.Findings)
	}
}

func TestCollectionCompletionIncludesReadOverhead(t *testing.T) {
	f := newFixture(t)
	v := f.trace[len(f.trace)-2]
	at := v["at"].(time.Time)
	v["observation_completed_at"] = at.Add(100 * time.Millisecond)
	v["wireguard_observed_at"] = at.Add(50 * time.Millisecond)
	f.save(t)
	zero := 0
	r := Analyze(f.dir, f.manifest, &zero)
	if r.Status != "complete" {
		t.Fatal(r.Findings)
	}
	v["observation_completed_at"] = at.Add(-time.Second)
	f.save(t)
	r = Analyze(f.dir, f.manifest, &zero)
	if r.Status != "failed" || !finding(r, "invalid_collection_duration") {
		t.Fatal(r.Findings)
	}
}
