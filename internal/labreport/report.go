// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
// Package labreport reads public lab artifacts. It never contacts a controller.
package labreport

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var phases = []string{"controller_restart", "underlay_loss", "target_restart", "monitor_restart", "node_remove_rejoin", "ca_rotation", "ca_rollback"}
var operations = []string{"local_monitor", "fleet_status", "storage", "wireguard", "uplink", "events", "alerts"}

type Distribution struct {
	Count int      `json:"count"`
	P50   *float64 `json:"p50"`
	P95   *float64 `json:"p95"`
	P99   *float64 `json:"p99"`
	Max   *float64 `json:"max"`
}

// Summarize uses nearest-rank quantiles over the observed requests only.
func Summarize(values []float64) Distribution {
	d := Distribution{Count: len(values)}
	if len(values) == 0 {
		return d
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	rank := func(q float64) *float64 { x := v[int(math.Ceil(float64(len(v))*q))-1]; return &x }
	d.P50, d.P95, d.P99, d.Max = rank(.5), rank(.95), rank(.99), rank(1)
	return d
}

type Input struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Scope  string `json:"hash_scope"`
}
type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
}
type Counter struct {
	Last       uint64 `json:"last_observed"`
	Increments uint64 `json:"observed_increments_lower_bound"`
	Decreases  int    `json:"observed_decreases"`
}
type Report struct {
	SchemaVersion       int                                `json:"schema_version"`
	Status              string                             `json:"run_status"`
	M2Gate              string                             `json:"m2_gate"`
	Inputs              []Input                            `json:"inputs"`
	Findings            []Finding                          `json:"findings"`
	SuiteCommit         string                             `json:"suite_commit"`
	SuiteDirty          *bool                              `json:"suite_dirty"`
	BinaryDigests       []string                           `json:"binary_sha256"`
	StartedAt           *time.Time                         `json:"started_at"`
	WorkloadEnd         *time.Time                         `json:"workload_end"`
	RequestedSeconds    float64                            `json:"requested_seconds"`
	ObservedSeconds     float64                            `json:"observed_workload_seconds"`
	WallClock24h        bool                               `json:"wall_clock_24h"`
	Nodes               int                                `json:"configured_nodes"`
	Observations        int                                `json:"observation_records"`
	ObservedNodes       int                                `json:"observed_node_identities"`
	Phases              map[string]int                     `json:"recovered_phases"`
	RecoverySeconds     map[string]Distribution            `json:"recovery_seconds"`
	LatencyMS           map[string]map[string]Distribution `json:"request_latency_ms"`
	MaxSampleGapSeconds float64                            `json:"max_trace_gap_seconds"`
	NormalErrors        int                                `json:"normal_errors"`
	ExpectedFaultErrors int                                `json:"expected_fault_errors"`
	TruncatedEventPages int                                `json:"truncated_event_pages"`
	ResourceSamples     int                                `json:"resource_samples"`
	MemoryPeak          *uint64                            `json:"observed_memory_peak_bytes"`
	DBPeak              *int64                             `json:"observed_db_peak_bytes"`
	WALPeak             *int64                             `json:"observed_wal_peak_bytes"`
	Counters            map[string]map[string]Counter      `json:"monitor_counters"`
	Population          string                             `json:"population_reconciliation"`
	Limitations         []string                           `json:"limitations"`
}

type observation struct {
	Kind             string             `json:"kind"`
	At               time.Time          `json:"at"`
	Phase            string             `json:"phase"`
	Node             string             `json:"node"`
	Error            string             `json:"error"`
	Nodes            int                `json:"nodes"`
	Duration         float64            `json:"duration_seconds"`
	Elapsed          float64            `json:"elapsed_seconds"`
	Registered       *int               `json:"registered_nodes"`
	HeartbeatUnknown *int               `json:"heartbeat_unknown"`
	HeartbeatAge     *float64           `json:"heartbeat_max_age_seconds"`
	WGAt             *time.Time         `json:"wireguard_observed_at"`
	WGPeers          *int               `json:"wireguard_peers"`
	Sources          map[string]int     `json:"probe_sources"`
	Truncated        bool               `json:"events_truncated"`
	UplinkStage      string             `json:"latest_uplink_failure_stage"`
	Latency          map[string]float64 `json:"api_latency_ms"`
	Storage          *struct {
		Validity string     `json:"validity"`
		Stale    bool       `json:"stale"`
		At       *time.Time `json:"observed_at"`
		Values   *struct {
			DB  int64 `json:"database_bytes"`
			WAL int64 `json:"wal_bytes"`
		} `json:"values"`
	} `json:"storage"`
	Delivery struct {
		Enabled bool     `json:"enabled"`
		Probe   counters `json:"delivery"`
		WG      counters `json:"wireguard_delivery"`
		Mapping uint64   `json:"mapping_dropped"`
	} `json:"delivery"`
}
type counters struct {
	Delivered uint64 `json:"delivered"`
	Dropped   uint64 `json:"dropped"`
	Quota     uint64 `json:"quota_dropped"`
}
type verdict struct {
	Version   int            `json:"schema_version"`
	Completed *bool          `json:"completed"`
	Started   time.Time      `json:"started_at"`
	Finished  time.Time      `json:"finished_at"`
	Requested float64        `json:"requested_seconds"`
	Nodes     int            `json:"nodes"`
	Phases    map[string]int `json:"phases"`
	WallClock *bool          `json:"wall_clock_24h"`
	Gate      string         `json:"m2_gate"`
}

type analyzer struct {
	r             Report
	seen          map[string]bool
	lat           map[string]map[string][]float64
	recovery      map[string][]float64
	previous      time.Time
	open          string
	faultAt       time.Time
	faultObserved bool
	ended         bool
	finalStarted  bool
	finalNodes    map[string]bool
	nodeLast      map[string]time.Time
}

func (a *analyzer) finding(severity, code string) {
	key := severity + ":" + code
	if !a.seen[key] {
		a.seen[key] = true
		a.r.Findings = append(a.r.Findings, Finding{severity, code})
	}
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Analyze accepts one soak output directory, its manifest and an independently
// recorded process exit code. A missing exit code cannot establish completion.
// All reads are bounded and streaming; no supplied file can approve the M2 gate.
func Analyze(dir, manifest string, exitCode *int) Report {
	a := analyzer{r: Report{SchemaVersion: 1, Status: "complete", M2Gate: "pending_review", Inputs: []Input{}, Findings: []Finding{}, Phases: map[string]int{}, RecoverySeconds: map[string]Distribution{}, LatencyMS: map[string]map[string]Distribution{}, Counters: map[string]map[string]Counter{}, Population: "not_reconcilable_from_soak_trace", Limitations: []string{
		"Windowed probe/uplink counts and limited event/WG pages are not an admission ledger.",
		"Counter increments are lower bounds; unobserved restarts and initial prefixes prevent exact delivery accounting.",
		"Resource and cached storage peaks describe sampled points, not continuous maxima.",
		"Read API latency is not heartbeat/renewal/route-control latency or a deployment SLO.",
		"CA operations, removed-credential replay and final integrity checks rely on the runner exit/verdict, not independent trace proof.",
		"Short or baseline completion does not establish mixed storage pressure, full population reconciliation or representative deployment qualification.",
	}}, seen: map[string]bool{}, lat: map[string]map[string][]float64{}, recovery: map[string][]float64{}, finalNodes: map[string]bool{}, nodeLast: map[string]time.Time{}}
	if manifest == "" {
		a.finding("incomplete", "manifest_missing")
	} else {
		a.manifest(manifest)
	}
	a.scan(filepath.Join(dir, "trace.jsonl"), 100000, func(line []byte) error {
		var v observation
		if err := json.Unmarshal(line, &v); err != nil {
			return err
		}
		return a.observe(v)
	})
	var resourceFirst, resourceLast time.Time
	a.scan(filepath.Join(dir, "resources.jsonl"), 750000, func(line []byte) error {
		var v struct {
			At        time.Time         `json:"at"`
			Resources map[string]string `json:"resources"`
		}
		if err := json.Unmarshal(line, &v); err != nil {
			return err
		}
		if v.At.IsZero() {
			return fmt.Errorf("resource timestamp missing")
		}
		if resourceFirst.IsZero() {
			resourceFirst = v.At
		}
		if !resourceLast.IsZero() {
			gap := v.At.Sub(resourceLast).Seconds()
			if gap < 0 {
				a.finding("failed", "resource_clock_regressed")
			}
			if gap > 5 {
				a.finding("incomplete", "resource_gap")
			}
		}
		resourceLast = v.At
		a.r.ResourceSamples++
		if n, e := strconv.ParseUint(v.Resources["memory.current"], 10, 64); e == nil {
			if a.r.MemoryPeak == nil || n > *a.r.MemoryPeak {
				a.r.MemoryPeak = &n
			}
		} else {
			a.finding("incomplete", "resource_memory_missing")
		}
		return nil
	})
	if a.r.StartedAt != nil && (resourceFirst.IsZero() || math.Abs(resourceFirst.Sub(*a.r.StartedAt).Seconds()) > 5) {
		a.finding("incomplete", "resource_start_coverage_missing")
	}
	if a.r.WorkloadEnd != nil && (resourceLast.IsZero() || resourceLast.Before(a.r.WorkloadEnd.Add(-5*time.Second))) {
		a.finding("incomplete", "resource_end_coverage_missing")
	}
	var v verdict
	if a.object(filepath.Join(dir, "verdict.json"), &v) {
		if v.Version != 1 || v.Completed == nil || v.WallClock == nil || v.Gate != "pending_review" {
			a.finding("failed", "invalid_verdict_contract")
		} else {
			if !*v.Completed {
				a.finding("failed", "runner_reported_failure")
			}
			if a.r.StartedAt == nil || !v.Started.Equal(*a.r.StartedAt) || v.Requested != a.r.RequestedSeconds || v.Nodes != a.r.Nodes {
				a.finding("failed", "verdict_start_mismatch")
			}
			if a.r.WorkloadEnd == nil {
				a.finding("incomplete", "workload_end_missing")
			} else if v.Finished.Before(*a.r.WorkloadEnd) {
				a.finding("failed", "verdict_end_mismatch")
			}
			if *v.WallClock != a.r.WallClock24h {
				a.finding("failed", "verdict_wall_clock_mismatch")
			}
			for _, phase := range phases {
				if v.Phases[phase] != a.r.Phases[phase] {
					a.finding("failed", "verdict_phase_mismatch")
				}
			}
			for phase := range v.Phases {
				if !contains(phases, phase) {
					a.finding("failed", "unknown_verdict_phase")
				}
			}
		}
	}
	if exitCode == nil {
		a.finding("incomplete", "process_exit_missing")
	} else if *exitCode != 0 {
		a.finding("failed", "process_exit_nonzero")
	}
	if a.r.StartedAt == nil {
		a.finding("incomplete", "start_missing")
	}
	if !a.ended {
		a.finding("incomplete", "workload_end_missing")
	}
	if a.open != "" {
		a.finding("incomplete", "fault_not_recovered")
	}
	for _, phase := range phases {
		if a.r.Phases[phase] == 0 {
			a.finding("incomplete", "phase_missing_"+phase)
		}
	}
	if a.r.Nodes == 0 || len(a.finalNodes) != a.r.Nodes {
		a.finding("incomplete", "final_node_coverage_missing")
	}
	if a.r.ResourceSamples == 0 || a.r.MemoryPeak == nil {
		a.finding("incomplete", "resource_evidence_missing")
	}
	for phase, ops := range a.lat {
		a.r.LatencyMS[phase] = map[string]Distribution{}
		for op, values := range ops {
			a.r.LatencyMS[phase][op] = Summarize(values)
		}
	}
	for phase, values := range a.recovery {
		a.r.RecoverySeconds[phase] = Summarize(values)
	}
	a.r.ObservedNodes = len(a.nodeLast)
	for _, f := range a.r.Findings {
		if f.Severity == "incomplete" && a.r.Status == "complete" {
			a.r.Status = "incomplete"
		}
		if f.Severity == "failed" {
			a.r.Status = "failed"
		}
	}
	return a.r
}
func (a *analyzer) observe(v observation) error {
	if v.At.IsZero() {
		return fmt.Errorf("timestamp missing")
	}
	if !a.previous.IsZero() {
		gap := v.At.Sub(a.previous).Seconds()
		if gap < 0 {
			a.finding("failed", "trace_clock_regressed")
		}
		if gap > a.r.MaxSampleGapSeconds {
			a.r.MaxSampleGapSeconds = gap
		}
		if a.open == "" && gap > 30 {
			a.finding("incomplete", "normal_trace_gap")
		}
	}
	a.previous = v.At
	if a.ended {
		return fmt.Errorf("record after workload end")
	}
	switch v.Kind {
	case "start":
		if a.r.StartedAt != nil || v.Nodes < 3 || v.Nodes > 32 || v.Duration < 60 || v.Duration > 604800 {
			return fmt.Errorf("invalid start")
		}
		a.r.StartedAt = &v.At
		a.r.Nodes = v.Nodes
		a.r.RequestedSeconds = v.Duration
	case "fault_start":
		if a.r.StartedAt == nil || a.open != "" || a.finalStarted || !contains(phases, v.Phase) {
			return fmt.Errorf("unmatched fault start")
		}
		a.open, a.faultAt = v.Phase, v.At
		a.faultObserved = false
	case "fault_recovered":
		if a.open == "" || a.open != v.Phase || v.At.Before(a.faultAt) {
			return fmt.Errorf("unmatched fault recovery")
		}
		elapsed := v.At.Sub(a.faultAt).Seconds()
		if math.Abs(elapsed-v.Duration) > .1 {
			a.finding("failed", "recovery_duration_mismatch")
		}
		if contains([]string{"controller_restart", "underlay_loss", "target_restart", "node_remove_rejoin"}, v.Phase) && !a.faultObserved {
			a.finding("incomplete", "fault_observation_missing_"+v.Phase)
		}
		a.r.Phases[v.Phase]++
		a.recovery[v.Phase] = append(a.recovery[v.Phase], elapsed)
		a.open = ""
	case "workload_end":
		if a.r.StartedAt == nil || a.open != "" {
			return fmt.Errorf("invalid workload end")
		}
		a.ended = true
		a.r.WorkloadEnd = &v.At
		a.r.ObservedSeconds = v.At.Sub(*a.r.StartedAt).Seconds()
		a.r.WallClock24h = a.r.ObservedSeconds >= 86400
		if math.Abs(a.r.ObservedSeconds-v.Elapsed) > .1 || a.r.ObservedSeconds < a.r.RequestedSeconds {
			a.finding("failed", "workload_duration_short_or_mismatched")
		}
	case "":
		return a.sample(v)
	default:
		return fmt.Errorf("unknown record kind")
	}
	return nil
}
func (a *analyzer) sample(v observation) error {
	if a.r.StartedAt == nil || v.Node == "" || len(v.Node) > 128 || len(a.nodeLast) > 1024 {
		return fmt.Errorf("invalid observation identity")
	}
	// Auxiliary samples are meaningful only within their matching fault.
	if (v.Phase == "before_monitor_restart" && a.open != "monitor_restart") ||
		((v.Phase == "before_node_remove" || v.Phase == "node_removed") && a.open != "node_remove_rejoin") {
		return fmt.Errorf("auxiliary observation outside matching fault")
	}
	normal := contains([]string{"steady", "final", "before_monitor_restart", "before_node_remove", "node_removed"}, v.Phase)
	if !normal && v.Phase != a.open {
		return fmt.Errorf("observation outside active phase")
	}
	if normal && a.open != "" && v.Phase != "before_monitor_restart" && v.Phase != "before_node_remove" && v.Phase != "node_removed" {
		return fmt.Errorf("normal observation inside fault")
	}
	if a.finalStarted && v.Phase != "final" {
		return fmt.Errorf("observation after final coverage")
	}
	a.r.Observations++
	a.nodeLast[v.Node] = v.At
	if v.Phase == "final" {
		a.finalStarted = true
		a.finalNodes[v.Node] = true
	}
	if v.Truncated {
		a.r.TruncatedEventPages++
	}
	if v.Error != "" {
		if (v.Phase == "controller_restart" || v.Phase == "underlay_loss") && v.Phase == a.open {
			a.r.ExpectedFaultErrors++
			a.faultObserved = true
		} else {
			a.r.NormalErrors++
			a.finding("failed", "unexpected_observation_error")
		}
	}
	if v.Error == "" && a.open == "target_restart" && v.Phase == a.open && v.UplinkStage == "server_endpoint" {
		a.faultObserved = true
	}
	if v.Error == "" && a.open == "node_remove_rejoin" && v.Phase == "node_removed" && v.Registered != nil && *v.Registered == a.r.Nodes-1 {
		a.faultObserved = true
	}
	if normal && v.Error == "" {
		if v.Registered == nil || v.HeartbeatUnknown == nil || v.HeartbeatAge == nil || v.Storage == nil || v.WGAt == nil || v.WGPeers == nil {
			return fmt.Errorf("normal observation fields missing")
		}
		expected := a.r.Nodes
		if v.Phase == "node_removed" {
			expected--
		}
		if *v.Registered != expected || *v.HeartbeatUnknown != 0 || *v.HeartbeatAge < 0 || *v.HeartbeatAge > 30 {
			a.finding("failed", "normal_heartbeat_or_registry_invalid")
		}
		// The worker timestamps the beginning of a sequence of reads. A cached
		// observation collected during that sequence may be newer than At.
		var collectionMS float64
		for _, latency := range v.Latency {
			if latency >= 0 && latency <= 2000 {
				collectionMS += latency
			}
		}
		collectionSeconds := collectionMS / 1000
		h := v.Storage
		if h.Validity != "observed" || h.Stale || h.At == nil || h.Values == nil {
			a.finding("failed", "normal_storage_unknown")
		} else {
			age := v.At.Sub(*h.At).Seconds()
			if age < -collectionSeconds || age >= 90 {
				a.finding("failed", "normal_storage_stale")
			}
			db, wal := h.Values.DB, h.Values.WAL
			if db < 0 || wal < 0 || db > 1<<30 || wal > 64<<20 {
				a.finding("failed", "normal_storage_budget")
			}
			if a.r.DBPeak == nil || db > *a.r.DBPeak {
				a.r.DBPeak = &db
			}
			if a.r.WALPeak == nil || wal > *a.r.WALPeak {
				a.r.WALPeak = &wal
			}
		}
		if v.Phase == "steady" || v.Phase == "final" {
			age := v.At.Sub(*v.WGAt).Seconds()
			if age < -collectionSeconds || age >= 90 {
				a.finding("failed", "normal_wireguard_stale")
			}
			if *v.WGPeers != a.r.Nodes || v.Sources["agent-direct"] <= 0 || v.Sources["monitor-overlay"] <= 0 {
				a.finding("incomplete", "normal_producer_coverage_missing")
			}
		}
		for _, op := range operations {
			if _, ok := v.Latency[op]; !ok {
				a.finding("incomplete", "request_latency_missing")
			}
		}
	}
	if len(v.Latency) > len(operations) {
		return fmt.Errorf("unexpected operation count")
	}
	if a.lat[v.Phase] == nil {
		a.lat[v.Phase] = map[string][]float64{}
	}
	for op, n := range v.Latency {
		if !contains(operations, op) || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return fmt.Errorf("invalid request latency")
		}
		a.lat[v.Phase][op] = append(a.lat[v.Phase][op], n)
		if normal && n > 2000 {
			a.finding("failed", "normal_request_deadline")
		}
	}
	if v.Error == "" && v.Delivery.Enabled {
		if a.r.Counters[v.Node] == nil {
			a.r.Counters[v.Node] = map[string]Counter{}
		}
		for key, n := range map[string]uint64{"probe_delivered": v.Delivery.Probe.Delivered, "probe_dropped": v.Delivery.Probe.Dropped, "probe_quota_dropped": v.Delivery.Probe.Quota, "wg_delivered": v.Delivery.WG.Delivered, "wg_dropped": v.Delivery.WG.Dropped, "wg_quota_dropped": v.Delivery.WG.Quota, "mapping_dropped": v.Delivery.Mapping} {
			prev, ok := a.r.Counters[v.Node][key]
			if ok {
				delta := n
				if n >= prev.Last {
					delta = n - prev.Last
				} else {
					prev.Decreases++
				}
				if math.MaxUint64-prev.Increments < delta {
					return fmt.Errorf("counter overflow")
				}
				prev.Increments += delta
			}
			prev.Last = n
			a.r.Counters[v.Node][key] = prev
		}
	}
	return nil
}

func (a *analyzer) scan(path string, limit int, fn func([]byte) error) {
	f, e := os.Open(path)
	if e != nil {
		a.finding("incomplete", filepath.Base(path)+"_unreadable")
		return
	}
	defer f.Close()
	hash := sha256.New()
	reader := &countReader{r: io.LimitReader(f, 1<<30+1), h: hash}
	s := bufio.NewScanner(reader)
	s.Buffer(make([]byte, 64<<10), 16<<20)
	n := 0
	for s.Scan() {
		n++
		if n > limit || len(s.Bytes()) == 0 {
			a.finding("failed", filepath.Base(path)+"_record_limit_or_empty")
			break
		}
		if err := fn(s.Bytes()); err != nil {
			a.finding("failed", filepath.Base(path)+"_invalid_record")
			break
		}
	}
	// Finish hashing the bounded input even when record validation stopped early.
	_, drainErr := io.Copy(io.Discard, reader)
	scope := "full_read"
	if reader.n > 1<<30 {
		scope = "bounded_prefix"
	}
	if s.Err() != nil || drainErr != nil || reader.n > 1<<30 {
		a.finding("failed", filepath.Base(path)+"_read_limit_or_error")
	}
	if reader.n > 0 && reader.last != '\n' {
		a.finding("incomplete", filepath.Base(path)+"_partial_tail")
	}
	a.r.Inputs = append(a.r.Inputs, Input{filepath.Base(path), reader.n, hex.EncodeToString(hash.Sum(nil)), scope})
}

type countReader struct {
	r    io.Reader
	h    io.Writer
	n    int64
	last byte
}

func (r *countReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.h.Write(p[:n])
	r.n += int64(n)
	if n > 0 {
		r.last = p[n-1]
	}
	return n, e
}
func (a *analyzer) object(path string, v any) bool {
	b, e := readSmall(path)
	if e != nil {
		a.finding("incomplete", filepath.Base(path)+"_unreadable")
		return false
	}
	sum := sha256.Sum256(b)
	a.r.Inputs = append(a.r.Inputs, Input{filepath.Base(path), int64(len(b)), hex.EncodeToString(sum[:]), "full_read"})
	if e = json.Unmarshal(b, v); e != nil {
		a.finding("failed", filepath.Base(path)+"_invalid_json")
		return false
	}
	return true
}
func readSmall(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("input too large")
	}
	return b, e
}
func (a *analyzer) manifest(path string) {
	b, e := readSmall(path)
	if e != nil {
		a.finding("incomplete", "manifest_unreadable")
		return
	}
	sum := sha256.Sum256(b)
	a.r.Inputs = append(a.r.Inputs, Input{filepath.Base(path), int64(len(b)), hex.EncodeToString(sum[:]), "full_read"})
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "suite_commit=") {
			value := strings.TrimPrefix(line, "suite_commit=")
			raw, e := hex.DecodeString(value)
			if e == nil && len(raw) == 20 {
				a.r.SuiteCommit = value
			}
		}
		if strings.HasPrefix(line, "suite_dirty=") {
			v, e := strconv.ParseBool(strings.TrimPrefix(line, "suite_dirty="))
			if e == nil {
				a.r.SuiteDirty = &v
			}
		}
		fields := strings.Fields(line)
		if len(fields) == 2 {
			raw, e := hex.DecodeString(fields[0])
			if e == nil && len(raw) == 32 {
				a.r.BinaryDigests = append(a.r.BinaryDigests, fields[0])
			}
		}
	}
	if a.r.SuiteCommit == "" || a.r.SuiteDirty == nil || len(a.r.BinaryDigests) != 2 {
		a.finding("incomplete", "manifest_identity_incomplete")
	}
	if a.r.SuiteDirty != nil && *a.r.SuiteDirty {
		a.finding("incomplete", "suite_has_uncommitted_changes")
	}
}
