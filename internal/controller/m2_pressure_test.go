// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/labreport"
	"vpnctl/internal/pki"
	"vpnctl/internal/wgstats"
)

type pressurePopulation struct {
	Success int `json:"success"`
	Failure int `json:"failure"`
	Unknown int `json:"unknown"`
}
type pressureAttempt struct {
	Category string `json:"category"`
	ID       string `json:"id"`
	Result   string `json:"result"`
}
type pressureEvidence struct {
	ControlAttempts        []pressureControlAttempt                     `json:"control_attempts"`
	OmittedControlAttempts int                                          `json:"omitted_control_attempts"`
	Ledger                 []pressureAttempt                            `json:"request_ledger"`
	ObservedRows           map[string]int                               `json:"observed_retained_rows"`
	SchemaVersion          int                                          `json:"schema_version"`
	Profile                string                                       `json:"profile"`
	Completed              bool                                         `json:"completed"`
	WALBytes               int64                                        `json:"pinned_wal_bytes"`
	Attempts               map[string]int                               `json:"request_attempts"`
	Rejections             map[string]int                               `json:"backpressure_rejections"`
	UniqueAccepted         map[string]int                               `json:"unique_accepted_ids"`
	ExpectedProbes         map[string]pressurePopulation                `json:"expected_probe_population"`
	ObservedProbes         map[string]pressurePopulation                `json:"observed_probe_population"`
	Control                map[string]map[string]labreport.Distribution `json:"control_latency_ms"`
	Coverage               string                                       `json:"coverage"`
}

// This is a bounded authenticated API fixture, not a kernel producer soak or
// deployment SLO. Only the unrelated pressure BLOB bypasses public ingestion.
func TestM2MixedWALPressureAccounting(t *testing.T) {
	if os.Getenv("VPNCTL_M2_PRESSURE") != "1" {
		t.Skip("dedicated WAL pressure profile")
	}
	for _, tiered := range []bool{false, true} {
		t.Run(fmt.Sprintf("tiered_%t", tiered), func(t *testing.T) { testM2Pressure(t, tiered) })
	}
}
func testM2Pressure(t *testing.T, tiered bool) {
	s, h := lifecycleServer(t, "10m", "30m", "9m59s")
	s.cfg.ServerPublicKey = wireGuardTestKey(9)
	s.cfg.ServerEndpoint = "127.0.0.1:51820"
	s.cfg.ServerAllowedIPs = []string{"10.7.0.0/24"}
	st := s.history.(*history.Store)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base := time.Now().UTC().Truncate(time.Hour).Add(-2*time.Hour + time.Minute)
	if tiered {
		if e := st.EnableTiering(ctx, base.Add(-12*time.Hour)); e != nil {
			t.Fatal(e)
		}
		if e := st.EnableReclamation(ctx); e != nil {
			t.Fatal(e)
		}
		if e := st.EnableJitter(ctx); e != nil {
			t.Fatal(e)
		}
	}
	c, dir := lifecycleNode(t, s, h, "robot")
	peer, _ := lifecycleNode(t, s, h, "peer")
	monitorRegister(t, c, "robot", wireGuardTestKey(1))
	monitorRegister(t, peer, "peer", wireGuardTestKey(2))
	catalog, e := c.MonitorPeers(ctx, "robot")
	if e != nil {
		t.Fatal(e)
	}
	ev := pressureEvidence{SchemaVersion: 1, Profile: fmt.Sprintf("mTLS mixed API / tiered=%t / pinned WAL", tiered), Attempts: map[string]int{}, Rejections: map[string]int{}, UniqueAccepted: map[string]int{}, ExpectedProbes: map[string]pressurePopulation{}, ObservedProbes: map[string]pressurePopulation{}, Control: map[string]map[string]labreport.Distribution{}, ObservedRows: map[string]int{}, Coverage: "scripted IDs only; no reclamation/expiry/kernel producer or 24h qualification"}
	// Store only public fixture summaries; no credentials, URLs or local paths.
	defer func() {
		if root := os.Getenv("VPNCTL_M2_PRESSURE_ARTIFACT_DIR"); root != "" {
			if e := os.MkdirAll(root, 0700); e != nil {
				t.Error(e)
				return
			}
			ev.Completed = ev.Completed && !t.Failed()
			b, e := json.MarshalIndent(ev, "", "  ")
			if e != nil {
				t.Error(e)
				return
			}
			if e = os.WriteFile(filepath.Join(root, fmt.Sprintf("pressure-tiered-%t.json", tiered)), b, 0600); e != nil {
				t.Error(e)
			}
		}
	}()
	accepted := map[string]map[string]bool{}
	record := func(kind, id string, err error, reject bool) {
		t.Helper()
		ev.Attempts[kind]++
		if reject {
			var response *api.HTTPError
			if !errors.As(err, &response) || response.StatusCode != 503 || response.Code == api.CodeHistoryQuota {
				t.Fatalf("%s: expected transient WAL rejection, got %v", kind, err)
			}
			ev.Rejections[kind]++
			ev.Ledger = append(ev.Ledger, pressureAttempt{kind, id, "transient_rejected"})
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if accepted[kind] == nil {
			accepted[kind] = map[string]bool{}
		}
		result := "duplicate_accepted"
		if !accepted[kind][id] {
			result = "new_accepted"
			accepted[kind][id] = true
			ev.UniqueAccepted[kind]++
		}
		ev.Ledger = append(ev.Ledger, pressureAttempt{kind, id, result})
	}
	// Explicit immutable input IDs permit independent dedup/population accounting.
	send := func(round int, reject bool) {
		t.Helper()
		at := base.Add(time.Duration(round) * time.Minute)
		for _, source := range []string{"agent-direct", "monitor-overlay"} {
			for outcome := 0; outcome < 3; outcome++ {
				id := fmt.Sprintf("m2-%d-%d", round, outcome)
				o := history.Observation{ID: id, Timestamp: at.Add(time.Duration(outcome) * time.Second), PeerID: "peer", Source: source, Path: "direct", Success: historyPtr(true), RTTMs: historyPtr(3.)}
				if source == "monitor-overlay" {
					o.Path = "unknown"
				}
				if outcome == 1 {
					o.Success = historyPtr(false)
					o.RTTMs = nil
					o.Reason = "probe_timeout"
				}
				if outcome == 2 {
					o.Success = nil
					o.RTTMs = nil
					o.Validity = "unknown"
					o.Reason = "collector_unavailable"
				}
				callCtx, stop := context.WithTimeout(ctx, 3*time.Second)
				var err error
				if source == "agent-direct" {
					err = c.SubmitMetrics(callCtx, api.MetricsRequest{NodeID: "robot", Observations: []history.Observation{o}})
				} else {
					err = c.SubmitMonitorMetrics(callCtx, api.MonitorMetricsRequest{NodeID: "robot", Peer: catalog.Peers[0], Observation: o})
				}
				stop()
				fresh := !accepted[source][id]
				record(source, id, err, reject)
				if !reject && fresh {
					p := ev.ExpectedProbes[source]
					switch outcome {
					case 0:
						p.Success++
					case 1:
						p.Failure++
					case 2:
						p.Unknown++
					}
					ev.ExpectedProbes[source] = p
				}
			}
		}
		id := fmt.Sprintf("m2-round-%d", round)
		count := wgstats.Counter(100 + round)
		wg := wgstats.Report{ID: fmt.Sprintf("%032x", round+1), ObservedAt: at, Reporter: catalog.Self, Interface: "wg0", Peers: []wgstats.Reading{{Peer: catalog.Peers[0], Sample: wgstats.Sample{ObservedAt: at, Generation: strings.Repeat("a", 32), Validity: "observed", RX: &count, TX: &count}}}}
		call := func(kind, recordID string, fn func(context.Context) error) {
			t.Helper()
			work, stop := context.WithTimeout(ctx, 3*time.Second)
			err := fn(work)
			stop()
			record(kind, recordID, err, reject)
		}
		call("wireguard", wg.ID, func(ctx context.Context) error { return c.SubmitWireGuard(ctx, wg) })
		u := controllerUplinkFixture()
		u.ID = id
		u.At = at
		call("uplink", id, func(ctx context.Context) error {
			return c.SubmitUplink(ctx, api.UplinkRequest{NodeID: "robot", Snapshot: u})
		})
		event := history.Event{ID: id, Timestamp: at, Kind: "probe_error", Source: "m2-fixture", Severity: "warning", Validity: "observed", Message: "fixture input"}
		call("event", id, func(ctx context.Context) error {
			return c.SubmitEvent(ctx, api.EventRequest{NodeID: "robot", Event: event})
		})
	}
	verify := func() {
		t.Helper()
		got := map[string]pressurePopulation{}
		cursor := ""
		seen := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 100 || seen[cursor] {
				t.Fatal("non-terminating cursor")
			}
			seen[cursor] = true
			r, e := c.FleetHistoryPage(ctx, "24h", "robot", "1h", "", cursor)
			if e != nil {
				t.Fatal(e)
			}
			for _, node := range r.Nodes {
				for _, b := range node.Buckets {
					p := got[b.Source]
					p.Success += b.Successes
					p.Failure += b.Count - b.Successes
					p.Unknown += b.UnknownCount
					got[b.Source] = p
				}
			}
			if r.Tiering == nil || r.Tiering.NextCursor == "" {
				break
			}
			cursor = r.Tiering.NextCursor
		}
		if !reflect.DeepEqual(got, ev.ExpectedProbes) {
			t.Fatal("probe population mismatch", got, ev.ExpectedProbes)
		}
		ev.ObservedProbes = got
		wg, e := c.FleetWireGuard(ctx, "robot", "24h", 100)
		if e != nil || len(wg.Snapshots) != ev.UniqueAccepted["wireguard"] {
			t.Fatal("WG population", len(wg.Snapshots), e)
		}
		seenWG := map[string]bool{}
		for _, snapshot := range wg.Snapshots {
			if !accepted["wireguard"][snapshot.ID] || seenWG[snapshot.ID] {
				t.Fatal("unexpected WG ID", snapshot.ID)
			}
			seenWG[snapshot.ID] = true
		}
		ev.ObservedRows["wireguard"] = len(wg.Snapshots)
		ul, e := c.FleetUplinks(ctx, "robot", "24h", 100)
		if e != nil || len(ul.Snapshots) != ev.UniqueAccepted["uplink"] {
			t.Fatal("uplink population", len(ul.Snapshots), e)
		}
		seenUL := map[string]bool{}
		for _, snapshot := range ul.Snapshots {
			if !accepted["uplink"][snapshot.ID] || seenUL[snapshot.ID] {
				t.Fatal("unexpected uplink ID", snapshot.ID)
			}
			seenUL[snapshot.ID] = true
		}
		ev.ObservedRows["uplink"] = len(ul.Snapshots)
		events, e := c.FleetEvents(ctx, "robot", "24h", 1000)
		if e != nil || events.Truncated {
			t.Fatal("event coverage", e)
		}
		seenEvents := map[string]bool{}
		count := 0
		for _, event := range events.Events {
			if event.Source == "m2-fixture" {
				count++
				if !accepted["event"][event.ID] || seenEvents[event.ID] {
					t.Fatal("unexpected retained event", event.ID)
				}
				seenEvents[event.ID] = true
			}
		}
		if count != ev.UniqueAccepted["event"] {
			t.Fatal("event population", count)
		}
		ev.ObservedRows["event"] = count
		for source, p := range got {
			ev.ObservedRows[source] = p.Success + p.Failure + p.Unknown
		}
	}
	send(0, false)
	send(0, false)
	verify()
	// Pin a real read transaction, then exceed the production 64MiB WAL watermark.
	u := url.URL{Scheme: "file", Path: filepath.Join(s.cfg.DataDir, "history.db")}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(1000)")
	q.Add("_pragma", "wal_autocheckpoint(0)")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.ExecContext(ctx, "CREATE TABLE m2_pressure(data BLOB)"); e != nil {
		t.Fatal(e)
	}
	readDB, e := sql.Open("sqlite", u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer readDB.Close()
	pinned, e := readDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	defer pinned.Rollback()
	var rows int
	if e = pinned.QueryRowContext(ctx, "SELECT count(*) FROM probes").Scan(&rows); e != nil {
		t.Fatal(e)
	}
	// Baseline uses the same control operations as the pressure phase.
	pulse := func(parent context.Context, phase string, values map[string][]float64, renew bool) error {
		// Wait for the fixture's real renewal window; exclude this scheduling
		// delay from RPC latency, without bypassing the authority policy.
		if renew {
			select {
			case <-parent.Done():
				return nil
			case <-time.After(1050 * time.Millisecond):
			}
		}
		ops := []struct {
			name string
			call func(context.Context) error
		}{
			{"heartbeat", func(ctx context.Context) error {
				_, e := c.Register(ctx, api.RegisterRequest{Name: "robot", PubKey: wireGuardTestKey(1), DirectMode: "off"})
				return e
			}},
			{"candidates", func(ctx context.Context) error { _, e := c.Candidates(ctx, "robot"); return e }},
			{"wg_config", func(ctx context.Context) error { _, e := c.WGConfig(ctx, "robot"); return e }},
			{"storage", func(ctx context.Context) error { _, e := c.FleetStorage(ctx); return e }},
			{"history_page", func(ctx context.Context) error {
				_, e := c.FleetHistoryPage(ctx, "24h", "robot", "1h", "", "")
				return e
			}},
		}
		if renew {
			ops = append(ops, struct {
				name string
				call func(context.Context) error
			}{"renew_install_ack", func(ctx context.Context) error {
				before, e := pki.LoadCredentials(dir)
				if e != nil {
					return e
				}
				if e = c.SyncCredentials(ctx, dir, "robot"); e != nil {
					return e
				}
				after, e := pki.LoadCredentials(dir)
				if e != nil {
					return e
				}
				if before.ClientCert == after.ClientCert {
					return fmt.Errorf("renewal did not install a new certificate")
				}
				return nil
			}})
		}
		for _, op := range ops {
			work, stop := context.WithTimeout(parent, 2*time.Second)
			started := time.Now()
			work, trace := tracePressureRequest(work, started)
			err := op.call(work)
			elapsed := time.Since(started)
			stop()
			ev.recordControl(values, trace.finish(phase, op.name, elapsed, err, parent.Err() != nil))
			if parent.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("%s: %w", op.name, err)
			}
			if elapsed > 2*time.Second {
				return fmt.Errorf("%s exceeded 2s", op.name)
			}
		}
		return nil
	}
	baseline := map[string][]float64{}
	for i := 0; i < 3; i++ {
		if e = pulse(ctx, "baseline", baseline, true); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.ExecContext(ctx, "INSERT INTO m2_pressure VALUES(zeroblob(68157440))"); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(s.cfg.DataDir, "history.db-wal"))
	if e != nil {
		t.Fatal(e)
	}
	ev.WALBytes = info.Size()
	if ev.WALBytes <= 64<<20 {
		t.Fatal("WAL watermark not reached")
	}
	// Fresh collection must still be readable despite the pinned WAL.
	if e = st.RefreshStorageHealth(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if health, e := c.FleetStorage(ctx); e != nil || health.Values == nil || health.Values.WALBytes <= 64<<20 {
		t.Fatal("pressure not observable", health, e)
	}
	pressure := map[string][]float64{}
	controlCtx, stopControl := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			if err := pulse(controlCtx, "pressure", pressure, i%4 == 0); err != nil {
				done <- err
				return
			}
			select {
			case <-controlCtx.Done():
				done <- nil
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}()
	joined := false
	defer func() {
		stopControl()
		if !joined {
			<-done
		}
	}()
	// Every category is rejected while the pin is held. No successful ACK or
	// write rollback may be counted as a new retained observation.
	send(1, true)
	send(1, true)
	stopControl()
	e = <-done
	joined = true
	if e != nil {
		t.Fatal(e)
	}
	if len(pressure["renew_install_ack"]) == 0 {
		t.Fatal("no renewal under pressure")
	}
	verify() // Rejected writes must remain absent before retries.
	if e = pinned.Rollback(); e != nil {
		t.Fatal(e)
	}
	send(1, false)
	send(1, false)
	send(2, false)
	recovery := map[string][]float64{}
	if e = pulse(ctx, "recovery", recovery, true); e != nil {
		t.Fatal(e)
	}
	// Confirm both raw and actual compacted views against independent inputs.

	verify()
	if tiered {
		if e = st.Maintain(ctx, time.Now().Add(6*time.Hour)); e != nil {
			t.Fatal(e)
		}
		verify()
	}

	if _, e = db.ExecContext(ctx, "DROP TABLE m2_pressure"); e != nil {
		t.Fatal(e)
	}
	if e = history.Check(ctx, filepath.Join(s.cfg.DataDir, "history.db")); e != nil {
		t.Fatal(e)
	}
	ev.Completed = true
	t.Logf("tiered=%t WAL=%d unique=%v rejected=%v control=%v", tiered, ev.WALBytes, ev.UniqueAccepted, ev.Rejections, ev.Control)
}
