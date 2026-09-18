// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"vpnctl/internal/direct"

	"vpnctl/internal/api"
	"vpnctl/internal/controller"
	"vpnctl/internal/history"
	"vpnctl/internal/quality"
)

func fleetPtr[T any](v T) *T { return &v }
func TestFleetCLIUsesAPIValuesAndNulls(t *testing.T) {
	now := time.Now().UTC()
	m := history.Measurement{Stream: history.Stream{NodeID: "node-a", PeerID: "node-b", Path: "relay", RelayID: "controller", Uplink: "wlan0"}, PeerQuality: quality.PeerQuality{Quality: "good", RTTMs: fleetPtr(10.0), LossPct: fleetPtr(0.0), SampleCount: 3, ObservedAt: &now}}
	status := api.FleetStatusResponse{SchemaVersion: 2, Nodes: []api.FleetNodeStatus{{Measurement: m, Name: "node-a", Status: "online"}, {Name: "node-b", Measurement: history.Measurement{PeerQuality: quality.ReplayQuality(nil)}}}}
	hist := api.FleetHistoryResponse{SchemaVersion: 2, Nodes: []api.FleetNodeHistory{{NodeID: "node-a", Name: "node-a", Buckets: []history.Bucket{{Stream: m.Stream, Time: now, Count: 3, AvgRTTMs: fleetPtr(10.0), P95RTTMs: fleetPtr(20.0), AvailabilityPct: fleetPtr(100.0), LossPct: fleetPtr(0.0)}}}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fleet/status":
			json.NewEncoder(w).Encode(status)
		case "/fleet/history":
			if r.URL.Query().Get("node_id") != "node-a" || r.URL.Query().Get("bucket") != "15m" {
				t.Error(r.URL.String())
			}
			json.NewEncoder(w).Encode(hist)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "node.yaml")
	os.WriteFile(cfg, []byte(fmt.Sprintf("node:\n  name: node-a\n  controller: %q\n", srv.URL)), 0600)
	for _, test := range []struct {
		args []string
		want []string
	}{
		{[]string{"fleet", "status", "--config", cfg}, []string{"good", "10.00", "0.00", "wlan0", "unknown", "-"}},
		{[]string{"fleet", "status", "--config", cfg, "--json"}, []string{`"schema_version":2`, `"rtt_ms":10`, `"loss_pct":0`, `"rtt_ms":null`}},
		{[]string{"fleet", "history", "--config", cfg, "--window", "24h", "--node", "node-a", "--bucket", "15m"}, []string{"10.00", "20.00", "100.00", "wlan0"}},
	} {
		out, e := cliProcess(t, test.args...).CombinedOutput()
		if e != nil {
			t.Fatal(e, string(out))
		}
		for _, want := range test.want {
			if !strings.Contains(string(out), want) {
				t.Fatal("missing", want, string(out))
			}
		}
	}
}
func TestHistoryCLIBackupRestoreRequiresStoppedController(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "controller.yaml")
	os.WriteFile(cfg, []byte(fmt.Sprintf("controller:\n  data_dir: %q\n", dir)), 0600)
	now := time.Now().UTC()
	st, e := history.Open(filepath.Join(dir, "history.db"), now)
	if e != nil {
		t.Fatal(e)
	}
	sample := history.Observation{ID: "one", Timestamp: now, PeerID: "node-b", Path: "relay", Success: fleetPtr(true), RTTMs: fleetPtr(10.0)}
	if e = st.Ingest(context.Background(), "node-a", []history.Observation{sample}, now); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	lock, e := controller.AcquireStateLock(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = runControllerHistory([]string{"backup", "--config", cfg, "--out", backup}); e == nil {
		t.Fatal("backup ignored controller ownership")
	}
	lock.Close()
	if e = runControllerHistory([]string{"backup", "--config", cfg, "--out", backup}); e != nil {
		t.Fatal(e)
	}
	restored := t.TempDir()
	restoreCfg := filepath.Join(restored, "controller.yaml")
	os.WriteFile(restoreCfg, []byte(fmt.Sprintf("controller:\n  data_dir: %q\n", restored)), 0600)
	if e = runControllerHistory([]string{"restore", "--config", restoreCfg, "--file", backup}); e != nil {
		t.Fatal(e)
	}
	again, e := history.Open(filepath.Join(restored, "history.db"), now)
	if e != nil {
		t.Fatal(e)
	}
	if got := again.Latest(now)["node-a"]; len(got) != 1 || *got[0].RTTMs != 10 {
		t.Fatal(got)
	}
}

func TestPingSubmitsIndividualObservationsAndReportsUploadFailure(t *testing.T) {
	responder, e := direct.StartResponder("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer responder.Close()
	_, portString, e := net.SplitHostPort(responder.LocalAddr())
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(portString)
	received := make(chan api.MetricsRequest, 4)
	fail := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/candidates":
			json.NewEncoder(w).Encode(api.CandidatesResponse{Peers: []api.PeerCandidate{{ID: "node-b", Name: "node-b", VPNIP: "127.0.0.1/32", ProbePort: port}}})
		case "/metrics":
			var req api.MetricsRequest
			if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
				t.Error(e)
				http.Error(w, "decode", 400)
				return
			}
			received <- req
			if fail.Load() {
				http.Error(w, "storage unavailable", 503)
			} else {
				w.WriteHeader(204)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "node.yaml")
	os.WriteFile(cfg, []byte(fmt.Sprintf("node:\n  name: node-a\n  controller: %q\n", srv.URL)), 0600)
	args := []string{"ping", "--config", cfg, "--peer", "node-b", "--path", "relay", "--count", "3", "--interval", "100ms", "--timeout", "200ms"}
	out, e := cliProcess(t, args...).CombinedOutput()
	if e != nil {
		t.Fatal(e, string(out))
	}
	req := <-received
	if len(req.Samples) != 0 || len(req.Observations) != 3 || req.NodeID != "node-a" {
		t.Fatal(req)
	}
	ids := map[string]bool{}
	for _, o := range req.Observations {
		if o.Success == nil || !*o.Success || o.RTTMs == nil || ids[o.ID] || o.Path != "relay" {
			t.Fatal(o)
		}
		ids[o.ID] = true
	}
	fail.Store(true)
	out, e = cliProcess(t, args...).CombinedOutput()
	if e == nil || !strings.Contains(string(out), "submit probe observations") {
		t.Fatal("submission failure hidden", e, string(out))
	}
	<-received
	// A measured timeout is uploaded with null RTT, not a zero-latency success.
	fail.Store(false)
	responder.Close()
	out, e = cliProcess(t, args...).CombinedOutput()
	if e != nil {
		t.Fatal(e, string(out))
	}
	req = <-received
	for _, o := range req.Observations {
		if o.Success == nil || *o.Success || o.RTTMs != nil {
			t.Fatal(o)
		}
	}
}

func TestControllerEventCLIContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fleet/events" || r.URL.Query().Get("scope") != "controller" || r.URL.Query().Get("node_id") != "" {
			t.Error(r.URL.String())
		}
		json.NewEncoder(w).Encode(history.EventHistory{SchemaVersion: 1, Scope: "controller", Events: []history.Event{{Kind: "certificate", Current: "renew:success"}}})
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("node:\n  name: node-a\n  controller: %q\n", srv.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := cliProcess(t, "fleet", "events", "--config", cfg, "--controller", "--json").CombinedOutput()
	if err != nil || !strings.Contains(string(out), `"scope":"controller"`) || !strings.Contains(string(out), "renew:success") {
		t.Fatal(string(out), err)
	}
	for _, args := range [][]string{{"--config", cfg}, {"--config", cfg, "--controller", "--node", "node-a"}} {
		if err := runFleetEvents(args); err == nil {
			t.Fatal("ambiguous scope accepted", args)
		}
	}
}
