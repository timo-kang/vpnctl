// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/history"
	"vpnctl/internal/observation"
)

func TestActualDirectOutcomesReachHistoryDespiteControlReportFailure(t *testing.T) {
	store, err := history.Open(t.TempDir()+"/history.db", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan history.Observation, 8)
	var reports atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/direct-result" {
			reports.Add(1)
			w.WriteHeader(503)
			return
		}
		if r.URL.Path != "/metrics" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		var req api.MetricsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if len(req.Samples) != 0 || len(req.Observations) != 1 {
			t.Error("legacy or duplicate producer", req)
			w.WriteHeader(400)
			return
		}
		if err := store.Ingest(r.Context(), req.NodeID, req.Observations, time.Now()); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		received <- req.Observations[0]
		w.WriteHeader(204)
	}))
	defer server.Close()
	remote, err := direct.StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	address, _ := net.ResolveUDPAddr("udp", remote.LocalAddr())
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	silentAddr := silent.LocalAddr().(*net.UDPAddr)
	shared, err := direct.ListenShared("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	cfg := config.NodeConfig{Name: "robot", Controller: server.URL}
	var supervisor ProbeHistorySupervisor
	ctx := supervisor.Configure(context.Background(), cfg)
	defer supervisor.Stop()
	client := api.NewClient(server.URL)
	defer client.CloseIdleConnections()
	peers := []api.PeerCandidate{{ID: "success", PublicAddr: remote.LocalAddr(), ProbePort: address.Port}, {ID: "failure", PublicAddr: silent.LocalAddr().String(), ProbePort: silentAddr.Port}, {ID: "unknown", PublicAddr: "127.0.0.1", ProbePort: 70000}}
	measureDirect(ctx, client, cfg, "robot", shared, directSnapshot{}, peers)
	got := map[string]history.Observation{}
	for len(got) < 3 {
		select {
		case o := <-received:
			got[o.PeerID] = o
		case <-time.After(3 * time.Second):
			t.Fatal("missing raw outcomes", got)
		}
	}
	if o := got["success"]; o.Success == nil || !*o.Success || o.RTTMs == nil || o.Source != "agent-direct" {
		t.Fatal(o)
	}
	if o := got["failure"]; o.Success == nil || *o.Success || o.RTTMs != nil || o.Reason != "probe_timeout" {
		t.Fatal(o)
	}
	if o := got["unknown"]; o.Success != nil || o.RTTMs != nil || o.Validity != "unknown" || o.Reason != "invalid_probe_target" {
		t.Fatal(o)
	}
	if reports.Load() != 2 {
		t.Fatal("unattempted outcome changed direct readiness", reports.Load())
	}
	bs, err := store.Query(context.Background(), "robot", time.Now(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	attempts, successes, unknown := 0, 0, 0
	for _, b := range bs {
		attempts += b.Count
		successes += b.Successes
		unknown += b.UnknownCount
	}
	if attempts != 2 || successes != 1 || unknown != 1 {
		t.Fatal(bs)
	}
	// A session retry retains queued observations; a new identity gets a new queue.
	before := observation.FromContext(ctx)
	ctx = supervisor.Configure(ctx, cfg)
	if observation.FromContext(ctx) != before {
		t.Fatal("session retry replaced queue")
	}
	cfg.Name = "replacement"
	ctx = supervisor.Configure(ctx, cfg)
	if observation.FromContext(ctx) == before {
		t.Fatal("identity changed without replacing queue")
	}
}

func TestProbeHistoryRetriesExactRequestAfterStorageOutage(t *testing.T) {
	var calls atomic.Int32
	done := make(chan struct{})
	var first api.MetricsRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.MetricsRequest
		json.NewDecoder(r.Body).Decode(&req)
		if calls.Add(1) == 1 {
			first = req
			w.WriteHeader(503)
			return
		}
		if !reflect.DeepEqual(first, req) {
			t.Error("retry rewrote raw sample")
		}
		w.WriteHeader(204)
		close(done)
	}))
	defer server.Close()
	var supervisor ProbeHistorySupervisor
	ctx := supervisor.Configure(context.Background(), config.NodeConfig{Name: "robot", Controller: server.URL})
	defer supervisor.Stop()
	observation.Emit(ctx, unknownDirect("peer", "collector_unavailable"))
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("retry not delivered")
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}

func TestDirectCollectorContentionIsUnknownNotPacketLoss(t *testing.T) {
	// Cancellation before a datagram was sent is explicitly preserved by Shared.
	shared, err := direct.ListenShared("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	rtt, err := shared.ProbePeer(ctx, "127.0.0.1:9191", time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	o := directObservation("peer", rtt, err)
	if o.Success != nil || o.Validity != "unknown" || o.Reason != "collector_unavailable" {
		t.Fatal(o)
	}
	// Superseded work emits nothing and never changes readiness.
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	var supervisor ProbeHistorySupervisor
	qctx := supervisor.Configure(context.Background(), config.NodeConfig{Name: "robot", Controller: server.URL})
	defer supervisor.Stop()
	canceled, stop := context.WithCancel(qctx)
	stop()
	client := api.NewClient(server.URL)
	defer client.CloseIdleConnections()
	measureDirect(canceled, client, config.NodeConfig{}, "robot", shared, directSnapshot{}, []api.PeerCandidate{{ID: "peer", PublicAddr: "127.0.0.1", ProbePort: 9191}})
	if requests.Load() != 0 {
		t.Fatal("shutdown created failure sample")
	}
}

func TestCollectorFailureKeepsConservativeReadinessInvalidation(t *testing.T) {
	reports := make(chan api.DirectResultRequest, 1)
	samples := make(chan history.Observation, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/direct-result" {
			var req api.DirectResultRequest
			json.NewDecoder(r.Body).Decode(&req)
			reports <- req
		} else {
			var req api.MetricsRequest
			json.NewDecoder(r.Body).Decode(&req)
			samples <- req.Observations[0]
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	shared, err := direct.ListenShared("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	shared.Close()
	cfg := config.NodeConfig{Name: "robot", Controller: server.URL}
	var supervisor ProbeHistorySupervisor
	ctx := supervisor.Configure(context.Background(), cfg)
	defer supervisor.Stop()
	client := api.NewClient(server.URL)
	defer client.CloseIdleConnections()
	measureDirect(ctx, client, cfg, "robot", shared, directSnapshot{}, []api.PeerCandidate{{ID: "peer", PublicAddr: "127.0.0.1", ProbePort: 9191}})
	select {
	case r := <-reports:
		if r.Success {
			t.Fatal("local failure retained readiness")
		}
	case <-time.After(time.Second):
		t.Fatal("history change suppressed readiness invalidation")
	}
	select {
	case o := <-samples:
		if o.Success != nil || o.Validity != "unknown" || o.Reason != "collector_unavailable" {
			t.Fatal("local failure counted as packet loss", o)
		}
	case <-time.After(time.Second):
		t.Fatal("collector failure not recorded")
	}
}
