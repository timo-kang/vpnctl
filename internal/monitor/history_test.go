// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/direct"
	"vpnctl/internal/history"
	"vpnctl/internal/observation"
	"vpnctl/internal/peersource"
)

func mappedReporter(url string) (*HistoryReporter, peersource.Peer) {
	p := api.MonitorPeer{NodeID: "peer", PublicKey: "full-public-key", VPNIP: "127.0.0.1", Epoch: strings.Repeat("a", 32)}
	return &HistoryReporter{client: api.NewClient(url), node: "robot", queue: observation.New(), peers: map[string]api.MonitorPeer{p.PublicKey: p}, observed: time.Now()}, peersource.Peer{PublicKey: p.PublicKey, VPNIP: p.VPNIP, Name: "misleading-display-name"}
}
func waitHistory(t *testing.T, f func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("history convergence deadline")
}
func runDelivery(t *testing.T, h *HistoryReporter) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.queue.Run(ctx, func(context.Context, history.Observation) (bool, error) {
			t.Error("uncaptured binding")
			return false, errors.New("uncaptured")
		})
	}()
	return func() { cancel(); <-done }
}
func TestMonitorBindingRetryIsImmutableAndReadyPeerBypassesBackoff(t *testing.T) {
	var mu sync.Mutex
	var received []api.MonitorMetricsRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.MonitorMetricsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		mu.Lock()
		received = append(received, req)
		n := len(received)
		mu.Unlock()
		if n == 1 {
			http.Error(w, "response lost after commit", 503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	h, peer := mappedReporter(server.URL)
	send := h.bind(peer)
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	send(at, probeOutcome{success: true, rtt: 1234})
	// A refreshed catalog must not retag the already captured observation, even
	// when new ready work gets ahead of its delayed retry.
	p := h.peers[peer.PublicKey]
	p.NodeID = "replacement"
	p.Epoch = strings.Repeat("b", 32)
	h.peers[peer.PublicKey] = p
	h.bind(peer)(at.Add(time.Second), probeOutcome{unknown: true, reason: "discovery_failed"})
	stop := runDelivery(t, h)
	defer stop()
	waitHistory(t, func() bool { return h.queue.Stats().Delivered == 2 })
	mu.Lock()
	firstBatch := append([]api.MonitorMetricsRequest(nil), received...)
	mu.Unlock()
	if len(firstBatch) != 3 || !reflect.DeepEqual(firstBatch[0], firstBatch[2]) || firstBatch[1].Peer.NodeID != "replacement" {
		t.Fatal(firstBatch)
	}
	o := firstBatch[0].Observation
	if o.ID == "" || o.Source != "monitor-overlay" || o.Path != "unknown" || o.RelayID != "" || o.Uplink != "" || o.PeerID != "peer" || !o.Timestamp.Equal(at) || *o.RTTMs != 1.234 {
		t.Fatal(o)
	}
	if firstBatch[1].Observation.Success != nil || firstBatch[1].Observation.RTTMs != nil || firstBatch[1].Observation.Validity != "unknown" {
		t.Fatal(firstBatch[1])
	}
	restarted, _ := mappedReporter(server.URL)
	restarted.bind(peer)(at, probeOutcome{success: true})
	stop2 := runDelivery(t, restarted)
	defer stop2()
	waitHistory(t, func() bool { return restarted.queue.Stats().Delivered == 1 })
	mu.Lock()
	defer mu.Unlock()
	if received[3].Observation.ID == o.ID {
		t.Fatal("restart reused ID")
	}
}
func TestMonitorRealProbeSurvivesLocalStoreFailureAndLossyUI(t *testing.T) {
	var mu sync.Mutex
	var got []api.MonitorMetricsRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.MonitorMetricsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		got = append(got, req)
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer server.Close()
	h, peer := mappedReporter(server.URL)
	responder, err := direct.StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	peer.ProbePort = portOf(t, responder.LocalAddr())
	store, err := OpenStore(t.TempDir() + "/local.db")
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	m := newTestMonitor(t, Config{History: h, Source: &fakePeerSource{[]peersource.Peer{peer}}, Store: store})
	m.Subscribe() // Intentionally never consumed: all individual results survive.
	stop := runDelivery(t, h)
	defer stop()
	for i := 0; i < 4; i++ {
		m.probeAll(context.Background())
	}
	waitHistory(t, func() bool { return h.queue.Stats().Delivered == 4 })
	if s := m.Latest(); s.StorageError != "store_write_failed" || !s.Peers[0].Success {
		t.Fatal(s)
	}
	m.reportDiscoveryFailure("discovery_failed")
	peer.ProbePort = 0
	m.cfg.Source = &fakePeerSource{[]peersource.Peer{peer}}
	m.probeAll(context.Background())
	waitHistory(t, func() bool { return h.queue.Stats().Delivered == 6 })
	mu.Lock()
	defer mu.Unlock()
	ids := map[string]bool{}
	for i, r := range got {
		if ids[r.Observation.ID] {
			t.Fatal("duplicate measurement")
		}
		ids[r.Observation.ID] = true
		if i < 4 && (r.Observation.Success == nil || !*r.Observation.Success || r.Observation.RTTMs == nil) {
			t.Fatal(r)
		}
		if i >= 4 && (r.Observation.Success != nil || r.Observation.RTTMs != nil || r.Observation.Validity != "unknown") {
			t.Fatal(r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.probeAll(ctx)
	if h.queue.Stats().Delivered != 6 || h.queue.Stats().Pending != 0 {
		t.Fatal("shutdown invented a failure")
	}
}
func TestMonitorMappingFailureAndQueuePressureAreExplicit(t *testing.T) {
	h, p := mappedReporter("http://127.0.0.1:1")
	bad := p
	bad.PublicKey = "controller-server-key"
	if h.bind(bad) != nil || h.Status().LastMappingDrop != "peer_not_registered" {
		t.Fatal(h.Status())
	}
	bad = p
	bad.VPNIP = "127.0.0.2"
	if h.bind(bad) != nil || h.Status().LastMappingDrop != "peer_binding_mismatch" {
		t.Fatal(h.Status())
	}
	send := h.bind(p)
	for i := 0; i < observation.Capacity+10; i++ {
		send(time.Now(), probeOutcome{unknown: true, reason: "collector_unavailable"})
	}
	if s := h.Status(); s.Delivery.Pending != observation.Capacity || s.Delivery.Dropped != 10 || s.MappingDropped != 2 {
		t.Fatal(s)
	}
	h.refresh(context.Background())
	if h.bind(p) != nil || h.Status().MappingReady || h.Status().ErrorReason != "catalog_unavailable" {
		t.Fatal(h.Status())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.queue.Run(ctx, nil)
	if s := h.Status(); s.Delivery.Pending != 0 || s.Delivery.Dropped != observation.Capacity+10 {
		t.Fatal(s)
	}
	h.observed = time.Now().Add(-historyBindingTTL - time.Second)
	h.reason = ""
	if h.Status().ErrorReason != "catalog_stale" || h.bind(p) != nil {
		t.Fatal(h.Status())
	}
}
func TestMonitorInvalidCatalogFailsClosed(t *testing.T) {
	for _, kind := range []string{"duplicate-id", "duplicate-key", "duplicate-ip", "invalid-epoch", "self", "schema"} {
		t.Run(kind, func(t *testing.T) {
			h, p := mappedReporter("")
			a := h.peers[p.PublicKey]
			b := a
			b.NodeID = "other"
			b.PublicKey = "other-key"
			b.VPNIP = "127.0.0.2"
			schema := 1
			switch kind {
			case "duplicate-id":
				b.NodeID = a.NodeID
			case "duplicate-key":
				b.PublicKey = a.PublicKey
			case "duplicate-ip":
				b.VPNIP = a.VPNIP
			case "invalid-epoch":
				b.Epoch = strings.Repeat("z", 32)
			case "self":
				b.NodeID = h.node
			case "schema":
				schema = 2
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(api.MonitorPeersResponse{SchemaVersion: schema, Peers: []api.MonitorPeer{a, b}})
			}))
			defer server.Close()
			h.client = api.NewClient(server.URL)
			h.refresh(context.Background())
			if h.Status().MappingReady || h.bind(p) != nil {
				t.Fatal("ambiguous catalog remained usable", h.Status())
			}
		})
	}
}

func portOf(t *testing.T, address string) int {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	return a.Port
}

func TestMonitorCollectorErrorsAreUnknown(t *testing.T) {
	for _, err := range []error{syscall.EACCES, syscall.EPERM, syscall.EMFILE, syscall.ENFILE, syscall.EADDRNOTAVAIL, syscall.ENODEV, syscall.ENOBUFS, syscall.ENOMEM, syscall.EAFNOSUPPORT} {
		out := probeFailure(context.Background(), &net.OpError{Op: "dial", Net: "udp", Err: err})
		if !out.unknown || out.success || out.reason != "collector_unavailable" {
			t.Fatal(err, out)
		}
		q := (&qualityWindow{}).observe(time.Now(), out, QualityConfig{Window: time.Minute, MinSamples: 1, RecoverySamples: 1, StaleAfter: time.Minute})
		if q.SampleCount != 0 || q.RTTMs != nil || q.LossPct != nil || q.Quality != "unknown" {
			t.Fatal(q)
		}
	}
	if out := probeFailure(context.Background(), syscall.ECONNREFUSED); out.unknown || out.reason != "responder_unavailable" {
		t.Fatal(out)
	}
}

func TestMonitorHistoryOptInRejectsMissingOrAmbiguousCredentials(t *testing.T) {
	for _, url := range []string{"", "http://controller:8443", "https://user:password@controller", "https://controller?token=x", "https://controller#fragment"} {
		if _, err := NewHistoryReporter(url, "robot", t.TempDir()); err == nil {
			t.Fatal("ambiguous transport accepted", url)
		}
	}
	if _, err := NewHistoryReporter("https://controller", "robot", ""); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if _, err := NewHistoryReporter("https://controller", "robot", t.TempDir()); err == nil {
		t.Fatal("unprovisioned identity accepted")
	}
	if s := (*HistoryReporter)(nil).Status(); s.Enabled {
		t.Fatal("standalone monitor unexpectedly uploads")
	}
}

type stalledHistoryLog struct{ release <-chan struct{} }

func (s stalledHistoryLog) Write(b []byte) (int, error) { <-s.release; return len(b), nil }
func TestMonitorMappingErrorsCannotBlockOnDiagnosticSink(t *testing.T) {
	// A full journal pipe must not block cache invalidation, probe binding or
	// status readers. Keep this test sequential while replacing the global sink.
	release := make(chan struct{})
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(stalledHistoryLog{release}, nil)))
	defer slog.SetDefault(old)
	done := make(chan struct{})
	h, p := mappedReporter("http://127.0.0.1:1")
	go func() {
		defer close(done)
		p.PublicKey = "unregistered-server"
		h.bind(p)
		h.refresh(context.Background())
		_ = h.Status()
	}()
	select {
	case <-done:
		close(release)
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("diagnostic output blocked mapping/probe path")
	}
	if status := h.Status(); status.MappingDropped != 1 || status.ErrorReason != "catalog_unavailable" {
		t.Fatal("failure signal lost", status)
	}
}
