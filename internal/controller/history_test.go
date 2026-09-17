// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/model"
	"vpnctl/internal/statuspage"
)

func historyPtr[T any](v T) *T { return &v }
func submitHistory(t *testing.T, s *Server, req api.MetricsRequest, identity string) *httptest.ResponseRecorder {
	t.Helper()
	body, e := json.Marshal(req)
	if e != nil {
		t.Fatal(e)
	}
	rec := httptest.NewRecorder()
	s.requireClientCert(s.handleMetrics)(rec, requestWithNodeCertificate(t, "POST", "/metrics", body, identity))
	return rec
}
func historySamples(now time.Time) []history.Observation {
	var out []history.Observation
	for i := 0; i < 3; i++ {
		out = append(out, history.Observation{ID: fmt.Sprint(i), Timestamp: now.Add(time.Duration(i-3) * time.Second), PeerID: "node-b", Path: "relay", RelayID: "controller", Uplink: "wlan0", Success: historyPtr(true), RTTMs: historyPtr(float64(i * 10))})
	}
	return out
}
func TestFleetMeasurementAPIPageAndHistory(t *testing.T) {
	s := newIdentityTestServer(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	s.reg.Nodes[0].LastSeenAt = now
	s.reg.Nodes[1].LastSeenAt = now
	unknown := s.fleetSnapshot().Nodes[0]
	if unknown.Status != "online" || unknown.Quality != "unknown" || unknown.RTTMs != nil || unknown.LossPct != nil {
		t.Fatal(unknown)
	}
	req := api.MetricsRequest{NodeID: "node-a", Observations: historySamples(now)}
	for i := 0; i < 2; i++ {
		rec := submitHistory(t, s, req, "node-a")
		if rec.Code != 204 {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	s.requireClientCert(s.handleFleetStatus)(rec, requestWithNodeCertificate(t, "GET", "/fleet/status", nil, "node-a"))
	var resp api.FleetStatusResponse
	if e := json.Unmarshal(rec.Body.Bytes(), &resp); e != nil {
		t.Fatal(e)
	}
	if resp.SchemaVersion != 2 || len(resp.Nodes) != 2 {
		t.Fatal(resp)
	}
	m := resp.Nodes[0]
	if m.Quality != "good" || *m.RTTMs != 10 || *m.LossPct != 0 || m.Path != "relay" || m.Uplink != "wlan0" || m.SampleCount != 3 {
		t.Fatal(m)
	}
	page := s.statusPageData()
	if page.Nodes[0].RTTMs != "10.00" || page.Nodes[0].LossPct != "0.00" || page.Nodes[0].Quality != m.Quality || page.Nodes[1].RTTMs != "-" {
		t.Fatal(page)
	}
	html := httptest.NewRecorder()
	statuspage.Handler(s.statusPageData)(html, httptest.NewRequest("GET", "/status", nil))
	for _, text := range []string{"10.00", "0.00", "wlan0", "unknown", "Reported peer"} {
		if !strings.Contains(html.Body.String(), text) {
			t.Fatal("page missing", text)
		}
	}
	rec = httptest.NewRecorder()
	s.requireClientCert(s.handleFleetHistory)(rec, requestWithNodeCertificate(t, "GET", "/fleet/history?window=24h&node_id=node-a", nil, "node-a"))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var hist api.FleetHistoryResponse
	if e := json.Unmarshal(rec.Body.Bytes(), &hist); e != nil {
		t.Fatal(e)
	}
	if len(hist.Nodes) != 1 || len(hist.Nodes[0].Buckets) != 96 {
		t.Fatal(hist)
	}
	b := hist.Nodes[0].Buckets[95]
	if b.Count != 3 || *b.AvgRTTMs != 10 || *b.P95RTTMs != 20 || *b.AvailabilityPct != 100 {
		t.Fatal(b)
	}
	if hist.Nodes[0].Buckets[0].AvgRTTMs != nil {
		t.Fatal("gap is measured")
	}
	// An offline controller contact is independent of a recent measured path.
	s.reg.Nodes[0].LastSeenAt = now.Add(-time.Minute)
	if m = s.fleetSnapshot().Nodes[0]; m.Status != "offline" || m.Quality != "good" {
		t.Fatal(m)
	}
}
func TestHistoryAuthorizationAndUntrustedInputs(t *testing.T) {
	s := newIdentityTestServer(t)
	now := time.Now().UTC()
	samples := historySamples(now)
	for _, test := range []struct {
		name   string
		mutate func(*api.MetricsRequest)
		code   int
	}{
		{"identity", func(r *api.MetricsRequest) { r.NodeID = "node-b" }, 403},
		{"unknown peer", func(r *api.MetricsRequest) { r.Observations[0].PeerID = "stranger" }, 400},
		{"unknown relay", func(r *api.MetricsRequest) { r.Observations[0].RelayID = "stranger" }, 400},
		{"mixed format", func(r *api.MetricsRequest) { r.Samples = []model.Metric{{NodeID: "node-a", PeerID: "node-b"}} }, 400},
		{"future", func(r *api.MetricsRequest) { r.Observations[0].Timestamp = now.Add(time.Hour) }, 400},
		{"batch limit", func(r *api.MetricsRequest) { r.Observations = make([]history.Observation, 257) }, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := api.MetricsRequest{NodeID: "node-a", Observations: append([]history.Observation(nil), samples...)}
			test.mutate(&req)
			rec := submitHistory(t, s, req, "node-a")
			if rec.Code != test.code {
				t.Fatal(rec.Code, rec.Body.String())
			}
		})
	}
	if s.fleetSnapshot().Nodes[0].SampleCount != 0 {
		t.Fatal("invalid batch left metrics")
	}
	for _, q := range []string{"window=-1h", "window=169h", "window=garbage", "window=1h&bucket=1s", "window=7d&bucket=1m", "node_id=missing"} {
		rec := httptest.NewRecorder()
		s.handleFleetHistory(rec, httptest.NewRequest("GET", "/fleet/history?"+q, nil))
		if rec.Code < 400 {
			t.Fatal(q, rec.Code)
		}
	}
	legacy := api.MetricsRequest{NodeID: "node-a", Samples: []model.Metric{{NodeID: "node-a", PeerID: "node-b", Path: "relay"}}}
	rec := submitHistory(t, s, legacy, "node-a")
	if rec.Code != 204 || rec.Header().Get("Warning") == "" {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if s.fleetSnapshot().Nodes[0].Quality != "unknown" {
		t.Fatal("legacy zero became good")
	}
}

type blockedHistory struct {
	history.Storage
	started, release chan struct{}
}

func (b *blockedHistory) Query(ctx context.Context, node string, end time.Time, window, width time.Duration) ([]history.Bucket, error) {
	close(b.started)
	select {
	case <-b.release:
		return b.Storage.Query(ctx, node, end, window, width)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestHistoryQueryDoesNotBlockRevocationAndRechecksBeforePublishing(t *testing.T) {
	s := newIdentityTestServer(t)
	rec := submitHistory(t, s, api.MetricsRequest{NodeID: "node-a", Observations: historySamples(time.Now())}, "node-a")
	if rec.Code != 204 {
		t.Fatal(rec.Body.String())
	}
	blocked := &blockedHistory{Storage: s.history, started: make(chan struct{}), release: make(chan struct{})}
	s.history = blocked
	req := requestWithNodeCertificate(t, "GET", "/fleet/history", nil, "node-a")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.handleAuthorizedFleetHistory(response, req) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("query did not start")
	}
	changed := make(chan struct{})
	go func() {
		s.stateMu.Lock()
		s.mu.Lock()
		s.reg.RemovedNodes = map[string]time.Time{"node-a": time.Now()}
		s.reg.Nodes = s.reg.Nodes[1:]
		s.mu.Unlock()
		s.stateMu.Unlock()
		close(changed)
	}()
	select {
	case <-changed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("history query held security admission lock")
	}
	close(blocked.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("query did not finish")
	}
	if response.Code != 403 {
		t.Fatal("removed caller received history", response.Code, response.Body.String())
	}
}
