// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
	"vpnctl/internal/statuspage"
)

func TestPathChurnMTLSLostResponseAndClientRestart(t *testing.T) {
	s, _ := lifecycleServer(t, "10m", "30m")
	s.cfg.ServerPublicKey = "server-public-key"
	s.cfg.ServerEndpoint = "127.0.0.1:51820"
	s.cfg.ServerAllowedIPs = []string{"10.7.0.0/24"}
	st := s.history.(*history.Store)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Hour)
	if err := st.EnableTiering(ctx, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableReclamation(ctx); err != nil {
		t.Fatal(err)
	}
	inner := s.httpHandler()
	var drop atomic.Bool
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" && drop.CompareAndSwap(true, false) {
			recorded := httptest.NewRecorder()
			inner.ServeHTTP(recorded, r)
			if recorded.Code != http.StatusNoContent {
				t.Errorf("request failed before response loss: %d %s", recorded.Code, recorded.Body.String())
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				connection.Close()
			}
			return
		}
		inner.ServeHTTP(w, r)
	}))
	h.TLS = s.authority.DynamicTLSConfig()
	h.StartTLS()
	defer h.Close()
	c, dir := lifecycleNode(t, s, h, "robot")
	var batch []history.Observation
	for peer := 0; peer < 2; peer++ {
		lifecycleNode(t, s, h, fmt.Sprintf("peer-%02d", peer))
		for _, source := range []string{"agent-direct", "monitor-overlay"} {
			for gen := 0; gen < 64; gen++ {
				batch = append(batch, history.Observation{ID: "old", Timestamp: now.Add(-24 * time.Hour), PeerID: fmt.Sprintf("peer-%02d", peer), Source: source, Path: "direct", Uplink: fmt.Sprintf("uplink-%d", gen), Success: historyPtr(true), RTTMs: historyPtr(1.)})
			}
		}
	}
	if err := c.SubmitMetrics(ctx, api.MetricsRequest{NodeID: "robot", Observations: batch}); err != nil {
		t.Fatal(err)
	}
	if err := st.Maintain(ctx, now); err != nil {
		t.Fatal(err)
	}
	before, err := c.FleetHistoryPage(ctx, "48h", "robot", "1h", "", "")
	if err != nil || before.SchemaVersion != 4 || before.Tiering.Coverage.Partial || before.Tiering.NextCursor == "" {
		t.Fatal(before, err)
	}
	next := batch[0]
	next.ID, next.Timestamp, next.Uplink = "new", now, "new-path"
	drop.Store(true)
	request := api.MetricsRequest{NodeID: "robot", Observations: []history.Observation{next}}
	if err = c.SubmitMetrics(ctx, request); err == nil {
		t.Fatal("lost response appeared successful")
	}
	stats, err := st.TieredStats(ctx)
	if err != nil || stats.ReclaimedSamples != 1 || stats.RawRows != 1 {
		t.Fatal("loss did not happen after commit", stats, err)
	}
	c.CloseIdleConnections()
	restarted := api.NewCredentialClient(h.URL, dir)
	defer restarted.CloseIdleConnections()
	if err = restarted.SubmitMetrics(ctx, request); err != nil {
		t.Fatal(err)
	}
	stats, err = st.TieredStats(ctx)
	if err != nil || stats.ReclaimedStreams != 1 || stats.RawRows != 1 {
		t.Fatal("client restart duplicated admission", stats, err)
	}
	_, err = restarted.FleetHistoryPage(ctx, "48h", "robot", "1h", "", before.Tiering.NextCursor)
	var response *api.HTTPError
	if !errors.As(err, &response) || response.StatusCode != 400 {
		t.Fatal("stale history cursor accepted", err)
	}
	page, err := restarted.FleetHistoryPage(ctx, "48h", "robot", "1h", "agent-direct", "")
	if err != nil || page.SchemaVersion != 4 || !page.Tiering.Coverage.Partial || page.Tiering.Coverage.DiscardedSamples != 1 {
		t.Fatal(page, err)
	}
	page, err = restarted.FleetHistoryPage(ctx, "48h", "robot", "1h", "monitor-overlay", "")
	if err != nil || page.Tiering.Coverage.Partial {
		t.Fatal("other source marked lost", page, err)
	}
	status := httptest.NewRecorder()
	statuspage.Handler(s.statusPageData)(status, httptest.NewRequest(http.MethodGet, "/status", nil))
	if !strings.Contains(status.Body.String(), "older archived paths may be reclaimed") {
		t.Fatal("policy hidden in HTML")
	}
	// Keep real reclamation requests in flight while exercising authenticated
	// heartbeat, route discovery, config, status and credential synchronization.
	burstCtx, cancelBurst := context.WithCancel(ctx)
	defer cancelBurst()
	burstDone := make(chan struct{})
	var burstErr error
	go func() {
		defer close(burstDone)
		for i := 0; i < 64; i++ {
			o := next
			o.Uplink = fmt.Sprintf("burst-%d", i)
			if err := restarted.SubmitMetrics(burstCtx, api.MetricsRequest{NodeID: "robot", Observations: []history.Observation{o}}); err != nil {
				burstErr = err
				return
			}
		}
	}()
	defer func() { cancelBurst(); <-burstDone }()
	control := api.NewCredentialClient(h.URL, dir)
	defer control.CloseIdleConnections()
	checks := []struct {
		name string
		call func(context.Context) error
	}{
		{"heartbeat", func(ctx context.Context) error {
			_, err := control.Register(ctx, api.RegisterRequest{Name: "robot", PubKey: "pub-robot"})
			return err
		}},
		{"candidates", func(ctx context.Context) error { _, err := control.Candidates(ctx, "robot"); return err }},
		{"wgconfig", func(ctx context.Context) error { _, err := control.WGConfig(ctx, "robot"); return err }},
		{"status", func(ctx context.Context) error { _, err := control.FleetStatus(ctx); return err }},
		{"credentials", func(ctx context.Context) error { return control.SyncCredentials(ctx, dir, "robot") }},
	}
	for round := 0; round < 8; round++ {
		for _, check := range checks {
			controlCtx, cancel := context.WithTimeout(ctx, time.Second)
			began := time.Now()
			err := check.call(controlCtx)
			cancel()
			if err != nil || time.Since(began) > time.Second {
				t.Fatalf("control %s during churn: %v (%s)", check.name, err, time.Since(began))
			}
		}
	}
	<-burstDone
	if burstErr != nil {
		t.Fatal(burstErr)
	}
	stats, err = st.TieredStats(ctx)
	if err != nil || stats.ReclaimedStreams != 65 || stats.RawRows != 65 {
		t.Fatal("burst was not committed exactly once", stats, err)
	}
	creds, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(creds.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.authority.Revoke(certificateFingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	_, err = restarted.FleetHistoryPage(ctx, "48h", "robot", "1h", "", "")
	if !errors.As(err, &response) || response.StatusCode != 403 {
		t.Fatal("revoked certificate read reclaimed history", err)
	}
}
