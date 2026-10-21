// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/modemsignal"
	"vpnctl/internal/uplink"
)

func controllerUplinkFixture() uplink.Snapshot {
	return uplink.Snapshot{ID: "first", At: time.Now().Add(-time.Second), IntervalSec: 60, Underlay: uplink.Up(), Links: []uplink.Link{{ID: "lan", Interface: "eth0", Kind: "ethernet", Check: uplink.Up(), Modem: uplink.Unknown("not_configured"), GatewayState: uplink.Unknown("not_configured"), DNS: uplink.Unknown("not_configured"), Controller: uplink.Up(), ControllerRoute: uplink.Route{Check: uplink.Up(), Interface: "eth0"}}}, Targets: []uplink.Target{{TransportRoute: uplink.Route{Check: uplink.Unknown("not_observed")}, ID: "server", Protocol: "tcp", Route: uplink.Route{Check: uplink.Up(), Interface: "wg0"}, Relay: uplink.Up(), Service: uplink.Check{State: "up", RTTMs: historyPtr(3.)}, FailureStage: "none"}}}
}
func TestUplinkIdentityAndSeparateTargetHistory(t *testing.T) {
	s := newIdentityTestServer(t)
	v := controllerUplinkFixture()
	v.Targets[0].ServiceStartedAt = historyPtr(v.At.Add(-2 * time.Second))
	v.Targets[0].ServiceCompletedAt = historyPtr(v.At.Add(-time.Second))
	v.Links[0].Kind = "lte"
	signal := modemsignal.Parse("modem.signal.lte.snr : 0\nmodem.signal.lte.rsrq : --", v.At.Add(-time.Second))
	v.Links[0].ModemSignals = &signal
	for _, tc := range []struct {
		node, identity string
		code           int
	}{{"node-a", "node-b", 403}, {"node-a", "node-a", 204}, {"node-a", "node-a", 204}, {"unregistered", "node-a", 403}} {
		body, _ := json.Marshal(api.UplinkRequest{NodeID: tc.node, Snapshot: v})
		rec := httptest.NewRecorder()
		s.requireClientCert(s.handleUplinkObservation)(rec, requestWithNodeCertificate(t, "POST", "/uplink-observations", body, tc.identity))
		if rec.Code != tc.code {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	fleet := s.fleetSnapshot()
	if fleet.Nodes[0].UplinkObservation == nil || fleet.Nodes[0].Quality != "unknown" || len(fleet.Nodes[0].Measurements) != 0 {
		t.Fatal("target polluted peer quality", fleet)
	}
	rec := httptest.NewRecorder()
	s.handleAuthorizedUplinks(rec, requestWithNodeCertificate(t, "GET", "/fleet/uplinks?node_id=node-a", nil, "node-a"))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var out history.UplinkHistory
	if e := json.Unmarshal(rec.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out.Summaries[0].Samples != 1 || out.Summaries[0].TargetID != "server" {
		t.Fatal(out)
	}
	if len(out.Snapshots) != 1 || out.Snapshots[0].Links[0].ModemSignals == nil || out.Snapshots[0].Links[0].ModemSignals.LTE.SNR.Value == nil || *out.Snapshots[0].Links[0].ModemSignals.LTE.SNR.Value != 0 || out.Snapshots[0].Links[0].ModemSignals.LTE.RSRQ.Value != nil || out.Snapshots[0].Links[0].ModemSignals.MeasurementTime != "unavailable" {
		t.Fatal("authenticated API lost RF evidence", out)
	}
	if len(out.Snapshots) != 1 || out.Snapshots[0].Targets[0].ServiceStartedAt == nil ||
		!out.Snapshots[0].Targets[0].ServiceStartedAt.Equal(v.Targets[0].ServiceStartedAt.Truncate(time.Microsecond)) ||
		out.Snapshots[0].Targets[0].ServiceCompletedAt == nil ||
		!out.Snapshots[0].Targets[0].ServiceCompletedAt.Equal(v.Targets[0].ServiceCompletedAt.Truncate(time.Microsecond)) {
		t.Fatal("authenticated history lost service timing", out)
	}
	rec = httptest.NewRecorder()
	s.handleAuthorizedUplinks(rec, httptest.NewRequest("GET", "/fleet/uplinks?node_id=node-a", nil))
	if rec.Code != 401 {
		t.Fatal("anonymous history", rec.Code)
	}
}

type blockedUplinks struct {
	*history.Store
	started, release chan struct{}
}

func (b *blockedUplinks) QueryUplinks(ctx context.Context, node string, end time.Time, window time.Duration, limit int) (history.UplinkHistory, error) {
	close(b.started)
	select {
	case <-b.release:
		return b.Store.QueryUplinks(ctx, node, end, window, limit)
	case <-ctx.Done():
		return history.UplinkHistory{}, ctx.Err()
	}
}
func TestUplinkQueryReauthorizesWithoutBlockingRemoval(t *testing.T) {
	s := newIdentityTestServer(t)
	b := &blockedUplinks{Store: s.history.(*history.Store), started: make(chan struct{}), release: make(chan struct{})}
	s.history = b
	rec := httptest.NewRecorder()
	req := requestWithNodeCertificate(t, "GET", "/fleet/uplinks?node_id=node-a", nil, "node-a")
	done := make(chan struct{})
	go func() { defer close(done); s.handleAuthorizedUplinks(rec, req) }()
	<-b.started
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
	case <-time.After(time.Second):
		t.Fatal("history blocked revocation")
	}
	close(b.release)
	<-done
	if rec.Code != 403 {
		t.Fatal("removed caller received history", rec.Code)
	}
}
