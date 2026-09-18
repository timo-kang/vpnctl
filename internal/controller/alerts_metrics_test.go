package controller

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"vpnctl/internal/uplink"
)

func TestAlertScrapeWithoutAPIAndAcrossNodes(t *testing.T) {
	s := newIdentityTestServer(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := uplink.Snapshot{ID: "one", At: now, IntervalSec: 60, Underlay: uplink.Down("no_route"), Links: []uplink.Link{{ID: "lan", Interface: "eth0", Kind: "ethernet", Check: uplink.Up(), Modem: uplink.Unknown("not_configured"), GatewayState: uplink.Unknown("not_configured"), DNS: uplink.Unknown("not_configured"), Controller: uplink.Up(), ControllerRoute: uplink.Route{Check: uplink.Up()}}}, Targets: []uplink.Target{{ID: "server", Protocol: "tcp", Route: uplink.Route{Check: uplink.Up()}, TransportRoute: uplink.Route{Check: uplink.Up()}, Relay: uplink.Up(), Service: uplink.Check{State: "up", RTTMs: new(float64)}, FailureStage: "none"}}}
	store := s.history.(uplinkStorage)
	if err := store.IngestUplink(context.Background(), "node-a", snapshot, now); err != nil {
		t.Fatal(err)
	}
	snapshot.Underlay = uplink.Up()
	if err := store.IngestUplink(context.Background(), "node-b", snapshot, now); err != nil {
		t.Fatal(err)
	}
	handler := s.httpHandler()
	for i := 0; i < 2; i++ {
		if i == 1 {
			rec := httptest.NewRecorder()
			s.handleAuthorizedAlerts(rec, requestWithNodeCertificate(t, "GET", "/fleet/alerts?node_id=node-b", nil, "node-b"))
			if rec.Code != 200 {
				t.Fatal(rec.Code)
			}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/prom/metrics", nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `vpnctl_alert_active{code="no_uplink",severity="critical"} 1`) {
			t.Fatal("scrape lost failing node", rec.Code, rec.Body.String())
		}
	}
	c := newAlertCollector(s)
	c.now = func() time.Time { return now.Add(3 * time.Minute) }
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	stale := false
	for _, f := range families {
		if f.GetName() == "vpnctl_alert_active" {
			for _, m := range f.Metric {
				for _, l := range m.Label {
					if l.GetName() == "code" && l.GetValue() == "stale_collector" && m.GetGauge().GetValue() == 2 {
						stale = true
					}
				}
			}
		}
	}
	if !stale {
		t.Fatal("scrape did not detect stopped collectors")
	}
	s.mu.Lock()
	s.reg.Nodes = nil
	s.mu.Unlock()
	families, err = reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, m := range f.Metric {
			if m.GetGauge().GetValue() != 0 {
				t.Fatal("removed nodes still counted")
			}
		}
	}
}
