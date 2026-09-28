//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
	"vpnctl/internal/monitor"
	"vpnctl/internal/pki"
)

type soakObservation struct {
	WGPeerNodes            []string              `json:"wireguard_peer_nodes"`
	HeartbeatUnknown       int                   `json:"heartbeat_unknown"`
	RecentEvents           []history.Event       `json:"recent_events"`
	CompletedAt            time.Time             `json:"observation_completed_at"`
	At                     time.Time             `json:"at"`
	Phase                  string                `json:"phase"`
	Node                   string                `json:"node"`
	Error                  string                `json:"error,omitempty"`
	RegisteredNodes        int                   `json:"registered_nodes"`
	HeartbeatMaxAgeSeconds float64               `json:"heartbeat_max_age_seconds"`
	Storage                history.StorageHealth `json:"storage"`
	Delivery               monitor.HistoryStatus `json:"delivery"`
	ProbeSamples           int                   `json:"probe_samples"`
	Sources                map[string]int        `json:"probe_sources"`
	WGReports              int                   `json:"wireguard_reports_in_page"`
	UplinkObservedAt       *time.Time            `json:"uplink_observed_at"`
	WGObservedAt           *time.Time            `json:"wireguard_observed_at"`
	WGPeers                int                   `json:"wireguard_peers"`
	UplinkSamples          int                   `json:"uplink_samples"`
	UplinkFailures         int                   `json:"uplink_failures"`
	LatestUplinkStage      string                `json:"latest_uplink_failure_stage"`
	EventCount             int                   `json:"event_count_in_page"`
	EventsTruncated        bool                  `json:"events_truncated"`
	Alerts                 []history.Alert       `json:"alerts"`
	LatencyMS              map[string]float64    `json:"api_latency_ms"`
	CertificateFingerprint string                `json:"certificate_fingerprint"`
	CertificateNotAfter    time.Time             `json:"certificate_not_after"`
}

func readSoakObservation() error {
	cfg, e := config.Load(os.Getenv("VPNCTL_SOAK_CONFIG"))
	if e != nil || cfg.Node == nil {
		return fmt.Errorf("invalid soak node configuration")
	}
	v := soakObservation{At: time.Now().UTC(), Node: cfg.Node.Name, Sources: map[string]int{}, LatencyMS: map[string]float64{}}
	collect := func() error {
		creds, e := pki.LoadCredentials(cfg.Node.PKIDir)
		if e != nil {
			return fmt.Errorf("credentials unavailable")
		}
		cert, e := pki.ParseCertificate(creds.ClientCert)
		if e != nil {
			return fmt.Errorf("certificate invalid")
		}
		v.CertificateFingerprint, v.CertificateNotAfter = pki.Fingerprint(cert), cert.NotAfter
		c := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
		defer c.CloseIdleConnections()
		request := func(name string, call func(context.Context) error) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			e := call(ctx)
			v.LatencyMS[name] = float64(time.Since(start).Microseconds()) / 1000
			if e != nil {
				return fmt.Errorf("%s: %w", name, e)
			}
			return nil
		}
		if e = request("local_monitor", func(ctx context.Context) error {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:19100/network/quality", nil)
			resp, e := http.DefaultClient.Do(req)
			if e != nil {
				return e
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			var q monitor.QualityResponse
			if e = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&q); e == nil {
				v.Delivery = q.History
			}
			return e
		}); e != nil {
			return e
		}
		if e = request("fleet_status", func(ctx context.Context) error {
			f, e := c.FleetStatus(ctx)
			if e != nil {
				return e
			}
			v.RegisteredNodes = len(f.Nodes)
			for _, n := range f.Nodes {
				if at, e := time.Parse(time.RFC3339, n.LastSeen); e == nil {
					age := v.At.Sub(at).Seconds()
					if age > v.HeartbeatMaxAgeSeconds {
						v.HeartbeatMaxAgeSeconds = age
					}
				}
				if _, err := time.Parse(time.RFC3339, n.LastSeen); err != nil {
					v.HeartbeatUnknown++
				}
				if n.Name == cfg.Node.Name {
					for _, m := range n.Measurements {
						v.ProbeSamples += m.SampleCount
						v.Sources[m.Source] += m.SampleCount
					}
				}
			}
			return nil
		}); e != nil {
			return e
		}
		if e = request("storage", func(ctx context.Context) error { var e error; v.Storage, e = c.FleetStorage(ctx); return e }); e != nil {
			return e
		}
		if e = request("wireguard", func(ctx context.Context) error {
			w, e := c.FleetWireGuard(ctx, cfg.Node.Name, "1h", 2)
			if e != nil {
				return e
			}
			v.WGReports = len(w.Snapshots)
			if len(w.Snapshots) > 0 {
				v.WGObservedAt = &w.Snapshots[0].ObservedAt
				v.WGPeers = len(w.Snapshots[0].Views)
				for _, peer := range w.Snapshots[0].Views {
					v.WGPeerNodes = append(v.WGPeerNodes, peer.Peer.NodeID)
				}
			}
			return nil
		}); e != nil {
			return e
		}
		if e = request("uplink", func(ctx context.Context) error {
			u, e := c.FleetUplinks(ctx, cfg.Node.Name, "1h", 1)
			if e != nil {
				return e
			}
			for _, s := range u.Summaries {
				v.UplinkSamples += s.Samples
				v.UplinkFailures += s.Failures
			}
			if len(u.Snapshots) > 0 && len(u.Snapshots[0].Targets) > 0 {
				v.LatestUplinkStage = u.Snapshots[0].Targets[0].FailureStage
				v.UplinkObservedAt = &u.Snapshots[0].At
			}
			return nil
		}); e != nil {
			return e
		}
		if e = request("events", func(ctx context.Context) error {
			r, e := c.FleetEvents(ctx, cfg.Node.Name, "1h", 20)
			v.EventCount = len(r.Events)
			v.RecentEvents = r.Events
			v.EventsTruncated = r.Truncated
			return e
		}); e != nil {
			return e
		}
		return request("alerts", func(ctx context.Context) error {
			var e error
			v.Alerts, e = c.FleetAlerts(ctx, cfg.Node.Name)
			return e
		})
	}
	if e := collect(); e != nil {
		v.Error = e.Error()
	}
	v.CompletedAt = time.Now().UTC()
	return json.NewEncoder(os.Stdout).Encode(v)
}

// checkSoakReady validates current identities and collection times, rather than
// treating a recent but pre-fault healthy snapshot as recovery evidence.
func checkSoakReady(v soakObservation, size int, peers []string, after, now time.Time) error {
	if v.Error != "" || v.Storage.Validity != "observed" || v.Storage.Stale || v.RegisteredNodes != size || v.HeartbeatUnknown != 0 || v.HeartbeatMaxAgeSeconds > 30 || v.WGReports == 0 || v.WGPeers != size || v.Delivery.WireGuardDelivery.Delivered == 0 || v.Sources["agent-direct"] == 0 || v.Sources["monitor-overlay"] == 0 || v.UplinkSamples == 0 || v.LatestUplinkStage != "none" {
		return fmt.Errorf("producer not ready: error=%q storage=%s nodes=%d WG_reports=%d WG_peers=%d WG_delivered=%d sources=%v uplinks=%d stage=%s", v.Error, v.Storage.Validity, v.RegisteredNodes, v.WGReports, v.WGPeers, v.Delivery.WireGuardDelivery.Delivered, v.Sources, v.UplinkSamples, v.LatestUplinkStage)
	}
	for _, at := range []*time.Time{v.WGObservedAt, v.UplinkObservedAt} {
		if at == nil || at.Before(after) || at.After(now) || now.Sub(*at) >= 90*time.Second {
			return fmt.Errorf("producer collection predates recovery or is stale/unknown")
		}
	}
	expected := map[string]bool{}
	for _, id := range peers {
		expected[id] = true
	}
	for _, id := range v.WGPeerNodes {
		delete(expected, id)
	}
	if len(expected) != 0 {
		return fmt.Errorf("current WG peer identities missing: %v", expected)
	}
	return nil
}
