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
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
	"vpnctl/internal/statuspage"
)

func TestTieredHistoryOverMTLSVariableTopology(t *testing.T) {
	for _, nodes := range []int{1, 3, 8, 32} {
		for _, mesh := range []bool{false, true} {
			t.Run(fmt.Sprintf("nodes_%d_mesh_%t", nodes, mesh), func(t *testing.T) {
				s, h := lifecycleServer(t, "10m", "30m")
				st := s.history.(*history.Store)
				now := time.Now().UTC().Truncate(time.Hour)
				ctx := context.Background()
				// Advance the storage clock over a real upload/maintenance cycle without
				// changing the TLS/admission wall clock or pre-creating rollup payloads.
				if err := st.EnableTiering(ctx, now.Add(-12*time.Hour)); err != nil {
					t.Fatal(err)
				}
				clients := make([]*api.Client, nodes)
				dirs := make([]string, nodes)
				for n := 0; n < nodes; n++ {
					clients[n], dirs[n] = lifecycleNode(t, s, h, fmt.Sprintf("robot-%02d", n))
				}
				var total int
				for n := 0; n < nodes; n++ {
					batch := []history.Observation{}
					for peer := 0; peer < nodes; peer++ {
						if peer == n || (!mesh && peer != 0 && n != 0) {
							continue
						}
						for src, source := range []string{"agent-direct", "monitor-overlay"} {
							for gen := 0; gen < 4; gen++ {
								o := history.Observation{ID: fmt.Sprintf("sample-%d-%d-%d", peer, src, gen), Timestamp: now.Add(time.Duration(gen-12)*time.Hour + time.Minute), PeerID: fmt.Sprintf("robot-%02d", peer), Path: "direct", Source: source, Uplink: fmt.Sprintf("uplink-%d", gen), Success: historyPtr(true), RTTMs: historyPtr(float64(peer + n + gen))}
								if src == 1 {
									o.Path = "relay"
									o.RelayID = "controller"
								}
								if gen == 0 {
									o.Success = nil
									o.RTTMs = nil
									o.Validity = "unknown"
									o.Reason = "collector_unavailable"
								}
								if gen == 1 {
									o.Success = historyPtr(false)
									o.RTTMs = nil
									o.Reason = "probe_timeout"
								}
								batch = append(batch, o)
							}
						}
					}
					if len(batch) > 0 {
						for retry := 0; retry < 2; retry++ {
							if err := clients[n].SubmitMetrics(ctx, api.MetricsRequest{NodeID: fmt.Sprintf("robot-%02d", n), Observations: batch}); err != nil {
								t.Fatal(err)
							}
						}
					}
					total += len(batch)
				}
				for {
					stats, err := st.TieredStats(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if stats.CompactedSamples == int64(total) {
						break
					}
					if err = st.Maintain(ctx, now); err != nil {
						t.Fatal(err)
					}
				}
				var got int
				var next string
				for n := 0; n < nodes; n++ {
					cursor := ""
					for {
						resp, err := clients[n].FleetHistoryPage(ctx, "24h", fmt.Sprintf("robot-%02d", n), "1h", "", cursor)
						if err != nil {
							t.Fatal(err)
						}
						if resp.SchemaVersion != 3 || resp.Tiering == nil || resp.Storage == nil || resp.Storage.PendingSamples != 0 {
							t.Fatal("tiered metadata missing", resp)
						}
						if n == 0 && cursor == "" {
							next = resp.Tiering.NextCursor
						}
						for _, node := range resp.Nodes {
							for _, b := range node.Buckets {
								got += b.Count + b.UnknownCount
								if b.UnknownCount > 0 && (b.AvailabilityPct != nil || b.LossPct != nil || b.P95RTTMs != nil) {
									t.Fatal("unknown became measured success", b)
								}
							}
						}
						if resp.Tiering.NextCursor == "" {
							break
						}
						cursor = resp.Tiering.NextCursor
					}
				}
				if got != total {
					t.Fatal("missing relation/source/generation", got, total)
				}
				if nodes > 1 {
					err := clients[0].SubmitMetrics(ctx, api.MetricsRequest{NodeID: "robot-00", Observations: []history.Observation{{ID: "late", Timestamp: now.Add(-8 * time.Hour), PeerID: "robot-01", Path: "direct", Success: historyPtr(false)}}})
					var response *api.HTTPError
					if !errors.As(err, &response) || response.StatusCode != 409 || response.Code != api.CodeHistorySealed {
						t.Fatal("sealed upload not classified", err)
					}
					creds, err := pki.LoadCredentials(dirs[0])
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
					_, err = clients[0].FleetHistoryPage(ctx, "24h", "robot-00", "1h", "", next)
					if !errors.As(err, &response) || response.StatusCode != 403 {
						t.Fatal("revoked reader admitted", err)
					}
				}
				page := httptest.NewRecorder()
				statuspage.Handler(s.statusPageData)(page, httptest.NewRequest(http.MethodGet, "/status", nil))
				if !strings.Contains(page.Body.String(), "older hourly distributions") {
					t.Fatal("HTML lacks history retention semantics")
				}
				t.Logf("nodes=%d mesh=%t observations=%d compacted and read over mTLS", nodes, mesh, total)
			})
		}
	}
}
