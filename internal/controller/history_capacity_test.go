// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/agent"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
	"vpnctl/internal/observation"
)

type rejectedProbeHistory struct {
	history.Storage
	err error
}

func (s rejectedProbeHistory) Ingest(context.Context, string, []history.Observation, time.Time) error {
	return s.err
}

func TestHistoryQuotaResponseExcludesTransientBackpressure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{"quota", fmt.Errorf("batch: %w", &history.QuotaError{Resource: "rows", Limit: history.MaxRows}), 503},
		{"WAL", history.ErrCapacity, 503},
		{"timeout", context.DeadlineExceeded, 503},
		{"IO", errors.New("disk unavailable"), 503},
		{"invalid", history.ErrInvalid, 400},
		{"conflict", history.ErrConflict, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newIdentityTestServer(t)
			s.history = rejectedProbeHistory{Storage: s.history, err: tc.err}
			rec := submitHistory(t, s, api.MetricsRequest{NodeID: "node-a", Observations: historySamples(time.Now())}, "node-a")
			var response api.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || rec.Code != tc.code {
				t.Fatal(rec.Code, rec.Body.String(), err)
			}
			if tc.name == "quota" {
				if response.Code != api.CodeHistoryQuota || response.Resource != "rows" || response.Limit != history.MaxRows {
					t.Fatal(response)
				}
			} else if response.Code != "" {
				t.Fatal("transient/invalid response mislabeled as quota", response)
			}
		})
	}
}

func TestHistoryQuotaOverMTLSKeepsAdmittedStreamFlowing(t *testing.T) {
	s, h := lifecycleServer(t, "90s")
	robot, dir := lifecycleNode(t, s, h, "robot")
	lifecycleNode(t, s, h, "admitted")
	lifecycleNode(t, s, h, "rejected")
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := history.Observation{ID: "seed", Timestamp: now, PeerID: "admitted", Path: "direct", Source: "agent-direct", Validity: "unknown", Reason: "collector_unavailable"}
	batch := make([]history.Observation, history.MaxNodeStreams)
	for i := range batch {
		batch[i] = base
		batch[i].Uplink = fmt.Sprint(i)
	}
	if err := robot.SubmitMetrics(context.Background(), api.MetricsRequest{NodeID: "robot", Observations: batch}); err != nil {
		t.Fatal(err)
	}
	over := base
	over.PeerID = "rejected"
	err := robot.SubmitMetrics(context.Background(), api.MetricsRequest{NodeID: "robot", Observations: []history.Observation{over}})
	var response *api.HTTPError
	if !errors.As(err, &response) || response.StatusCode != http.StatusServiceUnavailable || response.Code != api.CodeHistoryQuota {
		t.Fatal("real quota not classified", err)
	}
	rec := httptest.NewRecorder()
	s.httpHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/prom/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `vpnctl_probe_history_quota_rejected_total{resource="node_streams"}`) {
		t.Fatal("quota signal absent from production scrape route", rec.Code, rec.Body.String())
	}
	var supervisor agent.ProbeHistorySupervisor
	ctx := supervisor.Configure(context.Background(), config.NodeConfig{Name: "robot", Controller: h.URL, PKIDir: dir})
	defer supervisor.Stop()
	// Repeated rejected identities/streams must not impose 15s of backoff per
	// item on an already admitted stream. Query the committed DB via mTLS.
	for i := 0; i < 32; i++ {
		over.Uplink = fmt.Sprint(i)
		observation.Emit(ctx, over)
	}
	base.Uplink = "0"
	observation.Emit(ctx, base)
	start := time.Now()
	waitPKI(t, 2*time.Second, func() bool {
		resp, err := robot.FleetHistoryQuery(context.Background(), "1h", "robot", "1h")
		if err != nil || len(resp.Nodes) != 1 {
			return false
		}
		total := 0
		for _, b := range resp.Nodes[0].Buckets {
			if b.PeerID != "admitted" || b.Count != 0 || b.LossPct != nil || b.AvailabilityPct != nil {
				t.Error("quota drop became data or unknown became success", b)
			}
			total += b.UnknownCount
		}
		return total == history.MaxNodeStreams+1
	})
	t.Logf("admitted stream delivered after 32 quota rejections in %s", time.Since(start))
	// Replaying the original batch at the stream ceiling remains idempotent.
	if err := robot.SubmitMetrics(context.Background(), api.MetricsRequest{NodeID: "robot", Observations: batch}); err != nil {
		t.Fatal("quota broke idempotent retry", err)
	}
}
