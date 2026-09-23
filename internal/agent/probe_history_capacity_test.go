// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
	"vpnctl/internal/observation"
)

func TestProbeHistoryCapacityClassificationAndReadyPeerDeadline(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		retry      bool
	}{
		{"quota", `{"error":"quota reached","code":"history_quota"}`, 503, false},
		{"legacy_capacity_text", `{"error":"history capacity reached"}`, 503, true},
		{"unknown_code", `{"error":"busy","code":"future_code"}`, 503, true},
		{"malformed", `{"code":"history_quota"`, 503, true},
		{"registration_recovery", `{"code":"history_quota"}`, 403, true},
		{"unexpected_status", `{"code":"history_quota"}`, 500, true},
		{"removed_peer", `{"error":"peer not found"}`, 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var badCalls atomic.Int32
			badReceived, healthy := make(chan history.Observation, 8), make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req api.MetricsRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Observations) != 1 {
					t.Error("invalid producer request", err)
					w.WriteHeader(400)
					return
				}
				o := req.Observations[0]
				if o.PeerID == "bad" {
					badCalls.Add(1)
					badReceived <- o
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				w.WriteHeader(204)
				healthy <- struct{}{}
			}))
			defer server.Close()
			var supervisor ProbeHistorySupervisor
			ctx := supervisor.Configure(context.Background(), config.NodeConfig{Name: "robot", Controller: server.URL})
			defer supervisor.Stop()
			observation.Emit(ctx, unknownDirect("bad", "collector_unavailable"))
			observation.Emit(ctx, unknownDirect("healthy", "collector_unavailable"))
			select {
			case <-healthy:
			case <-time.After(750 * time.Millisecond):
				t.Fatal("healthy peer blocked by rejection/backoff")
			}
			first := <-badReceived
			select {
			case retry := <-badReceived:
				if !tc.retry || !reflect.DeepEqual(first, retry) {
					t.Fatal("wrong retry decision or changed body", retry)
				}
			case <-time.After(1500 * time.Millisecond):
				if tc.retry {
					t.Fatal("transient failure not retried")
				}
			}
			supervisor.Stop()
			want := int32(1)
			if tc.retry {
				want = 2
			}
			if badCalls.Load() != want {
				t.Fatal("unexpected retry count", badCalls.Load())
			}
		})
	}
}
