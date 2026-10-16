// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"vpnctl/internal/history"
	"vpnctl/internal/metrics"
	"vpnctl/internal/monitor"
)

// These global counters combine direct and monitor delivery. The scale cases
// run serially; take deltas without resetting metrics used by live producers.
func probeDeliveryCounters(t *testing.T) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, result := range []string{"queued", "delivered", "retry", "overflow_dropped", "exhausted_dropped", "rejected_dropped", "quota_dropped", "shutdown_dropped", "stopped_dropped"} {
		var value dto.Metric
		if err := metrics.ProbeHistoryDeliveryTotal.WithLabelValues(result).Write(&value); err != nil {
			t.Errorf("read probe delivery counter %s: %v", result, err)
			continue
		}
		out[result] = value.GetCounter().GetValue()
	}
	return out
}

func probeDeliveryDelta(t *testing.T, before map[string]float64) map[string]float64 {
	t.Helper()
	after := probeDeliveryCounters(t)
	for result, value := range after {
		after[result] = value - before[result]
	}
	return after
}

func logLiveProducerConvergence(t *testing.T, st *history.Store, uploaders []*monitor.HistoryReporter, before map[string]float64) {
	t.Helper()
	started := time.Now().UTC()
	latest := st.Latest(time.Time{})
	statuses := make([]*monitor.HistoryStatus, len(uploaders))
	for i, uploader := range uploaders {
		if uploader != nil {
			status := uploader.Status()
			statuses[i] = &status
		}
	}
	delivery := probeDeliveryDelta(t, before)
	finished := time.Now().UTC()
	// Collection is best effort while producers are live, not an atomic snapshot.
	// Copy all data before logging so log output cannot delay later captures.
	t.Logf("pre-cancel convergence capture: start=%s end=%s probe delivery delta (agent + monitor)=%v", started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), delivery)
	for i, status := range statuses {
		node := fmt.Sprintf("node-%02d", i)
		streams := map[history.Stream]history.Measurement{}
		sources := map[string]int{}
		for _, m := range latest[node] {
			streams[m.Stream] = m
			if m.SampleCount > 0 {
				sources[m.Source]++
			}
		}
		t.Logf("pre-cancel %s: observed streams=%v monitor=%+v", node, sources, status)
		for j := range uploaders {
			if i == j {
				continue
			}
			peer := fmt.Sprintf("node-%02d", j)
			for source, path := range map[string]string{"agent-direct": "direct", "monitor-overlay": "unknown"} {
				key := history.Stream{NodeID: node, PeerID: peer, Source: source, Path: path}
				m, exists := streams[key]
				if !exists {
					t.Logf("pre-cancel missing stream: node=%s peer=%s source=%s", node, peer, source)
				} else if m.SampleCount == 0 {
					t.Logf("pre-cancel stream without completed probes: node=%s peer=%s source=%s samples=%d validity=%s reason=%s observed_at=%v", node, peer, source, m.SampleCount, m.Validity, m.Reason, m.ObservedAt)
				}
			}
		}
	}
}
