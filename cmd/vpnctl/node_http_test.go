// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"vpnctl/internal/metrics"
)

func TestNodeMetricsHTTPIsLoopbackAndOnlyExposesHistoryDelivery(t *testing.T) {
	metrics.ProbeHistoryDeliveryTotal.WithLabelValues("queued").Inc()
	stop, address, err := startNodeMetricsHTTP(0, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("metrics listener address = %q, err = %v; want loopback", address, err)
	}
	response, err := http.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d", response.StatusCode)
	}
	text := string(body)
	if !strings.Contains(text, "vpnctl_probe_history_delivery_total") {
		t.Fatalf("direct history delivery counter missing from response: %s", text)
	}
	if strings.Contains(text, "vpnctl_direct_probes_total") || strings.Contains(text, "vpnctl_nodes_registered") {
		t.Fatalf("node endpoint exposed unrelated process metrics: %s", text)
	}
}
