// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
)

// Run the shipped producer/consumer CLIs over mTLS and real kernel WG. The
// lifecycle suite calls the returned check again after both controller restarts.
func exerciseFleetHistory(t *testing.T, bin string, namespaces, configs []string, results string) func(string) {
	t.Helper()
	if len(configs) < 2 {
		return func(string) {}
	}
	// The uplink-only fixture initially rejects WG peer-to-peer forwarding.
	// Verify truthful failed measurements before allowing only this test probe.
	netOutput(t, namespaces[1], bin, "ping", "--config", configs[0], "--peer", "node-1", "--path", "relay", "--count", "3", "--interval", "100ms", "--timeout", "200ms")
	blockedJSON := netOutput(t, namespaces[1], bin, "fleet", "status", "--config", configs[0], "--json")
	var blocked api.FleetStatusResponse
	if e := json.Unmarshal([]byte(blockedJSON), &blocked); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, n := range blocked.Nodes {
		if n.Name == "node-0" {
			found = true
			if n.Quality != "offline" || n.RTTMs != nil || n.LossPct == nil || *n.LossPct != 100 || n.SampleCount != 3 {
				t.Fatal("blocked path reported healthy", n)
			}
		}
	}
	if !found {
		t.Fatal("reporter missing")
	}
	mustWrite(t, filepath.Join(results, "fleet-status-blocked.json"), blockedJSON)
	for _, direction := range []struct{ source, dest, port string }{
		{"10.77.0.2", "10.77.0.3", "dport"}, {"10.77.0.3", "10.77.0.2", "sport"},
	} {
		netOutput(t, namespaces[0], "nft", "add", "rule", "ip", "vpnctl_lab", "forward", "iifname", "wg0", "oifname", "wg0", "ip", "saddr", direction.source, "ip", "daddr", direction.dest, "udp", direction.port, "51900", "counter", "accept")
	}
	netOutput(t, namespaces[1], bin, "ping", "--config", configs[0], "--peer", "node-1", "--path", "relay", "--count", "3", "--interval", "100ms")
	statusJSON := netOutput(t, namespaces[1], bin, "fleet", "status", "--config", configs[0], "--json")
	var status api.FleetStatusResponse
	if e := json.Unmarshal([]byte(statusJSON), &status); e != nil {
		t.Fatal(e, statusJSON)
	}
	var measured api.FleetNodeStatus
	for _, n := range status.Nodes {
		if n.Name == "node-0" {
			measured = n
		}
	}
	if measured.SampleCount != 6 || measured.RTTMs == nil || measured.LossPct == nil || *measured.LossPct != 50 || measured.Stale || measured.Path != "relay" || measured.PeerID != "node-1" {
		t.Fatal("real fleet measurement", statusJSON)
	}
	mustWrite(t, filepath.Join(results, "fleet-status.json"), statusJSON)
	text := netOutput(t, namespaces[1], bin, "fleet", "status", "--config", configs[0])
	if !strings.Contains(text, history.FormatNumber(measured.RTTMs)) {
		t.Fatal("CLI disagrees with API", text)
	}
	cfg, e := config.Load(configs[0])
	if e != nil {
		t.Fatal(e)
	}
	worker, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := netCommand(ctx, namespaces[1], "env", "VPNCTL_WORKER=fleet-page", "VPNCTL_PKI="+cfg.Node.PKIDir, worker, "-test.run=^TestNetworkWorker$")
	page, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatal(e, string(page))
	}
	if !strings.Contains(string(page), history.FormatNumber(measured.RTTMs)) {
		t.Fatal("status page disagrees with API", string(page))
	}
	mustWrite(t, filepath.Join(results, "fleet-status.html"), string(page))
	check := func(phase string) {
		t.Helper()
		body := netOutput(t, namespaces[1], bin, "fleet", "history", "--config", configs[0], "--node", "node-0", "--window", "24h", "--json")
		var resp api.FleetHistoryResponse
		if e := json.Unmarshal([]byte(body), &resp); e != nil {
			t.Fatal(e, body)
		}
		count := 0
		sum := 0.0
		for _, n := range resp.Nodes {
			for _, b := range n.Buckets {
				count += b.Count
				if b.AvgRTTMs != nil {
					sum += *b.AvgRTTMs * float64(b.Successes)
				}
			}
		}
		if count != 6 || fmt.Sprintf("%.3f", sum/3) != fmt.Sprintf("%.3f", *measured.RTTMs) {
			t.Fatal("history lost or changed samples", phase, body)
		}
		mustWrite(t, filepath.Join(results, "fleet-history-"+phase+".json"), body)
	}
	check("initial")
	return check
}
