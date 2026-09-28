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
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/monitor"
)

// Use the shipped monitor's live wg discovery, UDP probes, credential transport,
// local status and fleet CLI. Restore the temporary direct peers before the
// uplink-only lifecycle fixture takes its kernel snapshots.
func exerciseMonitorHistory(t *testing.T, bin string, namespaces, paths []string, results string) func(string) {
	t.Helper()
	if len(paths) < 2 {
		return func(string) {}
	}
	a, err := config.Load(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.Load(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	netOutput(t, namespaces[1], "wg", "set", "wg0", "peer", b.Node.WGPublicKey, "allowed-ips", "10.77.0.3/32", "endpoint", "192.0.2.3:51820")
	netOutput(t, namespaces[2], "wg", "set", "wg0", "peer", a.Node.WGPublicKey, "allowed-ips", "10.77.0.2/32", "endpoint", "192.0.2.2:51820")
	defer netOutput(t, namespaces[1], "wg", "set", "wg0", "peer", b.Node.WGPublicKey, "remove")
	defer netOutput(t, namespaces[2], "wg", "set", "wg0", "peer", a.Node.WGPublicKey, "remove")
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process := startNetworkProcess(t, namespaces[1], filepath.Join(results, "monitor-history.log"), nil, bin, "monitor", "--interface", "wg0", "--watch", "--history-config", paths[0], "--data", filepath.Join(results, "monitor-history.db"), "--metrics-port", "19100", "--interval", "200ms")
	read := func() (monitor.QualityResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		body, err := netCommand(ctx, namespaces[1], "env", "VPNCTL_WORKER=monitor-http", "VPNCTL_MONITOR_PATH=/network/quality", worker, "-test.run=^TestNetworkWorker$").CombinedOutput()
		var response monitor.QualityResponse
		if err == nil {
			err = json.Unmarshal(body, &response)
		}
		return response, err
	}
	eventually(t, 12*time.Second, "actual monitor history delivery", func() error {
		r, e := read()
		if e != nil {
			return e
		}
		if !r.History.MappingReady || r.History.Delivery.Delivered < 3 || r.History.LastMappingDrop != "peer_not_registered" {
			return fmt.Errorf("history not ready: %+v", r.History)
		}
		body, _ := json.MarshalIndent(r, "", "  ")
		mustWrite(t, filepath.Join(results, "monitor-history-quality.json"), string(body))
		return nil
	})
	netOutput(t, namespaces[2], "nft", "add", "table", "inet", "monitor_reject")
	netOutput(t, namespaces[2], "nft", "add", "chain", "inet", "monitor_reject", "input", "{ type filter hook input priority -10; policy accept; }")
	netOutput(t, namespaces[2], "nft", "add", "rule", "inet", "monitor_reject", "input", "iifname", "wg0", "ip", "saddr", "10.77.0.2", "udp", "dport", "51900", "reject")
	defer netOutput(t, namespaces[2], "nft", "delete", "table", "inet", "monitor_reject")
	readHistory := func() (api.FleetHistoryResponse, string) {
		body := netOutput(t, namespaces[1], bin, "fleet", "history", "--config", paths[0], "--node", "node-0", "--window", "1h", "--json")
		var r api.FleetHistoryResponse
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		return r, body
	}
	count := func(r api.FleetHistoryResponse) (int, int) {
		attempts, successes := 0, 0
		for _, n := range r.Nodes {
			for _, b := range n.Buckets {
				if b.Source != "monitor-overlay" {
					continue
				}
				if b.PeerID != "node-1" || b.Path != "unknown" || b.RelayID != "" || b.Uplink != "" {
					t.Fatal("false monitor identity/route", b)
				}
				attempts += b.Count
				successes += b.Successes
			}
		}
		return attempts, successes
	}
	eventually(t, 8*time.Second, "actual monitor failure reaches fleet", func() error {
		r, _ := readHistory()
		attempts, successes := count(r)
		if successes < 1 || attempts <= successes {
			return fmt.Errorf("attempts=%d successes=%d", attempts, successes)
		}
		return nil
	})
	process.terminate(t)
	r, body := readHistory()
	attempts, successes := count(r)
	mustWrite(t, filepath.Join(results, "monitor-history-initial.json"), body)
	return func(phase string) {
		t.Helper()
		r, body := readHistory()
		got, wins := count(r)
		if got != attempts || wins != successes {
			t.Fatal("monitor history changed after controller restart", phase, got, wins, attempts, successes)
		}
		mustWrite(t, filepath.Join(results, "monitor-history-"+phase+".json"), body)
	}
}
