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
	"vpnctl/internal/history"
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
		if !r.History.MappingReady || r.History.Delivery.Delivered < 3 || r.History.WireGuardDelivery.Delivered < 1 || r.History.LastMappingDrop != "peer_not_registered" {
			return fmt.Errorf("history not ready: %+v", r.History)
		}
		body, _ := json.MarshalIndent(r, "", "  ")
		mustWrite(t, filepath.Join(results, "monitor-history-quality.json"), string(body))
		return nil
	})

	readWG := func() (history.WireGuardHistory, string) {
		body := netOutput(t, namespaces[1], bin, "fleet", "wireguard", "--config", paths[0], "--node", "node-0", "--json")
		var r history.WireGuardHistory
		if e := json.Unmarshal([]byte(body), &r); e != nil {
			t.Fatal(e)
		}
		return r, body
	}
	wgInitial, wgBody := readWG()
	verifyWG := func(r history.WireGuardHistory) {
		t.Helper()
		if len(r.Snapshots) == 0 || r.Truncated {
			t.Fatal("missing or truncated WG history", r)
		}
		seen := map[string]bool{}
		for _, snapshot := range r.Snapshots {
			if seen[snapshot.ID] || snapshot.ViewsTruncated || len(snapshot.Views) != 2 || snapshot.Unmapped != 1 {
				t.Fatal("duplicate snapshot or missing controller/registered WG peer", snapshot)
			}
			seen[snapshot.ID] = true
			registered, native := false, false
			for _, v := range snapshot.Views {
				if v.RX == nil {
					t.Fatal("missing real kernel counter", v)
				}
				if v.Peer.NodeID == "node-1" && v.Peer.PublicKey == b.Node.WGPublicKey {
					registered = true
				}
				if v.Peer.NodeID == "" && v.Peer.Epoch == "" && v.Peer.PublicKey == a.Node.ServerPublicKey && v.Peer.VPNIP == "" && v.HandshakeState == "observed" && *v.RX > 0 && v.TX != nil && *v.TX > 0 {
					native = true
				}
			}
			if !registered || !native {
				t.Fatal("native controller peer identity was dropped or fabricated", snapshot)
			}
		}
	}
	mustWrite(t, filepath.Join(results, "wireguard-history-live.json"), wgBody)
	verifyWG(wgInitial)
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
	// Sampling uses UTC minute slots. Starting just before a minute boundary
	// can legitimately produce multiple snapshots while this fixture runs.
	// Capture the persistence baseline only after the producer has stopped.
	wgInitial, wgBody = readWG()
	mustWrite(t, filepath.Join(results, "wireguard-history-initial.json"), wgBody)
	verifyWG(wgInitial)
	r, body := readHistory()
	attempts, successes := count(r)
	mustWrite(t, filepath.Join(results, "monitor-history-initial.json"), body)
	return func(phase string) {
		t.Helper()
		wgNow, wgBody := readWG()
		verifyWG(wgNow)
		if len(wgNow.Snapshots) != len(wgInitial.Snapshots) {
			t.Fatal("WG history changed after restart", phase)
		}
		for i, snapshot := range wgNow.Snapshots {
			if snapshot.ID != wgInitial.Snapshots[i].ID {
				t.Fatal("WG snapshot changed after restart", phase, i)
			}
		}
		mustWrite(t, filepath.Join(results, "wireguard-history-"+phase+".json"), wgBody)
		r, body := readHistory()
		got, wins := count(r)
		if got != attempts || wins != successes {
			t.Fatal("monitor history changed after controller restart", phase, got, wins, attempts, successes)
		}
		mustWrite(t, filepath.Join(results, "monitor-history-"+phase+".json"), body)
	}
}
