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
	"slices"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
	"vpnctl/internal/monitor"
)

// Use the shipped monitor's live wg discovery, UDP probes, credential transport,
// local status and fleet CLI. Restore the temporary direct peers before the
// uplink-only lifecycle fixture takes its kernel snapshots. The first callback
// captures persisted state after controller termination; the second checks it
// through the live API after each restart. The suite is bounded to 15 minutes,
// shorter than the one-hour query window for this newly created history.
func exerciseMonitorHistory(t *testing.T, bin string, namespaces, paths []string, results, dataDir string) (func(), func(string)) {
	t.Helper()
	if len(paths) < 2 {
		return func() {}, func(string) {}
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
	count := func(r api.FleetHistoryResponse) monitorHistorySnapshot {
		out := monitorHistorySnapshot{WGIDs: []string{}}
		for _, n := range r.Nodes {
			for _, b := range n.Buckets {
				if b.Source != "monitor-overlay" {
					continue
				}
				if b.PeerID != "node-1" || b.Path != "unknown" || b.RelayID != "" || b.Uplink != "" {
					t.Fatal("false monitor identity/route", b)
				}
				out.Attempts += b.Count
				out.Successes += b.Successes
				out.Unknown += b.UnknownCount
			}
		}
		return out
	}
	eventually(t, 8*time.Second, "actual monitor failure reaches fleet", func() error {
		r, _ := readHistory()
		got := count(r)
		if got.Successes < 1 || got.Attempts <= got.Successes {
			return fmt.Errorf("attempts=%d successes=%d", got.Attempts, got.Successes)
		}
		return nil
	})
	process.terminate(t)
	// Preserve the producer-stop evidence; a canceled upload may still commit
	// at the controller. Only the later server drain establishes a baseline.
	wgInitial, wgBody = readWG()
	mustWrite(t, filepath.Join(results, "wireguard-history-initial.json"), wgBody)
	verifyWG(wgInitial)
	r, body := readHistory()
	beforeDrain := count(r)
	ids := func(r history.WireGuardHistory) []string {
		out := make([]string, 0, len(r.Snapshots))
		for _, snapshot := range r.Snapshots {
			out = append(out, snapshot.ID)
		}
		slices.Sort(out)
		return out
	}
	beforeDrain.WGIDs = ids(wgInitial)
	mustWrite(t, filepath.Join(results, "monitor-history-initial.json"), body)
	var baseline monitorHistorySnapshot
	drained := false
	capture := func() {
		t.Helper()
		if drained {
			t.Fatal("monitor history baseline already captured")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		baseline, err = readStoppedMonitorHistory(ctx, dataDir, time.Now())
		if err != nil {
			t.Fatal("capture drained monitor history", err)
		}
		body, e := json.MarshalIndent(struct {
			Before         monitorHistorySnapshot `json:"producer_stopped"`
			Drained        monitorHistorySnapshot `json:"controller_drained"`
			AttemptsDelta  int                    `json:"attempts_delta"`
			SuccessesDelta int                    `json:"successes_delta"`
			UnknownDelta   int                    `json:"unknown_delta"`
			WGDelta        int                    `json:"wireguard_delta"`
		}{beforeDrain, baseline, baseline.Attempts - beforeDrain.Attempts, baseline.Successes - beforeDrain.Successes, baseline.Unknown - beforeDrain.Unknown, len(baseline.WGIDs) - len(beforeDrain.WGIDs)}, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		mustWrite(t, filepath.Join(results, "monitor-history-drained.json"), string(body))
		if baseline.Attempts < beforeDrain.Attempts || baseline.Successes < beforeDrain.Successes || baseline.Unknown < beforeDrain.Unknown || baseline.Attempts-baseline.Successes < beforeDrain.Attempts-beforeDrain.Successes {
			t.Fatal("monitor history lost observations before drain", beforeDrain, baseline)
		}
		for _, id := range beforeDrain.WGIDs {
			if !slices.Contains(baseline.WGIDs, id) {
				t.Fatal("WG history lost snapshot before drain", id)
			}
		}
		drained = true
	}
	return capture, func(phase string) {
		t.Helper()
		if !drained {
			t.Fatal("monitor history persistence check requires controller drain")
		}
		wgNow, wgBody := readWG()
		mustWrite(t, filepath.Join(results, "wireguard-history-"+phase+".json"), wgBody)
		verifyWG(wgNow)
		if !slices.Equal(ids(wgNow), baseline.WGIDs) {
			t.Fatal("WG history changed after restart", phase)
		}
		r, body := readHistory()
		mustWrite(t, filepath.Join(results, "monitor-history-"+phase+".json"), body)
		got := count(r)
		if got.Attempts != baseline.Attempts || got.Successes != baseline.Successes || got.Unknown != baseline.Unknown {
			t.Fatal("monitor history changed after controller restart", phase, got, baseline)
		}
	}
}
