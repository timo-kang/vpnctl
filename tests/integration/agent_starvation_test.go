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
	"strconv"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/store"
)

// Real WG, VPN-only controller access, auto direct mode and default health
// settings. Silent candidates must not suppress heartbeat or tunnel recovery.
func TestNetns_AutoSilentFleet(t *testing.T) {
	requireNetwork(t)
	bin := integrationBinary(t)
	sizes := os.Getenv("VPNCTL_NETNS_SIZES")
	if sizes == "" {
		sizes = "1,3,8,32"
	}
	for _, part := range strings.Split(sizes, ",") {
		size, err := strconv.Atoi(part)
		if err != nil || size < 1 || size > 64 {
			t.Fatal("invalid size", part)
		}
		t.Run(fmt.Sprintf("silent_%d", size), func(t *testing.T) {
			ns := newNamespaces(t, 1)
			dir := t.TempDir()
			ctrlPrivate, ctrlPublic := wgKeyPair(t)
			nodePrivate, nodePublic := wgKeyPair(t)
			state := filepath.Join(dir, "controller")
			reg := &store.Registry{Nodes: []store.NodeInfo{{ID: "node", Name: "node", PubKey: nodePublic, VPNIP: "10.77.0.2/32"}}}
			for i := 0; i < size; i++ {
				_, key := wgKeyPair(t)
				reg.Nodes = append(reg.Nodes, store.NodeInfo{ID: fmt.Sprintf("silent-%d", i), Name: fmt.Sprintf("silent-%d", i), PubKey: key, VPNIP: fmt.Sprintf("10.77.0.%d/32", i+3), Endpoint: "192.0.2.1:52000", PublicAddr: "192.0.2.1:52000", ProbePort: 52000})
			}
			registryPath := filepath.Join(state, "registry.yaml")
			if err := store.SaveRegistry(registryPath, reg); err != nil {
				t.Fatal(err)
			}
			ctrlPath := filepath.Join(dir, "controller.yaml")
			if err := config.Save(ctrlPath, config.Config{Controller: &config.ControllerConfig{Listen: "0.0.0.0:8080", DataDir: state, VPNCIDR: "10.77.0.0/24", WGApply: true, WGPrivateKey: ctrlPrivate, WGAddress: "10.77.0.1/24", ServerPublicKey: ctrlPublic, ServerEndpoint: "192.0.2.1:51820", ServerAllowedIPs: []string{"10.77.0.0/24"}}}); err != nil {
				t.Fatal(err)
			}
			startController := func() *networkProcess {
				return startNetworkProcess(t, ns[0], filepath.Join(dir, "controller.log"), nil, bin, "controller", "init", "--config", ctrlPath)
			}
			ctrl := startController()
			eventually(t, 5*time.Second, "controller ready", func() error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, err := api.Admin(ctx, state, api.AdminRequest{Operation: "token.list"})
				if err != nil && strings.Contains(err.Error(), "409 Conflict") {
					return nil
				}
				return err
			})
			disabled := false
			nodePath := filepath.Join(dir, "node.yaml")
			if err := config.Save(nodePath, config.Config{Node: &config.NodeConfig{Name: "node", Controller: "http://10.77.0.1:8080", WGPrivateKey: nodePrivate, WGPublicKey: nodePublic, VPNIP: "10.77.0.2/32", WGConfigPath: filepath.Join(dir, "wg.conf"), ServerPublicKey: ctrlPublic, ServerEndpoint: "192.0.2.1:51820", ServerAllowedIPs: []string{"10.77.0.0/24"}, KeepaliveIntervalSec: 1, CandidatesIntervalSec: 1, DirectIntervalSec: 1, DirectMode: "auto", PolicyRoutingEnabled: &disabled}}); err != nil {
				t.Fatal(err)
			}
			nodeLog := filepath.Join(dir, "node.log")
			agent := startNetworkProcess(t, ns[1], nodeLog, nil, bin, "node", "serve", "--config", nodePath, "--retry-delay", "100ms", "--retry-max-delay", "1s")
			freshness := func() (time.Duration, error) {
				current, err := store.LoadRegistry(registryPath)
				if err != nil {
					return 0, err
				}
				for _, node := range current.Nodes {
					if node.ID == "node" {
						return time.Since(node.LastSeenAt), nil
					}
				}
				return 0, fmt.Errorf("node missing")
			}
			eventually(t, 5*time.Second, "agent heartbeat", func() error {
				age, err := freshness()
				if err != nil {
					return err
				}
				if age > 2*time.Second {
					return fmt.Errorf("stale heartbeat %v", age)
				}
				return nil
			})
			maxAge := time.Duration(0)
			until := time.Now().Add(8 * time.Second)
			for time.Now().Before(until) {
				age, err := freshness()
				if err != nil {
					t.Fatal(err)
				}
				if age > maxAge {
					maxAge = age
				}
				if age > 2500*time.Millisecond {
					t.Fatalf("heartbeat starved: %v", age)
				}
				time.Sleep(100 * time.Millisecond)
			}
			testBin, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			observed := netOutput(t, ns[1], "env", "VPNCTL_WORKER=plaintext-metrics", testBin, "-test.run=^TestNetworkWorker$")
			if !strings.Contains(observed, "vpnctl_direct_probes_total{") || !strings.Contains(observed, "silent-") {
				t.Fatal("direct failures were not exercised", observed)
			}
			// The production agent must upload real failed attempts, not only Prometheus
			// counters or successful probes. Quotas remain enforced at larger sizes.
			historyJSON := netOutput(t, ns[1], bin, "fleet", "history", "--config", nodePath, "--node", "node", "--window", "1h", "--bucket", "1h", "--json")
			var historyResponse api.FleetHistoryResponse
			if err := json.Unmarshal([]byte(historyJSON), &historyResponse); err != nil {
				t.Fatal(err, historyJSON)
			}
			failed := 0
			for _, node := range historyResponse.Nodes {
				for _, bucket := range node.Buckets {
					if bucket.Source != "agent-direct" || bucket.Successes != 0 || bucket.AvgRTTMs != nil || bucket.Count > 0 && (bucket.LossPct == nil || *bucket.LossPct != 100) {
						t.Fatal("silent candidate history is misleading", bucket)
					}
					failed += bucket.Count
				}
			}
			if failed == 0 {
				t.Fatal("automatic failed probes missing from central API", historyJSON)
			}
			if route := netOutput(t, ns[1], "ip", "route", "get", "10.77.0.1"); !strings.Contains(route, "dev wg0") {
				t.Fatal("uplink bypassed WG", route)
			}
			log, _ := os.ReadFile(nodeLog)
			if strings.Contains(string(log), "tunnel dead") {
				t.Fatal("false health failure during healthy uplink", string(log))
			}
			ctrl.stop()
			failedAt := time.Now()
			eventually(t, 13*time.Second, "default health detects failure during silent probes", func() error {
				log, err := os.ReadFile(nodeLog)
				if err != nil {
					return err
				}
				if !strings.Contains(string(log), "tunnel dead, recovering") {
					return fmt.Errorf("recovery not triggered")
				}
				return nil
			})
			detection := time.Since(failedAt)
			ctrl = startController()
			eventually(t, 8*time.Second, "agent recovers without manual rejoin", func() error {
				age, err := freshness()
				if err != nil {
					return err
				}
				if age > 2500*time.Millisecond {
					return fmt.Errorf("stale %v", age)
				}
				return nil
			})
			agent.terminate(t)
			ctrl.terminate(t)
			// Registry loss must fail before startup reconciles (and removes) kernel peers.
			persisted, err := os.ReadFile(registryPath)
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotKernel(t, ns[0])
			for _, fault := range []string{"missing", "empty", "null"} {
				if fault == "missing" {
					err = os.Remove(registryPath)
				} else {
					data := []byte{}
					if fault == "null" {
						data = []byte("null\n")
					}
					err = os.WriteFile(registryPath, data, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				out, startErr := netCommand(ctx, ns[0], bin, "controller", "init", "--config", ctrlPath).CombinedOutput()
				cancel()
				if startErr == nil || !strings.Contains(string(out), "restore controller state") {
					t.Fatalf("%s registry accepted: %v %s", fault, startErr, out)
				}
				after := snapshotKernel(t, ns[0])
				if after.Peers != before.Peers || after.AllowedIPs != before.AllowedIPs {
					t.Fatal("corrupt registry changed kernel peers")
				}
				if err := os.WriteFile(registryPath, persisted, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("silent_peers=%d max_heartbeat_age=%v default_health_detection=%v", size, maxAge, detection)
		})
	}
}
