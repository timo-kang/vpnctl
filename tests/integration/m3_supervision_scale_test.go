//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

var m3ScaleCommandDelayMS = flag.Int("m3-scale-command-delay-ms", 0, "test-only ip/wg/nft delay in [0,10] milliseconds")

// Population qualification, not simultaneous fleet traffic or a latency SLO.
func TestNetns_M3SupervisionScale(t *testing.T) {
	requireNetwork(t)
	if *m3ScaleCommandDelayMS < 0 || *m3ScaleCommandDelayMS > 10 {
		t.Fatal("m3-scale-command-delay-ms must be in [0,10]")
	}
	for _, size := range []int{1, 3, 8, 32} {
		for _, endpoints := range []int{1, 8} {
			t.Run(fmt.Sprintf("nodes_%d_endpoints_%d", size, endpoints), func(t *testing.T) {
				if *m3ScaleCommandDelayMS > 0 {
					slow := t.TempDir()
					for _, tool := range []string{"ip", "wg", "nft"} {
						executable, err := exec.LookPath(tool)
						if err != nil {
							t.Fatal(err)
						}
						shellPath := "'" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "'"
						script := fmt.Sprintf("#!/bin/sh\nsleep %.3f\nexec %s \"$@\"\n", float64(*m3ScaleCommandDelayMS)/1000, shellPath)
						if err := os.WriteFile(filepath.Join(slow, tool), []byte(script), 0700); err != nil {
							t.Fatal(err)
						}
					}
					t.Setenv("PATH", slow+":"+os.Getenv("PATH"))
				}
				ns := newNamespaces(t, 1)
				private := t.TempDir()
				if err := os.Chmod(private, 0700); err != nil {
					t.Fatal(err)
				}
				results, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-supervision-scale-")
				if err != nil {
					t.Fatal(err)
				}
				report := map[string]any{"schema_version": 1, "command_delay_ms": *m3ScaleCommandDelayMS, "nodes": size, "paths_per_node": 4, "endpoints": endpoints, "completed": false, "scope": "real controller mTLS, installed peers/routes and supervisor cycle timing; no fleet traffic SLO"}
				defer func() {
					if t.Failed() {
						// Capture public kernel state before process/namespace cleanup.
						// Inspect would enforce approval and change the failure evidence.
						inventory := map[string]any{"observed_at": time.Now().UTC()}
						for name, args := range map[string][]string{
							"links":  {"ip", "-j", "link", "show"},
							"routes": {"ip", "-j", "route", "show", "table", "all"},
							"peers":  {"wg", "show", "all", "peers"},
							"guards": {"nft", "-j", "-n", "-T", "list", "ruleset"},
						} {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							b, err := netCommand(ctx, ns[1], args...).CombinedOutput()
							cancel()
							truncated := len(b) > 512<<10
							if truncated {
								b = b[:512<<10]
							}
							result := map[string]any{"output": string(b), "truncated": truncated}
							if err != nil {
								result["error"] = err.Error()
							}
							inventory[name] = result
						}
						report["failure_kernel"] = inventory
					}
					b, err := json.MarshalIndent(report, "", "  ")
					if err != nil {
						t.Error(err)
						return
					}
					if err = os.WriteFile(filepath.Join(results, "report.json"), b, 0600); err != nil {
						t.Error(err)
					}
				}()
				ctrl := newM3Controller(t, ns[0], "192.0.2.1", private, results)
				configs := make([]string, size)
				for n := range configs {
					configs[n] = ctrl.enroll(ns[1], fmt.Sprintf("node-%d", n))
				}
				key, pub := wgKeyPair(t)
				keyfile := filepath.Join(private, "relay.key")
				mustWrite(t, keyfile, key)
				relay := relaycatalog.Relay{ID: "r", PublicKey: pub, KeyGeneration: 1}
				for ep := 0; ep < endpoints; ep++ {
					relay.Endpoints = append(relay.Endpoints, relaycatalog.Endpoint{ID: fmt.Sprintf("ep%d", ep), Address: fmt.Sprintf("192.0.2.2:%d", 51820+ep)})
				}
				spec := relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/16", Relays: []relaycatalog.Relay{relay}, Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{m3Target + "/32"}, ProbeAddress: m3Target, Port: 9192, Protocol: "tcp"}}}
				want := map[string]int{}
				for n := 0; n < size; n++ {
					for p := 0; p < 4; p++ {
						ep := fmt.Sprintf("ep%d", (n*4+p)%endpoints)
						want[ep]++
						spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p-%d-%d", n, p), NodeID: fmt.Sprintf("node-%d", n), RelayID: "r", EndpointID: ep, UnderlayID: fmt.Sprintf("lan%d", p), TargetIDs: []string{"app"}})
					}
				}
				ctrl.apply(spec, 3600)
				ctrl.grant("r", "node-0")
				for _, cfg := range configs {
					netOutput(t, ns[1], integrationBinary(t), "node", "relay", "refresh", "--config", cfg)
				}
				approved := ctrl.status()
				bindingAddress := map[string]string{}
				bindingEndpoint := map[string]string{}
				for _, binding := range approved.Bindings {
					bindingAddress[binding.PublicKey] = binding.InnerAddress
					for _, path := range approved.Spec.Paths {
						if path.ID == binding.PathID {
							bindingEndpoint[binding.PublicKey] = path.EndpointID
						}
					}
				}
				r := &m3Recipient{t: t, ns: ns[1], config: configs[0], relay: "r", cache: filepath.Join(private, "cache"), key: keyfile, results: results, generation: 1}
				r.require("refresh", -1, 0)
				started := time.Now()
				for ep := 0; ep < endpoints; ep++ {
					r.require("apply", ep, 51820+ep)
					if ep == 0 {
						r.start()
					}
				}
				report["apply_ms"] = time.Since(started).Milliseconds()
				for attempt := 0; attempt < 3; attempt++ {
					out := r.ready()
					if len(out.Kernel.Endpoints) != endpoints {
						t.Fatal("endpoint population", out)
					}
					actual := map[string]int{}
					for _, ep := range out.Kernel.Endpoints {
						lines := strings.Fields(netOutput(t, ns[1], "wg", "show", ep.Interface, "peers"))
						actual[ep.EndpointID] = len(lines)
						if len(lines) != want[ep.EndpointID] || ep.Peers != len(lines) {
							t.Fatal("kernel peer population", ep, lines)
						}
						allowed := strings.TrimSpace(netOutput(t, ns[1], "wg", "show", ep.Interface, "allowed-ips"))
						if allowed != "" {
							for _, line := range strings.Split(allowed, "\n") {
								fields := strings.Fields(line)
								if len(fields) != 2 || bindingAddress[fields[0]] != fields[1] || bindingEndpoint[fields[0]] != ep.EndpointID {
									t.Fatal("wrong peer/endpoint/address", ep.EndpointID, line)
								}
							}
						}
						var routes []map[string]any
						if err := json.Unmarshal([]byte(netOutput(t, ns[1], "ip", "-j", "-4", "route", "show", "dev", ep.Interface)), &routes); err != nil || len(routes) != len(lines) {
							t.Fatal("kernel route population", err, ep)
						}
						if ep.Lease == nil || !ep.Lease.Active || ep.Lease.Deadline.After(out.ApprovalExpiresAt) {
							t.Fatal("invalid lease deadline", ep)
						}
					}
					report["actual_peers_per_endpoint"] = actual
				}
				if size == 32 && endpoints == 8 {
					report["concurrent_same_namespace"] = checkM3ConcurrentRecipients(t, ctrl, r, spec)
				}
				// Capture process-local memory, not the machine's aggregate RSS.
				if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", r.watch.cmd.Process.Pid)); err == nil {
					for _, line := range strings.Split(string(b), "\n") {
						if strings.HasPrefix(line, "VmHWM:") || strings.HasPrefix(line, "VmRSS:") {
							report[strings.TrimSuffix(strings.Fields(line)[0], ":")] = strings.Join(strings.Fields(line)[1:], " ")
						}
					}
				} else {
					t.Fatal(err)
				}
				r.watch.terminate(t)
				logs, err := filepath.Glob(filepath.Join(results, r.relay+"-supervise-*.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				var b []byte
				for _, log := range logs {
					part, err := os.ReadFile(log)
					if err != nil {
						t.Fatal(err)
					}
					b = append(b, part...)
				}
				var maxCycle int64
				maxBytes, over1s, over5s, cycles := 0, 0, 0, 0
				for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
					var v m3SupervisorReport
					if err := json.Unmarshal([]byte(line), &v); err != nil {
						t.Fatal(err)
					}
					cycles++
					if v.CycleMS > maxCycle {
						maxCycle = v.CycleMS
					}
					if len(line) > maxBytes {
						maxBytes = len(line)
					}
					if v.CycleMS > 1000 {
						over1s++
					}
					if v.CycleMS > 5500 {
						over5s++
					}
				}
				report["supervision"] = map[string]any{"cycles": cycles, "max_cycle_ms": maxCycle, "over_1s": over1s, "over_5s_plus_500ms_scheduler_allowance": over5s, "max_json_bytes": maxBytes}
				if over5s > 0 {
					t.Fatal("supervisor exceeded operation budget", maxCycle)
				}
				// Real kernel set expiry with all 8 endpoints still installed. The
				// expiry time is absolute, not a report's potentially stale ready bit.
				time.Sleep(11 * time.Second)
				out, err := r.call("inspect", -1, 0)
				report["expired_inspection"] = json.RawMessage(out)
				if err == nil {
					t.Fatal("expired endpoints reported ready")
				}
				if endpoints == 8 {
					(relayUplink{relay: r.ns}).nft(t, `table inet scale_outage {
 chain output { type filter hook output priority -310; policy accept;
 ip daddr 192.0.2.1 tcp dport 9443 counter drop
 }
}`)
					r.start()
					time.Sleep(3 * time.Second)
					// Drain the failed refresh. SIGKILL here would deliberately
					// leave an interrupted-refresh marker and require reinstallation,
					// which is a different case from rearming retained peers.
					r.watch.terminate(t)
					out, err := r.call("inspect", -1, 0)
					report["cached_only_expired_inspection"] = json.RawMessage(out)
					if err == nil {
						t.Fatal("cached approval rearmed expired 8-endpoint deployment")
					}
					if rules := netOutput(t, r.ns, "nft", "list", "table", "inet", "scale_outage"); strings.Contains(rules, "counter packets 0 bytes 0") {
						t.Fatal("8-endpoint HTTP outage not exercised")
					}
					netOutput(t, r.ns, "nft", "delete", "table", "inet", "scale_outage")
				}
				r.start()
				r.ready() // only a new authenticated response can rearm.
				if size == 32 && endpoints == 8 {
					report["interrupted_refresh"] = checkM3InterruptedApproval(t, r)
				}
				r.watch.terminate(t)
				for ep := 0; ep < endpoints; ep++ {
					r.require("release", ep, 0)
				}
				if got := netOutput(t, ns[1], "wg", "show", "interfaces"); got != "" {
					t.Fatal("release retained interfaces", got)
				}
				report["kernel_peers"] = size * 4
				report["completed"] = true
				t.Log("nodes", strconv.Itoa(size), "endpoints", endpoints, "max cycle ms", maxCycle, "results", results)
			})
		}
	}
}
