//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
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

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayguard"
)

func latestApplicationResult(path string) (out relayapply.TargetReconcileResult) {
	b, _ := os.ReadFile(path)
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[:len(lines)-1] {
		var r relayapply.TargetReconcileResult
		if json.Unmarshal([]byte(line), &r) == nil && r.SchemaVersion == 1 {
			out = r
		}
	}
	return
}
func requireLiveApplicationLeases(t *testing.T, f *m3AuthorityFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := netCommand(ctx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_WORKER=boot-guard-snapshot")
	b, err := cmd.Output()
	if err != nil {
		t.Fatal("guard sampling", err)
	}
	states := map[string]struct {
		State relayguard.State `json:"state"`
		Error string           `json:"error"`
	}{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "BOOTTIME_GUARDS=") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "BOOTTIME_GUARDS=")), &states); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, p := range f.plan.Paths {
		s, ok := states[p.Pin.WGInterface]
		if !ok || s.Error != "" || !s.State.Active {
			t.Fatalf("lease starved %s: %+v", p.PathID, s)
		}
	}
}

// A healthy path must remain usable regardless of its catalog position while
// seven other TCP paths consume the full timeout and a second actuator competes.
func TestNetns_M3TargetApplicationMixedCandidates(t *testing.T) {
	requireNetwork(t)
	for _, healthy := range []int{0, 3, 7} {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) {
			f := applicationFixture(t, true, 8)
			cgroup := func(name string) string { b, _ := os.ReadFile(filepath.Join("/sys/fs/cgroup", name)); return string(b) }
			report := map[string]any{"healthy_index": healthy, "healthy_path": f.plan.Paths[healthy].PathID, "cpu_stat_before": cgroup("cpu.stat"), "memory_events_before": cgroup("memory.events")}
			t.Cleanup(func() {
				report["completed"] = !t.Failed()
				report["cpu_stat_after"] = cgroup("cpu.stat")
				report["memory_events_after"] = cgroup("memory.events")
				writeM3Report(t, filepath.Join(f.results, "application-mixed-candidates.json"), report)
			})
			secondLog := filepath.Join(f.results, "capacity-app2.jsonl")
			second := startNetworkProcess(t, f.robot, secondLog, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", "app2", "--watch", "--interval", "500ms")
			eventually(t, 45*time.Second, "independent app activated", func() error {
				r := latestApplicationResult(secondLog)
				if !r.Applied {
					return fmt.Errorf("app2 %s", r.Selection.Reason)
				}
				return nil
			})
			fault := "table inet capacity_slow {\n chain output { type filter hook output priority 0; policy accept;\n"
			for i, p := range f.plan.Paths {
				if i != healthy {
					fault += fmt.Sprintf("oifname %q ip daddr %s ip protocol tcp counter drop\n", p.Pin.WGInterface, m3Target)
				}
			}
			fault += "}\n}\n"
			(relayUplink{relay: f.robot}).nft(t, fault)
			started := time.Now()
			report["fault_installed_at"] = started
			logfile := filepath.Join(f.results, "capacity-app.jsonl")
			watcher := startNetworkProcess(t, f.robot, logfile, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", "app", "--watch", "--interval", "500ms", "--probe-timeout", "2s")
			var applied relayapply.TargetReconcileResult
			samples := 0
			eventually(t, 45*time.Second, "healthy path among seven slow paths", func() error {
				requireLiveApplicationLeases(t, f)
				if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
					t.Fatal("mixed observation interrupted independent app", p)
				}
				samples++
				r := latestApplicationResult(logfile)
				if !r.Applied {
					return fmt.Errorf("app %s", r.Selection.Reason)
				}
				if r.Selection.DesiredPathID != f.plan.Paths[healthy].PathID {
					t.Fatal("selected blackholed path", r)
				}
				for _, c := range r.Selection.Candidates {
					if c.PathID != r.Selection.DesiredPathID && c.Eligible {
						t.Fatal("slow path admitted", c)
					}
				}
				p := applicationPayload(t, f, m3Target)
				source := "198.18.0.11"
				if healthy >= 4 {
					source = "198.18.0.12"
				}
				if !p.OK || p.Source != source {
					return fmt.Errorf("wrong actual app path: %+v", p)
				}
				applied = r
				return nil
			})
			report["first_payload_seconds"] = time.Since(started).Seconds()
			// Keep both operational loops and all leases under pressure after first success.
			until := time.Now().Add(5 * time.Second)
			for time.Now().Before(until) {
				requireLiveApplicationLeases(t, f)
				for _, target := range []string{m3Target, "198.18.0.3"} {
					if p := applicationPayload(t, f, target); !p.OK {
						t.Fatal("steady mixed app failed", target, p)
					}
				}
				samples++
				time.Sleep(200 * time.Millisecond)
			}
			report["samples"] = samples
			report["result"] = applied
			report["all_eight_leases_active"] = true
			report["two_actuators_and_payloads_verified"] = true
			counters := netOutput(t, f.robot, "nft", "list", "table", "inet", "capacity_slow")
			if strings.Count(counters, "counter packets ") != 7 || strings.Contains(counters, "counter packets 0 bytes 0") {
				t.Fatal("not all seven slow paths exercised", counters)
			}
			report["fault_counters"] = counters
			watcher.terminate(t)
			second.terminate(t)
		})
	}
}
