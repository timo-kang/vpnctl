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
	"vpnctl/internal/relayplan"
)

func applicationFixture(t *testing.T, separate bool, size int) *m3AuthorityFixture {
	t.Helper()
	underlays := 2
	if size == 8 {
		underlays = 4
	}
	f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: separate, independentRecipients: true, underlays: underlays, extraTarget: true})
	cpuBefore, _ := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	memoryBefore, _ := os.ReadFile("/sys/fs/cgroup/memory.events")
	t.Cleanup(func() {
		cpuAfter, _ := os.ReadFile("/sys/fs/cgroup/cpu.stat")
		memoryAfter, _ := os.ReadFile("/sys/fs/cgroup/memory.events")
		cpuLimit, _ := os.ReadFile("/sys/fs/cgroup/cpu.max")
		writeM3Report(t, filepath.Join(f.results, "application-kernel.json"), map[string]string{
			"cpu_stat_before": string(cpuBefore), "cpu_stat_after": string(cpuAfter), "cpu_limit": string(cpuLimit),
			"memory_events_before": string(memoryBefore), "memory_events_after": string(memoryAfter),
			"rules":             netOutput(t, f.robot, "ip", "-j", "-N", "-4", "rule", "show"),
			"routes":            netOutput(t, f.robot, "ip", "-j", "-N", "-4", "route", "show", "table", "all"),
			"rp_filter":         netOutput(t, f.robot, "cat", "/proc/sys/net/ipv4/conf/all/rp_filter"),
			"robot_neighbours":  netOutput(t, f.robot, "ip", "-j", "neigh", "show"),
			"target_neighbours": netOutput(t, f.target, "ip", "-j", "neigh", "show"),
			"counters":          netOutput(t, f.robot, "cat", "/proc/net/netstat"),
		})
	})
	f.releaseNodeCandidates()
	// Only this fixture-owned robot namespace; physical interfaces keep their own
	// reverse-path policy. No host/global sysctl is changed.
	netOutput(t, f.robot, "sh", "-c", "mount -t proc proc /proc && printf 0 > /proc/sys/net/ipv4/conf/all/rp_filter && printf 0 > /proc/sys/net/ipv4/conf/default/rp_filter")
	f.plan.Paths = f.plan.Paths[:size]
	for _, p := range f.plan.Paths {
		netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", p.PathID, "--app-routes")
	}
	startNodeLeaseWatch(t, f, "application-node-supervisor")
	awaitApplicationCandidates(t, f)
	for _, target := range []string{"app", "app2"} {
		nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", target)
	}
	return f
}
func applicationPayload(t *testing.T, f *m3AuthorityFixture, target string) m3Probe {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := netCommand(ctx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE=", "VPNCTL_PROBE_INTERFACE=", "VPNCTL_PROBE_TARGET="+target)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("unbound payload worker", err, string(b))
	}
	for _, line := range strings.Split(string(b), "\n") {
		var p m3Probe
		if json.Unmarshal([]byte(line), &p) == nil && strings.Contains(line, `"ok"`) {
			return p
		}
	}
	t.Fatal("missing unbound payload result", string(b))
	return m3Probe{}
}
func applicationCandidate(t *testing.T, f *m3AuthorityFixture, p relayplan.Candidate) m3Probe {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := netCommand(ctx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE="+strings.TrimSuffix(p.InnerAddress, "/32"), "VPNCTL_PROBE_INTERFACE="+p.Pin.WGInterface)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(b))
	}
	for _, line := range strings.Split(string(b), "\n") {
		var result m3Probe
		if json.Unmarshal([]byte(line), &result) == nil && strings.Contains(line, `"ok"`) {
			return result
		}
	}
	t.Fatal("missing bound probe result", string(b))
	return m3Probe{}
}
func awaitApplicationCandidates(t *testing.T, f *m3AuthorityFixture) {
	t.Helper()
	eventually(t, 20*time.Second, "device-bound candidate lease", func() error {
		for _, p := range f.plan.Paths {
			if !applicationCandidate(t, f, p).OK {
				return fmt.Errorf("%s blocked: %+v", p.PathID, applicationCandidate(t, f, p))
			}
		}
		return nil
	})
}
func applicationReconcile(t *testing.T, f *m3AuthorityFixture, target string, success bool, extra ...string) relayapply.TargetReconcileResult {
	t.Helper()
	if success {
		// A finite two-attempt CLI invocation can legitimately consume an
		// attempt on lock admission. Exercise operational convergence with one
		// continuous selector instead of assuming both attempts observed paths.
		log, err := os.CreateTemp(f.results, "reconcile-"+target+"-*.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		args := []string{integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", target, "--watch", "--interval", "500ms"}
		watch := startNetworkProcess(t, f.robot, log.Name(), nil, append(args, extra...)...)
		var out relayapply.TargetReconcileResult
		eventually(t, 90*time.Second, "verified application convergence ("+log.Name()+")", func() error {
			b, err := os.ReadFile(log.Name())
			if err != nil {
				return err
			}
			admitted := 0
			lines := strings.Split(string(b), "\n")
			for _, line := range lines[:len(lines)-1] {
				var result relayapply.TargetReconcileResult
				if json.Unmarshal([]byte(line), &result) != nil || result.SchemaVersion != 1 {
					return fmt.Errorf("invalid application output: %s", line)
				}
				if result.Selection.Reason != "ownership_unavailable" {
					admitted++
				}
				out = result
			}
			if out.Applied {
				if admitted < 2 || !out.Application.Activated || out.Application.Proof == nil {
					t.Fatal("application without completed confirmation and proof", out)
				}
				return nil
			}
			return fmt.Errorf("state=%s reason=%s admitted=%d", out.Application.State, out.Selection.Reason, admitted)
		})
		watch.terminate(t)
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*relayapply.MaxDuration+5*time.Second)
	defer cancel()
	args := []string{integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", target, "--samples", "2", "--interval", "100ms"}
	b, err := netCommand(ctx, f.robot, append(args, extra...)...).CombinedOutput()
	if (err == nil) != success {
		t.Fatal("reconcile result", err, string(b))
	}
	var out relayapply.TargetReconcileResult
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		var r relayapply.TargetReconcileResult
		if json.Unmarshal([]byte(line), &r) == nil && r.SchemaVersion == 1 {
			out = r
			count++
		}
	}
	if count != 2 || out.Applied != success {
		t.Fatal("missing application evidence", string(b))
	}
	return out
}
func TestNetns_M3TargetApplication(t *testing.T) {
	requireNetwork(t)
	for _, placement := range []string{"colocated", "separate"} {
		for _, size := range []int{1, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", placement, size), func(t *testing.T) {
				f := applicationFixture(t, placement == "separate", size)
				if p := applicationPayload(t, f, m3Target); p.OK {
					t.Fatal("reservation failed", p)
				}
				out := applicationReconcile(t, f, "app", true)
				if out.Selection.DesiredPathID != "p00" || !out.Application.Activated || out.Application.Proof == nil {
					t.Fatal(out)
				}
				if p := applicationPayload(t, f, m3Target); !p.OK || p.Source != "198.18.0.11" {
					t.Fatal("wrong relay payload", p)
				}
				other := applicationReconcile(t, f, "app2", true)
				if p := applicationPayload(t, f, "198.18.0.3"); !p.OK || p.Source != "198.18.0.11" {
					t.Fatal("second target payload", p)
				}
				nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "inspect", "--config", f.node, "--target-id", "app")
				if size > 1 {
					out = applicationReconcile(t, f, "app", true, "--mode", "manual", "--path-id", f.plan.Paths[size-1].PathID)
					if p := applicationPayload(t, f, m3Target); !p.OK || p.Source != "198.18.0.12" {
						t.Fatal("manual alternate payload", p)
					}
					if p := applicationPayload(t, f, "198.18.0.3"); !p.OK || p.Source != "198.18.0.11" {
						t.Fatal("other target changed", p)
					}
				}
				// Candidate removal must first quarantine every target referencing it.
				f.nodeCall("release", "p00")
				if p := applicationPayload(t, f, "198.18.0.3"); p.OK {
					t.Fatal("candidate release reopened target", p)
				}
				writeM3Report(t, filepath.Join(f.results, "target-application.json"), map[string]any{"completed": !t.Failed(), "placement": placement, "candidates": size, "app": out, "app2": other, "unbound_payload_and_nat_verified": true, "candidate_release_quarantined": true})
			})
		}
	}
}
