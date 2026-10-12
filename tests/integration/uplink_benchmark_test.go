//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"
)

type uplinkFixture struct {
	robot            string
	relays           []string
	endpointPort     int
	logs             map[string]string
	roles            map[string]any
	version, profile string
	primary          func() error
	paths            []uplinkPath
	selection        func() map[string]string
}

func vpnctlUplinkFixture(t *testing.T, paths int, robot, server *capacityGroup, resultDir string) *uplinkFixture {
	a := applicationFixtureWithGroup(t, true, paths, false, robot.file)
	uplinkControlPath(t, a.robot, a.controller.ns)
	f := &uplinkFixture{robot: a.robot, endpointPort: 51820, logs: map[string]string{}, roles: map[string]any{}, version: "vpnctl; exact build identity in runner manifest", profile: "watch=500ms; other target policy defaults unchanged"}
	for _, p := range a.plan.Paths {
		f.paths = append(f.paths, uplinkPath{ID: p.PathID, Interface: p.Pin.WGInterface, Relay: int(p.PathID[1] - '0'), Underlay: int(p.PathID[2] - '0'), Port: 51820 + int(p.PathID[2]-'0')})
	}
	f.selection = func() map[string]string {
		out := map[string]string{}
		for target, log := range f.logs {
			r := latestApplicationResult(log)
			out[target] = r.Selection.DesiredPathID
			if !r.Applied {
				out[target] = "not_applied"
			}
		}
		return out
	}
	for i, r := range a.recipients {
		f.relays = append(f.relays, r.ns)
		f.roles[fmt.Sprintf("relay%d", i)] = server.placement(t, r.watch.cmd.Process.Pid)
	}
	f.roles["controller"] = server.placement(t, a.controller.process.cmd.Process.Pid)
	f.roles["supervisor"] = robot.placement(t, a.nodeSupervisor.cmd.Process.Pid)
	for _, target := range []string{"app", "app2"} {
		log := filepath.Join(resultDir, target+".jsonl")
		f.logs[target] = log
		p := startNetworkProcessInGroup(t, robot.file, a.robot, log, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", a.node, "--target-id", target, "--watch", "--interval", "500ms")
		f.roles[target] = robot.placement(t, p.cmd.Process.Pid)
	}
	eventually(t, 90*time.Second, "both applications on primary", func() error {
		for _, log := range f.logs {
			r := latestApplicationResult(log)
			if !r.Applied || r.Selection.DesiredPathID != "p00" {
				return fmt.Errorf("primary not active")
			}
		}
		return nil
	})
	return f
}

func uplinkResources(t *testing.T, g *capacityGroup) map[string]any {
	out := g.evidence(t)
	for _, name := range []string{"memory.current", "memory.peak", "memory.events"} {
		b, e := os.ReadFile(filepath.Join(g.path, name))
		if e != nil || len(b) == 0 {
			t.Fatal("missing role memory evidence", name, e)
		}
		out[name] = strings.TrimSpace(string(b))
	}
	return out
}

func TestVMUplinkBenchmark(t *testing.T) {
	if os.Getenv("VPNCTL_UPLINK_TRANSPORT") == "" {
		t.Skip("explicit comparison VM only")
	}
	requireIsolatedGuest(t)
	if runtime.NumCPU() != 2 {
		t.Fatal("comparison needs two guest CPUs")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("missing build identity")
	}
	for _, s := range info.Settings {
		if s.Key == "-race" && s.Value == "true" {
			t.Fatal("comparison requires non-race build")
		}
	}
	transport := os.Getenv("VPNCTL_UPLINK_TRANSPORT")
	paths, e := strconv.Atoi(os.Getenv("VPNCTL_UPLINK_PATHS"))
	if e != nil || paths != 4 && paths != 8 || transport != "vpnctl" && transport != "openvpn" {
		t.Fatal("invalid comparison profile")
	}
	// Only the identity-guarded guest's cgroup root is touched.
	if e := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory"), 0600); e != nil {
		t.Fatal(e)
	}
	faults := []string{"link-down", "endpoint-drop", "relay-drop", "uplink-drop", "last-endpoint-only"}
	if transport == "vpnctl" {
		faults = append(faults, "app1-last-path")
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) { runUplinkTrial(t, transport, paths, fault) })
	}
}

func runUplinkTrial(t *testing.T, transport string, paths int, fault string) {
	dir, e := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "uplink-")
	if e != nil {
		t.Fatal(e)
	}
	report := map[string]any{"schema_version": 1, "transport": transport, "paths": paths, "fault": fault, "completed": false, "phase": "setup", "race": false}
	t.Cleanup(func() {
		report["completed"] = !t.Failed() && report["phase"] == "measured"
		writeM3Report(t, filepath.Join(dir, "uplink.json"), report)
	})
	server := newCapacityGroup(t, "1", "1")
	server.scope = "controller-relays-and-measurement"
	server.moveWorker(t)
	robot := newCapacityGroup(t, "0.5", "0")
	robot.scope = "robot-transport-and-controllers"
	var f *uplinkFixture
	if transport == "vpnctl" {
		f = vpnctlUplinkFixture(t, paths, robot, server, dir)
	} else {
		f = openVPNUplinkFixture(t, paths, robot, server, dir)
	}
	report["profile"], report["version"], report["role_placement"] = f.profile, f.version, f.roles
	trace := filepath.Join(dir, "traffic.jsonl")
	worker, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	sampler := startNetworkProcess(t, f.robot, filepath.Join(dir, "traffic.log"), []string{"VPNCTL_UPLINK_TRACE=" + trace}, worker, "-test.run=^TestUplinkTrafficWorker$", "-test.timeout=8m")
	report["sampler_placement"] = server.placement(t, sampler.cmd.Process.Pid)
	report["measurement_placement"] = server.placement(t, os.Getpid())
	report["phase"] = "baseline"
	eventually(t, 20*time.Second, "initial application payload", func() error {
		rows := readUplinkTrace(t, trace)
		latest := map[string]uplinkSample{}
		for _, r := range rows {
			latest[r.Kind] = r
		}
		for _, kind := range []string{"app", "app2", "existing"} {
			r := latest[kind]
			if !r.OK || r.Relay != "r0" || managerMono()-r.End > int64(2*time.Second) {
				return fmt.Errorf("initial payload not verified")
			}
		}
		return nil
	})
	baseline := managerMono()
	report["baseline_start_ns"] = baseline
	report["robot_before"], report["server_before"] = uplinkResources(t, robot), uplinkResources(t, server)
	time.Sleep(10 * time.Second)
	rows := readUplinkTrace(t, trace)
	for _, kind := range []string{"app", "app2", "existing"} {
		count := 0
		last := baseline
		for _, r := range rows {
			if r.Kind == kind && r.Begin >= baseline {
				count++
				last = r.End
				if !r.OK || r.Relay != "r0" {
					report["samples"] = rows
					t.Fatal("unhealthy baseline")
				}
			}
		}
		if count < 20 || managerMono()-last > int64(2*time.Second) {
			report["samples"] = rows
			t.Fatal("incomplete baseline")
		}
	}
	// Ensure an unexpected initial selector change cannot alter which fault is injected.
	if transport == "vpnctl" {
		for _, log := range f.logs {
			r := latestApplicationResult(log)
			if !r.Applied || r.Selection.DesiredPathID != "p00" {
				t.Fatal("baseline primary changed")
			}
		}
	} else if err := f.primary(); err != nil {
		t.Fatal("baseline primary changed", err)
	}
	report["phase"] = "injecting"
	begin := managerMono()
	report["fault_begin_ns"] = begin
	injectUplinkFault(t, f, fault)
	end := managerMono()
	stop := end + int64(45*time.Second)
	report["fault_begin_ns"], report["fault_end_ns"], report["window_end_ns"] = begin, end, stop
	report["phase"] = "observing"
	report["fault_rules_before"] = uplinkFaultEvidence(t, f, fault)
	report["fault_rules_before_observed_ns"] = managerMono()
	time.Sleep(time.Duration(max(int64(0), stop-managerMono())))
	mustWrite(t, trace+".stop", "stop")
	sampler.finish(t)
	rows = readUplinkTrace(t, trace)
	report["fault_rules_after"] = uplinkFaultEvidence(t, f, fault)
	report["fault_rules_after_observed_ns"] = managerMono()
	report["final_selection_begin_ns"] = managerMono()
	report["final_selection"] = f.selection()
	report["final_selection_end_ns"] = managerMono()
	report["candidate_ids"] = f.paths
	report["samples"] = rows
	report["robot_after"], report["server_after"] = uplinkResources(t, robot), uplinkResources(t, server)
	metrics := map[string]uplinkMetric{}
	report["metrics"] = metrics
	for _, kind := range []string{"app", "app2", "existing"} {
		m, err := measureUplink(rows, kind, baseline, begin, end, stop)
		if err != nil {
			t.Fatal("invalid metric evidence", kind, err)
		}
		metrics[kind] = m
		if m.BaselineFailures != 0 || m.BaselineSamples < 20 || m.MaxSchedulingGap > int64(2*time.Second) {
			t.Error("incomplete or unhealthy sampling", kind)
		}
	}
	report["phase"] = "measured"
}

// The link-down fault concerns data underlay only. Keep controller reachability
// separate, with forwarding disabled there, so this is not also approval loss.
func uplinkControlPath(t *testing.T, robot, controller string) {
	netOutput(t, robot, "ip", "link", "add", "benchctl0", "type", "veth", "peer", "name", "benchctl0", "netns", controller)
	for _, v := range []struct{ ns, addr string }{{robot, "198.18.10.1/30"}, {controller, "198.18.10.2/30"}} {
		netOutput(t, v.ns, "ip", "addr", "add", v.addr, "dev", "benchctl0")
		netOutput(t, v.ns, "ip", "link", "set", "benchctl0", "up")
	}
	netOutput(t, robot, "ip", "route", "add", "192.0.2.254/32", "via", "198.18.10.2", "dev", "benchctl0")
	// Existing controller TCP sessions can retain the original underlay source.
	netOutput(t, controller, "ip", "route", "add", "192.0.2.10/32", "via", "198.18.10.1", "dev", "benchctl0")
}
