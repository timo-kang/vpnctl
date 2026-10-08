//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayguard"
)

func applicationResults(path string) (out []relayapply.TargetReconcileResult) {
	b, _ := os.ReadFile(path)
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[:len(lines)-1] {
		var r relayapply.TargetReconcileResult
		if json.Unmarshal([]byte(line), &r) == nil && r.SchemaVersion == 1 {
			out = append(out, r)
		}
	}
	return
}

const applicationLogRecordLimit = 256 * 1024

// Polling must not reparse the complete history on every iteration. That makes
// the measuring process consume progressively more of the fixture's CPU quota.
// Read a bounded tail and decode only the newest complete schema-v1 record.
// The separate trace reader still validates and preserves every complete cycle.
func latestApplicationResult(path string) (out relayapply.TargetReconcileResult) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	return readLatestApplicationResult(f, st.Size())
}

func readLatestApplicationResult(r io.ReaderAt, size int64) (out relayapply.TargetReconcileResult) {
	if size <= 0 || size > 32*1024*1024 {
		return
	}
	start := max(int64(0), size-2*applicationLogRecordLimit-1)
	b := make([]byte, size-start)
	n, err := r.ReadAt(b, start)
	if n != len(b) || err != nil && err != io.EOF {
		return
	}
	// A writer may have appended only part of its next JSON record.
	end := bytes.LastIndexByte(b, '\n')
	if end < 0 {
		return
	}
	b = b[:end]
	for len(b) > 0 {
		sep := bytes.LastIndexByte(b, '\n')
		if sep < 0 && start != 0 {
			return // The first bytes of the tail may be a partial record.
		}
		line := b[sep+1:]
		if len(line) > applicationLogRecordLimit {
			return
		}
		var v relayapply.TargetReconcileResult
		if json.Unmarshal(line, &v) == nil && v.SchemaVersion == 1 {
			return v
		}
		if sep < 0 {
			break
		}
		b = b[:sep]
	}
	return
}

// Count real applied cycles after the baseline, rejecting a gap before any
// later recovery can hide it. Payload alone can pass while an observer stalls.
func applicationContinuity(t *testing.T, path string, baseline int) (cycles int, maxGap time.Duration) {
	t.Helper()
	cycles, maxGap, err := evaluateApplicationContinuity(applicationResults(path), baseline, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return cycles, maxGap
}

func evaluateApplicationContinuity(results []relayapply.TargetReconcileResult, baseline int, now time.Time) (cycles int, maxGap time.Duration, err error) {
	if baseline < 1 || baseline > len(results) {
		return 0, 0, fmt.Errorf("missing application continuity baseline")
	}
	// Consecutive record gaps cannot detect an observer that stops writing.
	// Leases and payload may remain live while its final observation expires.
	latest := results[len(results)-1].Selection
	fresh := false
	for _, c := range latest.Candidates {
		if c.PathID == latest.DesiredPathID && c.Eligible && c.State == "reachable" && !c.ObservedAt.IsZero() {
			age := now.Sub(c.ObservedAt)
			fresh = age >= 0 && age <= 10*time.Second
		}
	}
	if !fresh {
		return 0, 0, fmt.Errorf("latest selected-path observation missing or stale: target=%s", latest.TargetID)
	}
	for i := max(0, baseline-1); i < len(results); i++ {
		r := results[i]
		if !r.Applied || r.Selection.Policy.MaxAge != 10*time.Second || r.Selection.Policy.Successes != 2 {
			return cycles, maxGap, fmt.Errorf("application lost fresh continuous eligibility: target=%s reason=%s state=%s", r.Selection.TargetID, r.Selection.Reason, r.Application.State)
		}
		if i < baseline {
			continue
		}
		cycles++
		previous := results[i-1]
		for _, c := range r.Selection.Candidates {
			if !c.Eligible {
				continue
			}
			for _, old := range previous.Selection.Candidates {
				if old.PathID == c.PathID && old.State == "reachable" {
					gap := c.ObservedAt.Sub(old.ObservedAt)
					maxGap = max(maxGap, gap)
					if gap <= 0 || gap > 10*time.Second {
						return cycles, maxGap, fmt.Errorf("freshness gap %s in %s", gap, c.PathID)
					}
				}
			}
		}
	}
	return
}
func requireLiveApplicationLeases(t *testing.T, f *m3AuthorityFixture) {
	requireApplicationLeasesExcept(t, f, "")
}
func requireApplicationLeasesExcept(t *testing.T, f *m3AuthorityFixture, excluded string) {
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
		if p.PathID == excluded {
			continue
		}
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
		t.Run(fmt.Sprint(healthy), func(t *testing.T) { applicationMixedCandidates(t, healthy, false) })
	}
}

func TestNetns_M3PreparationCapacity(t *testing.T) {
	requireNetwork(t)
	for _, healthy := range []int{0, 3, 7} {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) { applicationMixedCandidates(t, healthy, true) })
	}
}

func applicationMixedCandidates(t *testing.T, healthy int, rebuild bool) {
	applicationMixedCandidatesProfile(t, healthy, rebuild, 8, "", "shared")
}

func applicationMixedCandidatesProfile(t *testing.T, healthy int, rebuild bool, paths int, robotCPU, layout string) {
	var group, serverGroup *capacityGroup
	robotCPUs := ""
	if layout == "split" {
		serverGroup = newCapacityGroup(t, "1", "1")
		serverGroup.scope = "controller-relays-and-measurement"
		serverGroup.moveWorker(t)
		robotCPUs = "0"
	}
	var groupFD *os.File
	if robotCPU != "" {
		group = newCapacityGroup(t, robotCPU, robotCPUs)
		groupFD = group.file
	}
	f := applicationFixtureWithGroup(t, true, paths, false, groupFD)
	managed := map[string]relayapply.PreparationStatus{}
	if rebuild {
		for _, p := range f.plan.Paths {
			managed[p.PathID] = enablePreparation(t, f, p.PathID)
		}
	}
	cgroup := func(name string) string { b, _ := os.ReadFile(filepath.Join("/sys/fs/cgroup", name)); return string(b) }
	report := map[string]any{"healthy_index": healthy, "healthy_path": f.plan.Paths[healthy].PathID, "cpu_stat_before": cgroup("cpu.stat"), "memory_events_before": cgroup("memory.events")}
	if group != nil {
		report["resource_profile"] = group.evidence(t)
	}
	if serverGroup != nil {
		report["server_resource_profile"] = serverGroup.evidence(t)
	}
	t.Cleanup(func() {
		defer func() {
			report["completed"] = !t.Failed()
			writeM3Report(t, filepath.Join(f.results, "application-mixed-candidates.json"), report)
		}()
		report["cpu_stat_after"] = cgroup("cpu.stat")
		report["memory_events_after"] = cgroup("memory.events")
		if group != nil {
			report["resource_profile_after"] = group.evidence(t)
		}
		if serverGroup != nil {
			report["server_resource_profile_after"] = serverGroup.evidence(t)
		}
	})
	secondLog := filepath.Join(f.results, "capacity-app2.jsonl")
	secondMode := "auto"
	secondArgs := []string{integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", "app2", "--watch", "--interval", "500ms"}
	if rebuild {
		secondMode = "manual"
		secondArgs = append(secondArgs, "--mode", "manual", "--path-id", f.plan.Paths[healthy].PathID)
	}
	report["actuator_modes"] = map[string]string{"app": "auto", "app2": secondMode}
	second := startNetworkProcessInGroup(t, groupFD, f.robot, secondLog, nil, secondArgs...)
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
	watcher := startNetworkProcessInGroup(t, groupFD, f.robot, logfile, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", "app", "--watch", "--interval", "500ms", "--probe-timeout", "2s")
	var placement func() map[string]any
	if group != nil {
		for _, p := range []*networkProcess{f.nodeSupervisor, watcher, second} {
			group.requireMembership(t, p.cmd.Process.Pid, true)
		}
		group.requireMembership(t, os.Getpid(), false)
		group.requireMembership(t, f.controller.process.cmd.Process.Pid, false)
		for _, r := range f.recipients {
			group.requireMembership(t, r.watch.cmd.Process.Pid, false)
		}
		if serverGroup != nil {
			placement = func() map[string]any {
				roles := map[string]any{}
				for name, p := range map[string]*networkProcess{"supervisor": f.nodeSupervisor, "app": watcher, "app2": second} {
					roles[name] = group.placement(t, p.cmd.Process.Pid)
				}
				roles["measurement"] = serverGroup.placement(t, os.Getpid())
				roles["controller"] = serverGroup.placement(t, f.controller.process.cmd.Process.Pid)
				for i, r := range f.recipients {
					roles[fmt.Sprintf("relay%d", i)] = serverGroup.placement(t, r.watch.cmd.Process.Pid)
				}
				return roles
			}
			report["role_cpu_placement"] = placement()
			// Runs before process cleanup so every live role can be checked.
			t.Cleanup(func() {
				if report["role_cpu_placement_after"] == nil {
					report["role_cpu_placement_after"] = placement()
				}
			})
		}
		report["role_placement_verified"] = true
	}
	// A payload can detect quarantine before the current reconcile finishes
	// writing its diagnostic row. Preserve that bounded cycle before automatic
	// process cleanup; the original failure remains a failure even if it recovers.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		at := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		capture := func(args ...string) string {
			b, err := netCommand(ctx, f.robot, args...).CombinedOutput()
			return fmt.Sprintf("%s\nerror=%v", b, err)
		}
		diagnostic := map[string]any{"observed_at": at, "wait_limit_ms": 10000,
			"routes": capture("ip", "-j", "-N", "-4", "route", "show", "table", "all"),
			"nft":    capture("nft", "-j", "list", "ruleset")}
		report["failure_diagnostics"] = diagnostic
		for ctx.Err() == nil {
			app, app2 := latestApplicationResult(logfile), latestApplicationResult(secondLog)
			diagnostic["app"], diagnostic["app2"] = app, app2
			if app.FinishedAt.After(at) && app2.FinishedAt.After(at) {
				diagnostic["cycles_completed"] = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		diagnostic["finished_at"] = time.Now()
	})
	// Sample the actual three long-lived workers. The short qualification is
	// not an indefinite leak proof; record peaks and enforce a generous bound
	// inside the unchanged 2 GiB container allowance for both build profiles.
	type resourcePeak struct {
		FD    int `json:"fd"`
		RSSKB int `json:"rss_kb"`
	}
	peaks := map[string]resourcePeak{}
	sampleResources := func() {
		if !rebuild {
			return
		}
		for name, p := range map[string]*networkProcess{"supervisor": f.nodeSupervisor, "app": watcher, "app2": second} {
			base := filepath.Join("/proc", strconv.Itoa(p.cmd.Process.Pid))
			fds, err := os.ReadDir(filepath.Join(base, "fd"))
			if err != nil {
				t.Fatal("worker fd inventory", err)
			}
			status, err := os.ReadFile(filepath.Join(base, "status"))
			if err != nil {
				t.Fatal("worker memory inventory", err)
			}
			rss := 0
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					if _, err := fmt.Sscanf(line, "VmRSS: %d kB", &rss); err != nil {
						t.Fatal(err)
					}
				}
			}
			if rss <= 0 || rss > 512*1024 || len(fds) > 128 {
				t.Fatal("worker resource bound", name, len(fds), rss)
			}
			peak := peaks[name]
			peak.FD, peak.RSSKB = max(peak.FD, len(fds)), max(peak.RSSKB, rss)
			peaks[name] = peak
		}
		report["worker_resource_peaks"] = peaks
	}
	var applied relayapply.TargetReconcileResult
	samples := 0
	eventually(t, 45*time.Second, "healthy path among seven slow paths", func() error {
		sampleResources()
		requireLiveApplicationLeases(t, f)
		if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
			report["payload_failure"] = map[string]any{"target": "198.18.0.3", "probe": p}
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
		if healthy >= paths/2 {
			source = "198.18.0.12"
		}
		if !p.OK || p.Source != source {
			return fmt.Errorf("wrong actual app path: %+v", p)
		}
		applied = r
		return nil
	})
	report["first_payload_seconds"] = time.Since(started).Seconds()
	// Exercise several complete rounds, not just residual leases after
	// activation. Preserve continuous payload/lease sampling throughout.
	steadyStart := time.Now()
	baseline1, baseline2 := len(applicationResults(logfile)), len(applicationResults(secondLog))
	broken := ""
	repaired := !rebuild
	if rebuild {
		p := f.plan.Paths[(healthy+1)%len(f.plan.Paths)]
		broken = p.PathID
		netOutput(t, f.robot, "ip", "route", "del", p.Pin.EndpointPrefix, "table", strconv.Itoa(int(p.Pin.Table)))
	}
	cycles1, cycles2 := 0, 0
	var gap1, gap2 time.Duration
	limit := 45 * time.Second
	minimum := 15 * time.Second
	if rebuild {
		limit = 120 * time.Second
		if robotCPU != "" {
			minimum = 60 * time.Second
		}
	}
	for time.Since(steadyStart) < minimum || cycles1 < 3 || cycles2 < 3 || !repaired {
		if time.Since(steadyStart) > limit {
			t.Fatalf("steady qualification did not converge: app=%d app2=%d rebuilt=%t", cycles1, cycles2, repaired)
		}
		sampleResources()
		cycles1, gap1 = applicationContinuity(t, logfile, baseline1)
		cycles2, gap2 = applicationContinuity(t, secondLog, baseline2)
		if rebuild && !repaired {
			current := latestPreparation(filepath.Join(f.results, "application-node-supervisor.jsonl"), broken)
			if current.Phase == "ready" && current.Current != nil && current.Current.Owner != managed[broken].Current.Owner {
				// Ready is initially closed; wait for an authenticated rearm.
				for _, p := range f.plan.Paths {
					if p.PathID == broken {
						repaired = applicationCandidateTarget(t, f, p, "198.18.0.3").OK
					}
				}
			}
			if repaired {
				report["rebuild_seconds"] = time.Since(steadyStart).Seconds()
			}
		}
		if repaired {
			requireLiveApplicationLeases(t, f)
		} else {
			requireApplicationLeasesExcept(t, f, broken)
		}
		for _, target := range []string{m3Target, "198.18.0.3"} {
			if p := applicationPayload(t, f, target); !p.OK {
				report["payload_failure"] = map[string]any{"target": target, "probe": p}
				t.Fatal("steady mixed app failed", target, p)
			}
		}
		samples++
		time.Sleep(200 * time.Millisecond)
	}
	cycles1, gap1 = applicationContinuity(t, logfile, baseline1)
	cycles2, gap2 = applicationContinuity(t, secondLog, baseline2)
	report["steady_seconds"] = time.Since(steadyStart).Seconds()
	report["steady_applied_cycles"] = map[string]int{"app": cycles1, "app2": cycles2}
	report["maximum_fresh_observation_gap_seconds"] = map[string]float64{"app": gap1.Seconds(), "app2": gap2.Seconds()}
	report["samples"] = samples
	report["result"] = applied
	report["paths"] = paths
	report["all_candidate_leases_active"] = true
	if paths == 8 {
		report["all_eight_leases_active"] = true
	}
	report["automatic_rebuild"] = rebuild
	if rebuild {
		report["rebuilt_path"] = broken
		report["rebuild_completed"] = repaired
	}
	report["two_actuators_and_payloads_verified"] = true
	counters := netOutput(t, f.robot, "nft", "list", "table", "inet", "capacity_slow")
	if strings.Count(counters, "counter packets ") != paths-1 || strings.Contains(counters, "counter packets 0 bytes 0") {
		t.Fatal("not all slow paths exercised", counters)
	}
	report["fault_counters"] = counters
	if placement != nil {
		report["role_cpu_placement_after"] = placement()
	}
	watcher.terminate(t)
	second.terminate(t)
}
