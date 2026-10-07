//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
)

func runManagerAutoScenarios(t *testing.T, f *m3AuthorityFixture, report map[string]any, logs map[string]string, watchers map[string]*networkProcess, startWatch func(string) *networkProcess, configDigests map[string]string, snapshot func() map[string]any, size int, lanNS map[string]string) {
	t.Helper()
	report["clock"] = "CLOCK_MONOTONIC; same guest boot; excludes suspend; not authorization evidence"
	report["mode"] = "automatic"
	report["policy"] = map[string]any{"successes": 2, "hold_down_ms": 10000, "minimum_dwell_ms": 15000, "interval_ms": 500, "probe_timeout_ms": 1000}
	report["existing_tcp_contract"] = "fresh socket before each applicable fault, no reconnect within that phase; explicit session IDs; nonce framing survives partial reads/timeouts; server idle limit 30 minutes"
	report["slo_contract"] = "individual failover/no-uplink limit 10s; nearest-rank p95 requires at least 20 measured transitions per class/profile; incomplete samples never qualify"
	report["no_uplink_scope"] = "all permitted candidates failed for this server target (no_verified_path); guarded unknown/blocked state is not conclusive no-uplink evidence or physical-link diagnosis"
	// Below all owned application guards, above main. Preserve the VM's
	// management default route; a foreign specific route is rightly a conflict.
	applicationFallbackRoute(t, f, "table", "65002")
	managerCommand(t, "ip", "rule", "add", "priority", "32760", "to", m3Target+"/32", "table", "65002")
	// The inherited deployment fixture permits only its TCP echo port. Add
	// this UDP test service to that fixture policy; product ACL/lease guards
	// still run first and are not changed.
	for i, relay := range f.recipients {
		deployment := relay.require("inspect", -1, 0)
		for _, endpoint := range deployment.Endpoints {
			netOutput(t, relay.ns, "nft", "add", "rule", "ip", "m3", "forward", "iifname", endpoint.Interface, "oifname", "uplink0", "ip", "daddr", m3Target, "udp", "dport", "9193", "accept")
		}
		netOutput(t, relay.ns, "nft", "add", "rule", "ip", "m3", "postrouting", "oifname", "uplink0", "ip", "saddr", "10.78.0.0/16", "ip", "daddr", m3Target, "udp", "dport", "9193", "snat", "to", fmt.Sprintf("198.18.0.%d", 11+i))
	}
	startNetworkProcess(t, f.target, filepath.Join(f.results, "manager-udp.log"), []string{"VPNCTL_WORKER=manager-udp-echo"}, f.worker, "-test.run=^TestNetworkWorker$")
	// An unrelated VPN policy table and an independently managed firewall table.
	// These are explicit fixture resources, not another VPN implementation.
	managerCommand(t, "ip", "route", "add", "unreachable", "203.0.114.0/24", "table", "65001", "metric", "701")
	managerCommand(t, "ip", "rule", "add", "priority", "32000", "to", "203.0.114.0/24", "table", "65001")
	managerCommand(t, "nft", "add", "table", "inet", "manager_foreign")
	foreignRoutes := managerCommand(t, "ip", "-j", "-N", "route", "show", "table", "65001")
	foreignRules := managerCommand(t, "ip", "-j", "-N", "rule", "show", "priority", "32000")
	// NM activation and fixture link creation publish asynchronous netlink
	// events. Start fault measurements only after all candidates and both apps
	// have a stable, fully confirmed baseline; do not count bootstrap as a fault.
	report["baseline_wait_started_monotonic_ns"] = managerMono()
	barrier := managerBaselineBarrier{after: report["baseline_wait_started_monotonic_ns"].(int64)}
	var stableSince time.Time
	eventually(t, 120*time.Second, "stable automatic baseline", func() error {
		app, independent := latestApplicationResult(logs["app"]), latestApplicationResult(logs["app2"])
		if !barrier.ready(app, independent, size) {
			stableSince = time.Time{}
			return fmt.Errorf("waiting for two fresh ready cycles per application after fixture policy changes")
		}
		if stableSince.IsZero() {
			stableSince = time.Now()
		}
		if time.Since(stableSince) < 3*time.Second {
			return fmt.Errorf("confirming stable baseline")
		}
		return nil
	})
	report["baseline_ready_monotonic_ns"] = managerMono()
	report["baseline_ready_cycles"] = map[string]int{"app": barrier.appSamples, "app2": barrier.otherSamples}
	trace := startManagerAutoTrace(logs)
	t.Cleanup(func() {
		trace.close()
		packets, cycles, err := trace.snapshot()
		report["packets"] = packets
		report["cycles"] = cycles
		report["trace_error"] = err
		report["non_json_log_lines"] = trace.warnings
		if err != "" {
			t.Error(err)
		}
	})
	sourceFor := func(path string) string {
		if strings.HasPrefix(path, "p1") {
			return "198.18.0.12"
		}
		return "198.18.0.11"
	}
	pathSources := map[string]string{}
	for _, p := range f.plan.Paths {
		pathSources[p.PathID] = sourceFor(p.PathID)
	}
	integrity := func() {
		for path, digest := range configDigests {
			if managerDigest(t, path) != digest {
				t.Fatal("external configuration changed", path)
			}
		}
		if managerCommand(t, "ip", "-j", "-N", "route", "show", "table", "65001") != foreignRoutes || managerCommand(t, "ip", "-j", "-N", "rule", "show", "priority", "32000") != foreignRules {
			t.Fatal("foreign VPN policy changed")
		}
		managerCommand(t, "nft", "list", "table", "inet", "manager_foreign")
	}
	evidence := func(out relayapply.TargetReconcileResult) map[string]any {
		g := out.Application.Reservation
		if g == nil || g.Active == nil {
			t.Fatal("applied route identity missing")
		}
		route := managerCommand(t, "ip", "-j", "-N", "route", "get", m3Target)
		var v []struct {
			Dev    string `json:"dev"`
			Source string `json:"prefsrc"`
		}
		if err := json.Unmarshal([]byte(route), &v); err != nil || len(v) != 1 || v[0].Dev != g.Active.Interface || v[0].Source != g.Active.Source {
			t.Fatal("actual route does not match applied path", route, g.Active)
		}
		handshake := managerCommand(t, "wg", "show", g.Active.Interface, "latest-handshakes")
		hs := strings.Fields(handshake)
		if len(hs) != 2 || hs[1] == "0" {
			t.Fatal("no WireGuard handshake", handshake)
		}
		transfers := managerCommand(t, "wg", "show", g.Active.Interface, "transfer")
		fields := strings.Fields(transfers)
		if len(fields) != 3 || fields[1] == "0" || fields[2] == "0" {
			t.Fatal("WireGuard bytes missing", transfers)
		}
		return map[string]any{"route": json.RawMessage(route), "handshake": handshake, "transfers": transfers, "active": g.Active, "proof": out.Application.Proof}
	}
	phase := func(name, origin, desired, metric string, independent bool, action func()) map[string]any {
		t.Helper()
		t.Log("automatic manager phase", name)
		packetOffset, err := trace.position()
		if err != "" {
			t.Fatal(err)
		}
		if independent {
			eventually(t, 20*time.Second, "independent app baseline", func() error { return managerPayload("198.18.0.3", "198.18.0.12") })
		}
		if latestApplicationResult(logs["app"]).Applied {
			session := trace.restartStream()
			eventually(t, 10*time.Second, "existing TCP before fault", func() error {
				packets, _, err := trace.snapshot()
				if err != "" {
					return fmt.Errorf("%s", err)
				}
				for _, p := range packets {
					if p.Kind == "tcp-existing" && p.Session == session && p.OK {
						return nil
					}
				}
				return fmt.Errorf("stream not established")
			})
		}
		begin := managerMono()
		before := latestApplicationResult(logs["app"])
		row := map[string]any{"name": name, "passed": false, "origin": origin, "desired": desired, "metric": metric, "begin_monotonic_ns": begin, "previous_path": before.Selection.DesiredPathID, "packet_offset": packetOffset}
		report["steps"] = append(report["steps"].([]map[string]any), row)
		action()
		row["action_completed_monotonic_ns"] = managerMono()
		var lanRecovered int64
		if name == "netplan-apply" {
			lan := managerLANRecovery(t, row["action_completed_monotonic_ns"].(int64))
			row["lan_reconfiguration"] = lan
			lanRecovered = lan["recovered_monotonic_ns"].(int64)
		}
		var out relayapply.TargetReconcileResult
		eventually(t, 120*time.Second, "automatic manager convergence "+name, func() error {
			_, err := trace.position()
			if err != "" {
				t.Fatal(err)
			}
			out = latestApplicationResult(logs["app"])
			if out.Diagnostics == nil || int64(out.Diagnostics.StartedMono) <= begin || out.Selection.DesiredPathID != desired || out.Applied != (desired != "") || desired == "" && !out.Application.Guarded {
				return fmt.Errorf("desired=%s applied=%v reason=%s application=%s", out.Selection.DesiredPathID, out.Applied, out.Selection.Reason, out.Application.Reason)
			}
			if desired != "" {
				source, err := managerAutoTCP(m3Target)
				if err != nil || source != sourceFor(desired) {
					return fmt.Errorf("TCP path source %s: %v", source, err)
				}
				source, err = managerAutoUDP()
				if err != nil || source != sourceFor(desired) {
					return fmt.Errorf("UDP path source %s: %v", source, err)
				}
			}
			return nil
		})
		ready := managerMono()
		row["ready_observed_monotonic_ns"] = ready
		row["result"] = out
		if desired != "" {
			row["kernel"] = evidence(out)
		}
		// Complete fresh, independent packet samples after convergence. Negative
		// phases need a real quiet window, not a single conveniently failed probe.
		duration := time.Second
		if desired == "" {
			duration = 3 * time.Second
		}
		time.Sleep(duration)
		packets, cycles, err := trace.snapshot()
		if err != "" {
			t.Fatal(err)
		}
		counts := map[string]map[string]int{}
		for _, p := range packets {
			if p.Begin < begin {
				continue
			}
			if counts[p.Kind] == nil {
				counts[p.Kind] = map[string]int{}
			}
			key := "failed"
			if p.OK {
				key = "ok"
			}
			counts[p.Kind][key]++
			if !p.OK && (p.Kind == "rf-lan" || p.Kind == "gimbal-lan" || independent && p.Kind == "independent-app") && !managerLANReconfigurationSample(name, p, begin, lanRecovered) {
				t.Fatal("unaffected communication interrupted", name, p)
			}
			if desired != "" && p.Begin >= ready && p.OK && (p.Kind == "tcp-new" || p.Kind == "udp") && p.Source != sourceFor(desired) {
				t.Fatal("post-convergence payload used another relay", name, p)
			}
			if desired == "" && p.Begin >= ready && (p.Kind == "tcp-new" || p.Kind == "udp" || p.Kind == "tcp-existing" && p.Sent >= ready) && p.OK {
				t.Fatal("no-uplink/approval quarantine leaked payload", name, p)
			}
		}
		for _, kind := range []string{"tcp-new", "udp", "rf-lan", "gimbal-lan", "independent-app", "tcp-existing"} {
			if counts[kind]["ok"]+counts[kind]["failed"] == 0 {
				t.Fatal("missing packet evidence", name, kind)
			}
		}
		if desired == "" {
			for _, kind := range []string{"tcp-new", "udp"} {
				n := 0
				for _, p := range packets {
					if p.Kind == kind && p.Begin >= ready {
						n++
					}
				}
				if n < 2 {
					t.Fatal("missing closed-window probes", kind)
				}
			}
		}
		row["traffic"] = counts
		if name == "netplan-apply" {
			row["lan_reconfiguration"].(map[string]any)["failed_samples"] = counts["rf-lan"]["failed"] + counts["gimbal-lan"]["failed"]
		}
		end := managerMono()
		gaps := map[string]float64{}
		for kind := range counts {
			var last, gap int64
			for _, packet := range packets {
				if packet.Kind != kind || !packet.OK {
					continue
				}
				if packet.End >= begin && last > 0 {
					gap = max(gap, packet.End-last)
				}
				last = packet.End
			}
			if last > 0 {
				gap = max(gap, end-last)
				gaps[kind] = float64(gap) / 1e6
			}
		}
		row["max_success_gap_ms"] = gaps
		streamStatus := "no_post_convergence_reply_in_window"
		for _, packet := range packets {
			if packet.Kind == "tcp-existing" && packet.Sent >= ready && packet.OK {
				streamStatus = "same_socket_payload_verified"
			}
		}
		row["existing_tcp_outcome"] = streamStatus
		// Internal checkpoints and the packet sampler share CLOCK_MONOTONIC.
		// Selection/route command completion are separate from verified payload.
		timeline := managerTimeline(packets, cycles, before.Selection.DesiredPathID, desired, sourceFor(desired), begin)
		row["timeline"] = timeline
		if metric == "failover" {
			// Any freshly applied approved alternative can restore service.
			// Returning to the fixture's preferred path may happen much later
			// after minimum dwell/hold-down; keep that convergence separately.
			path, restored := managerFailoverTimeline(packets, cycles, before.Selection.DesiredPathID, pathSources, begin)
			row["failover_path"], row["failover_timeline"] = path, restored
			timeline = restored
		} else if metric == "no-uplink" {
			timeline = managerNoPathTimeline(packets, cycles, before.Selection.DesiredPathID, begin)
			row["no_uplink_timeline"] = timeline
			row["no_uplink_evidence_state"] = out.Selection.State
			if timeline["decision_complete"] > 0 {
				row["no_uplink_evidence_state"] = "no_verified_path"
			}
		}
		firstSuccess, decided, applied := timeline["first_success"], timeline["decision_complete"], timeline["routes_completed"]
		if metric == "failover" || metric == "no-uplink" {
			finish := firstSuccess
			if metric == "no-uplink" {
				finish = decided
			}
			measured := finish > begin && decided >= begin && (metric == "no-uplink" || applied >= begin)
			status := "unmeasured"
			if measured {
				status = "pass"
				if finish-begin > int64(10*time.Second) {
					status = "fail"
				}
			}
			slo := map[string]any{"status": status, "limit_ms": 10000, "metric": metric}
			if measured {
				slo["elapsed_ms"] = float64(finish-begin) / 1e6
			} else if metric == "no-uplink" {
				slo["reason"] = "no_confirmed_all_candidate_failure"
			} else {
				slo["reason"] = "incomplete_restoration_timeline"
			}
			row["slo"] = slo
		}
		integrity()
		row["end_monotonic_ns"] = managerMono()
		row["passed"] = true
		return row
	}
	phase("baseline", "none", "p00", "baseline", true, func() { time.Sleep(time.Second) })
	initial := latestApplicationResult(logs["app"])
	phase("nm-down", "NetworkManager", "p01", "failover", true, func() { managerCommand(t, "nmcli", "--wait", "15", "connection", "down", "vpnctl-wan") })
	phase("relay0-down", "kernel fault", "p11", "failover", true, func() { netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "down") })
	phase("all-relays-down", "kernel fault", "", "no-uplink", false, func() { netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "down") })
	alternate := phase("alternate-recovery", "kernel fault", "p11", "recovery", false, func() { netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "up") })
	preferred := phase("preferred-recovery", "NetworkManager and kernel fault", "p00", "recovery", true, func() {
		netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "up")
		managerCommand(t, "nmcli", "--wait", "15", "connection", "up", "vpnctl-wan")
	})
	a := alternate["result"].(relayapply.TargetReconcileResult)
	p := preferred["result"].(relayapply.TargetReconcileResult)
	if a.Application.Reservation.ChangedAt == nil || p.Application.Reservation.ChangedAt == nil || p.Application.Reservation.ChangedAt.Sub(*a.Application.Reservation.ChangedAt) < 15*time.Second {
		t.Fatal("preferred recovery violated committed dwell")
	}
	alternateApplied := alternate["timeline"].(map[string]int64)["routes_completed"]
	preferredApplied := preferred["timeline"].(map[string]int64)["routes_completed"]
	if alternateApplied <= 0 || preferredApplied-alternateApplied < int64(15*time.Second) {
		t.Fatal("missing monotonic committed dwell evidence")
	}
	report["committed_dwell_monotonic_ns"] = preferredApplied - alternateApplied
	_, cycles, err := trace.snapshot()
	if err != "" {
		t.Fatal(err)
	}
	fresh, held := false, false
	var healthyConfirmed int64
	oldGeneration := ""
	for _, c := range initial.Selection.Candidates {
		if c.PathID == "p00" {
			oldGeneration = c.UnderlayGeneration
		}
	}
	for _, c := range cycles {
		if c.Target != "app" || c.Diagnostics == nil || int64(c.Diagnostics.FinishedMono) < preferred["begin_monotonic_ns"].(int64) || int64(c.Diagnostics.FinishedMono) > preferred["end_monotonic_ns"].(int64) {
			continue
		}
		if c.Reason == "minimum_dwell" || c.Reason == "recovery_hold_down" {
			held = true
		}
		for _, path := range c.Candidates {
			if path.PathID == "p00" && path.UnderlayGeneration != "" && path.UnderlayGeneration != oldGeneration && path.ConsecutiveSuccesses == 1 && !path.Eligible {
				fresh = true
				for _, checkpoint := range c.Diagnostics.Checkpoints {
					if checkpoint.Name == "decision_complete" && int64(checkpoint.At) <= preferredApplied {
						healthyConfirmed = int64(checkpoint.At)
					}
				}
			}
		}
	}
	if !fresh || !held {
		t.Fatal("fresh generation confirmation or recovery hold-down not exercised", fresh, held)
	}
	if healthyConfirmed <= 0 || preferredApplied-healthyConfirmed < int64(10*time.Second) {
		t.Fatal("preferred recovery preceded monotonic health hold-down")
	}
	report["health_hold_down_monotonic_ns"] = preferredApplied - healthyConfirmed
	report["fresh_generation_confirmed"] = true
	report["recovery_hysteresis_observed"] = true
	phase("nm-restart", "NetworkManager", "p00", "maintenance", true, func() { managerCommand(t, "systemctl", "restart", "NetworkManager.service") })
	phase("netplan-apply", "Netplan-networkd", "p00", "maintenance", true, func() { managerCommand(t, "netplan", "apply") })
	phase("networkd-restart", "networkd", "p00", "maintenance", true, func() { managerCommand(t, "systemctl", "restart", "systemd-networkd.service") })
	phase("foreign-firewall-reload", "foreign nft fixture", "p00", "maintenance", true, func() {
		managerCommand(t, "nft", "add", "chain", "inet", "manager_foreign", "input", "{ type filter hook input priority 10; policy accept; }")
		managerCommand(t, "nft", "flush", "chain", "inet", "manager_foreign", "input")
	})
	for i := 0; i < 2; i++ {
		phase(fmt.Sprintf("flap-down-%d", i), "NetworkManager", "p01", "failover", true, func() { managerCommand(t, "nmcli", "--wait", "15", "connection", "down", "vpnctl-wan") })
		phase(fmt.Sprintf("flap-up-%d", i), "NetworkManager", "p00", "recovery", true, func() { managerCommand(t, "nmcli", "--wait", "15", "connection", "up", "vpnctl-wan") })
	}
	phase("nm-shared-up", "NetworkManager DHCP/NAT", "p00", "maintenance", true, func() { managerSharedUp(t, f, lanNS["shared0"], report, snapshot) })
	phase("nm-shared-down", "NetworkManager DHCP/NAT", "p00", "maintenance", true, func() { managerCommand(t, "nmcli", "--wait", "15", "connection", "down", "vpnctl-shared") })
	_, foreignPeer := wgKeyPair(t)
	foreignInterface := f.plan.Paths[0].Pin.WGInterface
	phase("foreign-peer-conflict", "foreign WG peer fixture", "p01", "ownership", true, func() {
		managerCommand(t, "wg", "set", foreignInterface, "peer", foreignPeer, "allowed-ips", "203.0.114.1/32")
	})
	if !strings.Contains(managerCommand(t, "wg", "show", foreignInterface, "peers"), foreignPeer) {
		t.Fatal("foreign peer deleted")
	}
	report["foreign_peer_preserved"] = true
	phase("foreign-peer-removed", "foreign owner cleanup", "p00", "recovery", true, func() {
		managerCommand(t, "wg", "set", foreignInterface, "peer", foreignPeer, "remove")
	})
	phase("watch-restart", "process restart", "p00", "recovery", true, func() { watchers["app"].terminate(t); watchers["app"] = startWatch("app") })
	// Controller loss must preserve still-valid approval; record a fresh cycle
	// before waiting for the actual, shortened approval expiry (no clock changes).
	approval := f.controller.apply(f.spec, 60)
	for _, r := range f.recipients {
		r.readyApproval(approval.ExpiresAt)
	}
	eventually(t, 30*time.Second, "new shortened node approval observed", func() error {
		if !managerApprovalReady(approval.Generation, latestApplicationResult(logs["app"]), latestApplicationResult(logs["app2"])) {
			return fmt.Errorf("awaiting both applications' current approval confirmation")
		}
		return nil
	})
	report["approval_expires_at"] = approval.ExpiresAt
	cutoff := managerMono() + int64(time.Until(approval.ExpiresAt))
	report["approval_cutoff_monotonic_estimate_ns"] = cutoff
	phase("controller-offline-valid", "controller process", "p00", "authority", true, func() { f.controller.process.stop() })
	phase("approval-expired-offline", "real elapsed approval TTL", "", "authority", false, func() {
		wait := time.Until(approval.ExpiresAt.Add(300 * time.Millisecond))
		if wait > 0 {
			time.Sleep(wait)
		}
	})
	packets, _, _ := trace.snapshot()
	for _, e := range packets {
		if e.Begin > cutoff+int64(time.Second) && (e.Kind == "tcp-new" || e.Kind == "udp" || e.Kind == "tcp-existing" && e.Sent > cutoff+int64(time.Second)) && e.OK {
			t.Fatal("expired approval carried payload", e)
		}
	}
	report["relay_after_fresh_approval"] = map[string]m3SupervisorReport{}
	phase("fresh-approval-awaiting-relay-apply", "fresh approval without relay installation", "", "authority", false, func() {
		f.controller.start()
		fresh := f.controller.apply(f.spec, 3600)
		for _, relay := range f.recipients {
			// An absent endpoint must not meet the installed-endpoint readiness
			// helper's KernelReady requirement. Verify fresh authority AND empty,
			// non-ready kernel state independently before any explicit apply.
			after := time.Now()
			eventually(t, 12*time.Second, "fresh approval with empty relay "+relay.relay, func() error {
				b, err := os.ReadFile(relay.watch.log)
				if err != nil {
					return err
				}
				lines := strings.Split(string(b), "\n")
				if len(lines) < 2 {
					return fmt.Errorf("missing supervisor report")
				}
				var state m3SupervisorReport
				if err := json.Unmarshal([]byte(lines[len(lines)-2]), &state); err != nil {
					return err
				}
				if !state.ObservedAt.After(after) || state.Refresh != "success" || !state.ApprovalValid || !state.ApprovalExpiresAt.Equal(fresh.ExpiresAt) || state.Kernel == nil {
					return fmt.Errorf("fresh authority not yet observed")
				}
				if len(state.Kernel.Endpoints) != 0 || state.Kernel.KernelReady {
					t.Fatal("retired relay resurrected without explicit apply", state)
				}
				report["relay_after_fresh_approval"].(map[string]m3SupervisorReport)[relay.relay] = state
				return nil
			})
		}
		eventually(t, 20*time.Second, "fresh node approval while relay remains absent", func() error {
			if latestApplicationResult(logs["app"]).Selection.Generation != fresh.Generation {
				return fmt.Errorf("fresh approval not yet observed")
			}
			return nil
		})
	})
	phase("fresh-approval-recovery", "explicit approved relay installation; automatic node selection", "p00", "authority", false, func() {
		for _, relay := range f.recipients {
			for endpoint := range f.spec.Relays[0].Endpoints {
				relay.require("apply", endpoint, 51820+endpoint)
			}
			relay.ready()
		}
	})
	report["relay_expiry_recovery"] = "fresh approval plus explicit relay apply; node candidates and application selection recover automatically"
	if os.Getenv("VPNCTL_VM_RELAY_INSTALL") == "1" {
		report["installation_mode"] = true
		phase("intent-enrolled", "explicit opt-in; automatic relay installation", "p00", "authority", false, func() {
			for _, relay := range f.recipients {
				for endpoint := range f.spec.Relays[0].Endpoints {
					relay.require("release", endpoint, 0)
					relay.require("prepare", endpoint, 51820+endpoint)
				}
			}
		})
		before := map[string]relayapply.DeploymentResult{}
		for _, relay := range f.recipients {
			relay.ready()
			before[relay.relay] = relay.require("inspect", -1, 0)
		}
		report["installation_before_expiry"] = before
		approval := f.controller.apply(f.spec, 60)
		for _, relay := range f.recipients {
			relay.readyApproval(approval.ExpiresAt)
		}
		eventually(t, 30*time.Second, "short approval before automatic installation test", func() error {
			if !managerApprovalReady(approval.Generation, latestApplicationResult(logs["app"]), latestApplicationResult(logs["app2"])) {
				return fmt.Errorf("awaiting both applications' current approval confirmation")
			}
			return nil
		})
		phase("intent-controller-offline-valid", "controller process", "p00", "authority", true, func() { f.controller.process.stop() })
		phase("intent-expired-offline", "real elapsed approval TTL", "", "authority", false, func() {
			if wait := time.Until(approval.ExpiresAt.Add(300 * time.Millisecond)); wait > 0 {
				time.Sleep(wait)
			}
		})
		phase("intent-offline-relay-restart", "relay supervisor restart without authority", "", "authority", false, func() {
			for _, relay := range f.recipients {
				relay.watch.terminate(t)
				relay.start()
			}
		})
		// Kernel ownership is gone; durable local intent still cannot authorize
		// installation after an offline process restart.
		empty := map[string]m3SupervisorReport{}
		for _, relay := range f.recipients {
			state := relay.awaitOffline(time.Now(), false, false)
			if state.Kernel == nil || len(state.Kernel.Endpoints) != 0 || len(state.Kernel.Installations) != len(f.spec.Relays[0].Endpoints) {
				t.Fatal("offline installation state", state)
			}
			empty[relay.relay] = state
		}
		report["installation_offline_restart"] = empty
		phase("intent-fresh-approval-recovery", "new authenticated approval; automatic relay and node recovery", "p00", "authority", false, func() {
			f.controller.start()
			f.controller.apply(f.spec, 3600)
		})
		after := map[string]relayapply.DeploymentResult{}
		for _, relay := range f.recipients {
			relay.ready()
			state := relay.require("inspect", -1, 0)
			if !state.KernelReady || len(state.Installations) != len(before[relay.relay].Installations) {
				t.Fatal("automatic installation incomplete", state)
			}
			for i, intent := range state.Installations {
				old := before[relay.relay].Installations[i]
				if !intent.Enabled || intent.Phase != "applied" || intent.Revision != old.Revision || intent.Attempts != old.Attempts+1 {
					t.Fatal("intent changed or uncontrolled reinstall", intent, old)
				}
			}
			after[relay.relay] = state
		}
		report["installation_after_recovery"] = after
		report["relay_installation_recovery"] = "explicit intent retained across real expiry and offline supervisor restart; fresh authenticated approval restores relay endpoints and actual TCP/UDP without apply"
	}
	report["final"] = snapshot()
	report["foreign_policy_preserved"] = true
	// Sample count is deliberately explicit: this functional matrix alone does
	// not establish a fleet p95, even when every individual observation is fast.
	samples := 0
	misses := 0
	unmeasured := 0
	for _, raw := range report["steps"].([]map[string]any) {
		if slo, ok := raw["slo"].(map[string]any); ok {
			samples++
			if slo["status"] == "fail" {
				misses++
			}
			if slo["status"] == "unmeasured" {
				unmeasured++
			}
		}
	}
	report["slo_summary"] = map[string]any{"samples": samples, "misses": misses, "unmeasured": unmeasured, "p95_status": "unqualified_insufficient_samples", "required_samples_per_class": 20}
	managerFinalInventory(t, f, report, size)
	trace.close()
	watchers["app"].terminate(t)
	nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "release", "--config", f.node, "--target-id", "app")
	eventually(t, 10*time.Second, "positive fallback control after explicit release", func() error {
		source, err := managerAutoTCP(m3Target)
		if err != nil || source != "203.0.113.1" {
			return fmt.Errorf("fallback %s: %v", source, err)
		}
		return nil
	})
	report["fallback_positive_control"] = true
}
