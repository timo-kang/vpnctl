//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/relayapply"
)

func applicationStream(t *testing.T, f *m3AuthorityFixture, label string) *networkProcess {
	t.Helper()
	p := startNetworkProcess(t, f.robot, filepath.Join(f.results, label+"-stream.jsonl"), []string{"VPNCTL_WORKER=lease-stream", "VPNCTL_PROBE_SOURCE=", "VPNCTL_PROBE_INTERFACE="}, f.worker, "-test.run=^TestNetworkWorker$")
	eventually(t, 5*time.Second, "ordinary TCP baseline", func() error {
		b, _ := os.ReadFile(p.log)
		if !strings.Contains(string(b), `"ok":true`) {
			return fmt.Errorf("no payload")
		}
		return nil
	})
	return p
}
func requireApplicationBlocked(t *testing.T, f *m3AuthorityFixture, stream *networkProcess, deadline time.Time) {
	t.Helper()
	if p := applicationPayload(t, f, m3Target); p.OK {
		t.Fatal("new ordinary TCP escaped quarantine", p)
	}
	eventually(t, 3*time.Second, "post-cutoff existing TCP evidence", func() error {
		b, err := os.ReadFile(stream.log)
		if err != nil {
			return err
		}
		count := 0
		for _, line := range strings.Split(string(b), "\n") {
			var e leaseStreamEvent
			if json.Unmarshal([]byte(line), &e) == nil && e.At.After(deadline) {
				count++
				if e.OK {
					t.Fatal("existing unbound TCP escaped quarantine", e)
				}
			}
		}
		if count == 0 {
			return fmt.Errorf("missing post-cutoff sample")
		}
		return nil
	})
}
func applicationFallback(t *testing.T, f *m3AuthorityFixture) {
	t.Helper()
	netOutput(t, f.robot, "ip", "link", "add", "fallback0", "type", "veth", "peer", "name", "fallback1", "netns", f.target)
	netOutput(t, f.robot, "ip", "addr", "add", "203.0.113.1/30", "dev", "fallback0")
	netOutput(t, f.target, "ip", "addr", "add", "203.0.113.2/30", "dev", "fallback1")
	netOutput(t, f.robot, "ip", "link", "set", "fallback0", "up")
	netOutput(t, f.target, "ip", "link", "set", "fallback1", "up")
	netOutput(t, f.robot, "ip", "route", "add", "default", "via", "203.0.113.2", "dev", "fallback0")
	// This fixed fixture tests target reservation, not ARP convergence/GC. Keep
	// its two owned neighbours permanent, as in the direct dataplane fixture.
	mac := func(ns, dev string) string {
		var links []struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal([]byte(netOutput(t, ns, "ip", "-j", "link", "show", "dev", dev)), &links); err != nil || len(links) != 1 {
			t.Fatal("fallback link inventory", err)
		}
		if _, err := net.ParseMAC(links[0].Address); err != nil {
			t.Fatal(err)
		}
		return links[0].Address
	}
	netOutput(t, f.robot, "ip", "neigh", "replace", "203.0.113.2", "lladdr", mac(f.target, "fallback1"), "nud", "permanent", "dev", "fallback0")
	netOutput(t, f.target, "ip", "neigh", "replace", "203.0.113.1", "lladdr", mac(f.robot, "fallback0"), "nud", "permanent", "dev", "fallback1")
}
func TestNetns_M3TargetApplicationQuarantine(t *testing.T) {
	requireNetwork(t)
	f := applicationFixture(t, true, 4)
	report := map[string]any{}
	t.Cleanup(func() {
		report["completed"] = !t.Failed()
		writeM3Report(t, filepath.Join(f.results, "application-quarantine.json"), report)
	})
	applicationFallback(t, f)
	lookup := func(stage string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, err := netCommand(ctx, f.robot, "ip", "-j", "-4", "route", "get", m3Target).CombinedOutput()
		report[stage+"_route"] = string(b)
		var routes []struct {
			Dev     string `json:"dev"`
			Source  string `json:"prefsrc"`
			Gateway string `json:"gateway"`
		}
		if err != nil || json.Unmarshal(b, &routes) != nil || len(routes) != 1 || routes[0].Dev != "fallback0" || routes[0].Source != "203.0.113.1" || routes[0].Gateway != "203.0.113.2" {
			t.Fatal("fallback route", err, string(b))
		}
	}
	// Prove the exact same target/default route works before challenging the
	// reservation; otherwise a dead fixture could falsely pass quarantine.
	nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "release", "--config", f.node, "--target-id", "app")
	lookup("baseline")
	eventually(t, 5*time.Second, "fallback fixture readiness before quarantine", func() error {
		p := applicationPayload(t, f, m3Target)
		report["fallback_baseline"] = p
		if !p.OK || p.Source != "203.0.113.1" {
			return fmt.Errorf("fallback not ready: %+v", p)
		}
		return nil
	})
	nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", "app")
	applicationReconcile(t, f, "app", true)
	stream := applicationStream(t, f, "quarantine")
	// All candidates stay alive. A nonexistent manual pin must still close the
	// ordinary socket that already has a candidate's inner source address.
	out := applicationReconcile(t, f, "app", false, "--mode", "manual", "--path-id", "unavailable")
	if !out.Application.Guarded || out.Selection.Reason != "manual_pin_unavailable" {
		t.Fatal(out)
	}
	cutoff := time.Now().Add(500 * time.Millisecond)
	awaitApplicationCandidates(t, f)
	requireApplicationBlocked(t, f, stream, cutoff)
	report["old_and_new_unbound_tcp_blocked"], report["all_bound_probes_live"], report["result"] = true, true, out
	// Explicit release is the only operation allowed to expose the default.
	nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "release", "--config", f.node, "--target-id", "app")
	lookup("released")
	p := applicationPayload(t, f, m3Target) // Retain the single 1s post-release probe.
	report["fallback_after_release"] = p
	if !p.OK || p.Source != "203.0.113.1" {
		t.Fatal("released fallback unavailable", p)
	}
	report["default_fallback_verified"] = true
}
func TestNetns_M3TargetApplicationFailover(t *testing.T) {
	requireNetwork(t)
	for _, placement := range []string{"colocated", "separate"} {
		t.Run(placement, func(t *testing.T) {
			f := applicationFixture(t, placement == "separate", 4)
			applicationFallback(t, f)
			logfile := filepath.Join(f.results, "application-watch.jsonl")
			// The recovery window must span multiple real observations even with
			// race instrumentation on a constrained runner. Production budgets stay
			// unchanged; assert elapsed time from the actual committed route below.
			const dwell = 15 * time.Second
			watcher := startNetworkProcess(t, f.robot, logfile, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", "app", "--watch", "--interval", "100ms", "--probe-timeout", "150ms", "--hold-down", "10s", "--minimum-dwell", dwell.String())
			after := time.Now()
			phases := []map[string]any{}
			await := func(name, path, source string) relayapply.TargetReconcileResult {
				t.Helper()
				var out relayapply.TargetReconcileResult
				eventually(t, 45*time.Second, name, func() error {
					b, err := os.ReadFile(logfile)
					if err != nil {
						return err
					}
					lines := strings.Split(string(b), "\n")
					for i := len(lines) - 2; i >= 0; i-- {
						var v relayapply.TargetReconcileResult
						if json.Unmarshal([]byte(lines[i]), &v) == nil && v.SchemaVersion == 1 {
							out = v
							break
						}
					}
					if !out.StartedAt.After(after) || out.Selection.DesiredPathID != path || out.Applied != (path != "") || path == "" && !out.Application.Guarded {
						return fmt.Errorf("waiting %s: desired=%s applied=%v state=%s reason=%s", name, out.Selection.DesiredPathID, out.Applied, out.Application.State, out.Application.Reason)
					}
					p := applicationPayload(t, f, m3Target)
					if p.OK != (path != "") || p.OK && p.Source != source {
						return fmt.Errorf("payload %+v", p)
					}
					return nil
				})
				phases = append(phases, map[string]any{"name": name, "fault_or_phase_at": after, "first_payload_checked_at": time.Now(), "result": out})
				return out
			}
			await("baseline", "p00", "198.18.0.11")
			f.controller.process.stop()
			after = time.Now()
			await("controller_offline", "p00", "198.18.0.11")
			(relayUplink{relay: f.robot}).nft(t, `table inet application_fault {
 chain output { type filter hook output priority filter; policy accept;
 oifname "wan0" udp dport { 51820, 51821 } drop
 }
}`)
			after = time.Now()
			await("underlay0_blackhole", "p01", "198.18.0.11")
			netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "down")
			after = time.Now()
			await("relay0_down", "p11", "198.18.0.12")
			netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "down")
			after = time.Now()
			await("all_unavailable", "", "")
			netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "up")
			after = time.Now()
			alternate := await("alternate_recovery", "p11", "198.18.0.12")
			netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "up")
			netOutput(t, f.robot, "nft", "delete", "table", "inet", "application_fault")
			after = time.Now()
			preferred := await("preferred_recovery", "p00", "198.18.0.11")
			if alternate.Application.Reservation.ChangedAt == nil || preferred.Application.Reservation.ChangedAt == nil || preferred.Application.Reservation.ChangedAt.Sub(*alternate.Application.Reservation.ChangedAt) < dwell {
				t.Fatal("preferred recovery preceded minimum committed dwell", alternate, preferred)
			}
			// Foreign peer must be preserved while a valid alternative actually carries apps.
			_, foreign := wgKeyPair(t)
			iface := f.plan.Paths[0].Pin.WGInterface
			netOutput(t, f.robot, "wg", "set", iface, "peer", foreign, "allowed-ips", "203.0.114.1/32")
			after = time.Now()
			await("foreign_peer", "p01", "198.18.0.11")
			if !strings.Contains(netOutput(t, f.robot, "wg", "show", iface, "peers"), foreign) {
				t.Fatal("foreign peer removed")
			}
			watcher.terminate(t)
			// Verify that recovery delay was grounded in actual committed state.
			b, err := os.ReadFile(logfile)
			if err != nil {
				t.Fatal(err)
			}
			delayed := false
			for _, line := range strings.Split(string(b), "\n") {
				var v relayapply.TargetReconcileResult
				if json.Unmarshal([]byte(line), &v) == nil && v.StartedAt.After(alternate.FinishedAt) && v.FinishedAt.Before(preferred.FinishedAt) && v.Applied && v.Selection.DesiredPathID == "p11" && (v.Selection.Reason == "minimum_dwell" || v.Selection.Reason == "recovery_hold_down") {
					delayed = true
				}
			}
			if !delayed {
				t.Fatal("recovery hysteresis was not exercised")
			}
			writeM3Report(t, filepath.Join(f.results, "application-failover.json"), map[string]any{"completed": !t.Failed(), "placement": placement, "phases": phases, "unbound_payload_and_nat_verified": true})
		})
	}
}
func TestNetns_M3TargetApplicationCrash(t *testing.T) {
	requireNetwork(t)
	for _, point := range []string{"del", "add"} {
		t.Run(point, func(t *testing.T) {
			f := applicationFixture(t, true, 4)
			initial := applicationReconcile(t, f, "app", true)
			// Two cycles of a new selector first quarantine p00, then install p11.
			// SIGKILL is injected at either mutation while the intent is already durable.
			dir := filepath.Join(f.private, "application-kill")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			ip, err := exec.LookPath("ip")
			if err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\n" + ip + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ] && [ \"$1 $2 $3 $4\" = '-4 route " + point + " 198.18.0.2/32' ] && [ \"$6\" = '" + fmt.Sprint(initial.Application.Reservation.Table) + "' ]; then printf fired > \"$VPNCTL_APP_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
			if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "fired")
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			cmd := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", "app", "--mode", "manual", "--path-id", "p11", "--samples", "2", "--interval", "100ms")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "VPNCTL_APP_MARKER="+marker)
			b, err := cmd.CombinedOutput()
			cancel()
			if err == nil {
				t.Fatal("actuator survived injected kill", string(b))
			}
			if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("wrong fault", err, string(b))
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatal("mutation not exercised", err)
			}
			eventually(t, 12*time.Second, "pending intent blocks candidate", func() error {
				if applicationPayload(t, f, m3Target).OK {
					return fmt.Errorf("pending route still open")
				}
				return nil
			})
			// Unreferenced p01 must still get leases during recovery.
			if !applicationCandidate(t, f, f.plan.Paths[1]).OK {
				t.Fatal("unrelated candidate starved")
			}
			nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "recover", "--config", f.node, "--target-id", "app")
			if applicationPayload(t, f, m3Target).OK {
				t.Fatal("recovery replayed stale path")
			}
			awaitApplicationCandidates(t, f)
			applicationReconcile(t, f, "app", true)
			writeM3Report(t, filepath.Join(f.results, "application-crash.json"), map[string]any{"completed": !t.Failed(), "sigkill_after": point, "recovery_quarantined": true, "unrelated_candidate_live": true, "fresh_reconciliation_recovers": true})
		})
	}
}
func TestNetns_M3TargetApplicationApproval(t *testing.T) {
	requireNetwork(t)
	for _, fault := range []string{"expiry", "revocation"} {
		t.Run(fault, func(t *testing.T) {
			f := applicationFixture(t, true, 4)
			if fault == "expiry" {
				grant := f.controller.apply(f.spec, 60)
				// Explicit refresh fixes which generation is isolated before the outage.
				f.nodeCall("refresh", "")
				applicationReconcile(t, f, "app", true)
				stream := applicationStream(t, f, "expiry")
				nodeControllerOutage(t, f)
				f.controller.apply(f.spec, 3600)
				time.Sleep(12 * time.Second)
				if !applicationPayload(t, f, m3Target).OK {
					t.Fatal("valid offline application stopped")
				}
				time.Sleep(time.Until(grant.ExpiresAt.Add(time.Second)))
				requireApplicationBlocked(t, f, stream, grant.ExpiresAt.Add(500*time.Millisecond))
				for _, r := range f.recipients {
					if !r.require("inspect", -1, 0).KernelReady {
						t.Fatal("relay also expired")
					}
				}
				applicationReconcile(t, f, "app", false)
				netOutput(t, f.robot, "nft", "delete", "table", "inet", "node_outage")
				awaitApplicationCandidates(t, f)
				applicationReconcile(t, f, "app", true)
			} else {
				applicationReconcile(t, f, "app", true)
				stream := applicationStream(t, f, "revocation")
				cfg, err := config.Load(f.node)
				if err != nil {
					t.Fatal(err)
				}
				creds, err := pki.LoadCredentials(cfg.Node.PKIDir)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := pki.ParseCertificate(creds.ClientCert)
				if err != nil {
					t.Fatal(err)
				}
				f.controller.admin(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)})
				at := time.Now()
				time.Sleep(11 * time.Second)
				requireApplicationBlocked(t, f, stream, at.Add(11*time.Second))
				nodeControllerOutage(t, f)
				applicationReconcile(t, f, "app", false)
				if applicationPayload(t, f, m3Target).OK {
					t.Fatal("outage erased denial")
				}
				for _, r := range f.recipients {
					if !r.require("inspect", -1, 0).KernelReady {
						t.Fatal("independent relay denied")
					}
				}
			}
			writeM3Report(t, filepath.Join(f.results, "application-approval.json"), map[string]any{"completed": !t.Failed(), "fault": fault, "old_and_new_unbound_tcp_blocked": true, "relay_approvals_live": true})
		})
	}
}

func TestNetns_M3TargetApplicationSlowProbes(t *testing.T) {
	requireNetwork(t)
	f := applicationFixture(t, true, 8)
	applicationReconcile(t, f, "app", true)
	applicationReconcile(t, f, "app2", true)
	checkProtectedSlowProbes(t, f, true)
	awaitApplicationCandidates(t, f)
	applicationReconcile(t, f, "app", true)
}

func TestNetns_M3TargetApplicationForeignState(t *testing.T) {
	requireNetwork(t)
	applicationForeignState(t, false)
}

func TestNetns_M3PreparationForeignState(t *testing.T) {
	requireNetwork(t)
	applicationForeignState(t, true)
}

func applicationForeignState(t *testing.T, managed bool) {
	f := applicationFixture(t, true, 4)
	if managed {
		enablePreparation(t, f, "p00")
	}
	applicationReconcile(t, f, "app2", true, "--mode", "manual", "--path-id", "p11")
	phases := []string{}
	kinds := []string{"target-route", "target-rule", "tc", "nft", "rp-filter", "underlay-address"}
	if managed {
		kinds = append([]string{"alias", "mark", "peer", "psk"}, kinds...)
	}
	for _, kind := range kinds {
		t.Logf("foreign-state phase: %s", kind)
		initial := applicationReconcile(t, f, "app", true)
		iface := f.plan.Paths[0].Pin.WGInterface
		var snapshot func() string
		var undo func()
		switch kind {
		case "alias":
			var links []struct {
				Alias string `json:"ifalias"`
			}
			if err := json.Unmarshal([]byte(netOutput(t, f.robot, "ip", "-j", "link", "show", iface)), &links); err != nil || len(links) != 1 {
				t.Fatal(err)
			}
			old := links[0].Alias
			netOutput(t, f.robot, "ip", "link", "set", iface, "alias", "foreign-preparation-owner")
			snapshot = func() string { return netOutput(t, f.robot, "ip", "-j", "link", "show", iface) }
			undo = func() { netOutput(t, f.robot, "ip", "link", "set", iface, "alias", old) }
		case "mark":
			old := netOutput(t, f.robot, "wg", "show", iface, "fwmark")
			netOutput(t, f.robot, "wg", "set", iface, "fwmark", "1")
			snapshot = func() string { return netOutput(t, f.robot, "wg", "show", iface, "fwmark") }
			undo = func() { netOutput(t, f.robot, "wg", "set", iface, "fwmark", old) }
		case "peer":
			_, pub := wgKeyPair(t)
			netOutput(t, f.robot, "wg", "set", iface, "peer", pub, "allowed-ips", "198.18.0.254/32")
			snapshot = func() string { return netOutput(t, f.robot, "wg", "show", iface, "allowed-ips") }
			undo = func() { netOutput(t, f.robot, "wg", "set", iface, "peer", pub, "remove") }
		case "psk":
			key, _ := wgKeyPair(t)
			file := filepath.Join(f.private, "foreign-psk.key")
			mustWrite(t, file, key)
			peer := f.plan.Paths[0].RelayPublicKey
			netOutput(t, f.robot, "wg", "set", iface, "peer", peer, "preshared-key", file)
			// Compare a digest inside the namespace; never record the PSK output.
			snapshot = func() string {
				return netOutput(t, f.robot, "sh", "-c", `wg show "$1" preshared-keys | sha256sum`, "sh", iface)
			}
			undo = func() { netOutput(t, f.robot, "wg", "set", iface, "peer", peer, "preshared-key", "/dev/null") }
		case "target-route":
			table := fmt.Sprint(initial.Application.Reservation.Table)
			netOutput(t, f.robot, "ip", "route", "add", "unreachable", "203.0.114.1/32", "table", table, "proto", "99")
			snapshot = func() string {
				return netOutput(t, f.robot, "ip", "-j", "route", "show", "table", table, "proto", "99")
			}
			undo = func() {
				netOutput(t, f.robot, "ip", "route", "del", "unreachable", "203.0.114.1/32", "table", table, "proto", "99")
			}
		case "target-rule":
			netOutput(t, f.robot, "ip", "route", "add", "unreachable", m3Target+"/32", "table", "9999", "proto", "99")
			netOutput(t, f.robot, "ip", "rule", "add", "priority", "31999", "to", m3Target+"/32", "iif", "lo", "fwmark", "0", "lookup", "9999", "protocol", "99")
			snapshot = func() string {
				return netOutput(t, f.robot, "ip", "-j", "rule", "show", "protocol", "99") + netOutput(t, f.robot, "ip", "-j", "route", "show", "table", "9999")
			}
			undo = func() {
				netOutput(t, f.robot, "ip", "rule", "del", "priority", "31999", "to", m3Target+"/32", "iif", "lo", "fwmark", "0", "lookup", "9999", "protocol", "99")
				netOutput(t, f.robot, "ip", "route", "del", "unreachable", m3Target+"/32", "table", "9999", "proto", "99")
			}
		case "tc":
			netOutput(t, f.robot, "tc", "filter", "add", "dev", iface, "ingress", "pref", "22", "matchall", "action", "pass")
			snapshot = func() string {
				return netOutput(t, f.robot, "tc", "filter", "show", "dev", iface, "ingress", "pref", "22")
			}
			undo = func() { netOutput(t, f.robot, "tc", "filter", "del", "dev", iface, "ingress", "pref", "22") }
		case "nft":
			table := "vl" + iface[2:]
			netOutput(t, f.robot, "nft", "add", "chain", "inet", table, "foreign")
			snapshot = func() string { return netOutput(t, f.robot, "nft", "list", "chain", "inet", table, "foreign") }
			undo = func() { netOutput(t, f.robot, "nft", "delete", "chain", "inet", table, "foreign") }
		case "rp-filter":
			file := "/proc/sys/net/ipv4/conf/" + iface + "/rp_filter"
			netOutput(t, f.robot, "sh", "-c", `mount -t proc proc /proc && printf 2 > "$1"`, "sh", file)
			snapshot = func() string { return netOutput(t, f.robot, "cat", file) }
			undo = func() { netOutput(t, f.robot, "sh", "-c", `mount -t proc proc /proc && printf 0 > "$1"`, "sh", file) }
		case "underlay-address":
			netOutput(t, f.robot, "ip", "addr", "del", "192.0.2.10/24", "dev", "wan0")
			snapshot = func() string { return netOutput(t, f.robot, "ip", "-j", "address", "show", "dev", "wan0") }
			undo = func() {
				netOutput(t, f.robot, "ip", "addr", "add", "192.0.2.10/24", "dev", "wan0")
				// Removing the source also removes its endpoint routes. Recreate
				// those candidates explicitly; never expect automatic drift repair.
				for _, index := range []int{0, 2} {
					if managed && index == 0 {
						continue
					}
					path := f.plan.Paths[index].PathID
					f.nodeCall("release", path)
					netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", path, "--app-routes")
				}
			}
		}
		before := snapshot()
		applicationReconcile(t, f, "app", false, "--mode", "manual", "--path-id", "p00")
		if managed {
			time.Sleep(3 * time.Second)
		} // At least two supervisor retry opportunities.
		if snapshot() != before {
			t.Fatal("foreign state modified", kind)
		}
		if p := applicationPayload(t, f, "198.18.0.3"); !p.OK || p.Source != "198.18.0.12" {
			t.Fatal("other target lost", kind, p)
		}
		undo()
		nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "recover", "--config", f.node, "--target-id", "app")
		if managed {
			eventually(t, 60*time.Second, "managed candidate after foreign state removal", func() error {
				for _, p := range f.plan.Paths {
					if !applicationCandidate(t, f, p).OK {
						return fmt.Errorf("%s still unavailable", p.PathID)
					}
				}
				return nil
			})
		} else {
			awaitApplicationCandidates(t, f)
		}
		phases = append(phases, kind)
	}
	applicationReconcile(t, f, "app", true)
	writeM3Report(t, filepath.Join(f.results, "application-foreign.json"), map[string]any{"completed": !t.Failed(), "preserved": phases, "second_app_unchanged": true})
}
