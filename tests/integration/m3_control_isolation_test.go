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
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayplan"
)

// Real product control/relay processes. Only underlay setup, application source
// routes and uplink NAT are fixture-owned; no automatic selection is implied.
func TestNetns_M3ControlIsolation(t *testing.T) {
	requireNetwork(t)
	for _, placement := range []string{"colocated", "separate"} {
		t.Run(placement, func(t *testing.T) {
			f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: placement == "separate", independentRecipients: true})
			report := map[string]any{
				"schema_version": 1, "placement": placement, "completed": false,
				"scope":      "real mTLS, WireGuard and target TCP; explicit fixture source routes, no automatic failover or session migration",
				"controller": map[string]string{"namespace": f.controller.ns, "address": f.controller.address},
				"robot":      f.robot, "target": f.target, "paths": f.plan.Paths,
			}
			phases := []map[string]any{}
			completed := false
			defer func() {
				report["phases"] = phases
				report["completed"] = completed && !t.Failed()
				writeM3Report(t, filepath.Join(f.results, "control-isolation.json"), report)
			}()
			if len(f.plan.Paths) != 4 || f.recipients[0].config == f.recipients[1].config {
				t.Fatal("expected four paths and independent relay identities")
			}
			all := func(relayplan.Candidate) bool { return true }
			none := func(relayplan.Candidate) bool { return false }
			otherRelay := func(p relayplan.Candidate) bool { return p.RelayID == "r1" }
			// Every observation is retained before assertion, including failures.
			phase := func(name string, want func(relayplan.Candidate) bool) {
				t.Helper()
				v := map[string]m3Probe{}
				entry := map[string]any{"name": name, "at": time.Now().UTC(), "probes": v}
				phases = append(phases, entry)
				for _, p := range f.plan.Paths {
					v[p.PathID] = f.probe(p)
					if v[p.PathID].OK != want(p) {
						t.Errorf("%s: %s got %+v, want reachable=%v", name, p.PathID, v[p.PathID], want(p))
					}
				}
				entry["ended_at"] = time.Now().UTC()
				if t.Failed() {
					t.FailNow()
				}
			}
			for _, p := range f.plan.Paths {
				eventually(t, 10*time.Second, "initial target "+p.PathID, func() error {
					if !f.probe(p).OK {
						return fmt.Errorf("target not ready")
					}
					return nil
				})
			}
			phase("baseline", all)
			report["wireguard"] = f.checkPathWireGuard()
			// A robot with no direct uplink must not silently bypass the relay.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			route, err := netCommand(ctx, f.robot, "ip", "route", "get", m3Target).CombinedOutput()
			cancel()
			if err == nil || !strings.Contains(string(route), "Network is unreachable") {
				t.Fatal("expected no direct robot route to uplink", err, string(route))
			}
			if placement == "separate" {
				if netOutput(t, f.controller.ns, "wg", "show", "interfaces") != "" || strings.TrimSpace(netOutput(t, f.controller.ns, "cat", "/proc/sys/net/ipv4/ip_forward")) != "0" {
					t.Fatal("dedicated controller acquired a data-plane role")
				}
			}
			// The other enrolled relay identity cannot fetch r0's approval.
			wrong := *f.recipients[0]
			wrong.config, wrong.cache = f.recipients[1].config, filepath.Join(f.private, "wrong-recipient")
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			denial, err := wrong.callContext(ctx, "refresh", -1, 0)
			cancel()
			var denied relaycache.DeploymentReport
			if err == nil || json.Unmarshal(denial, &denied) != nil || denied.BlockedReason != "identity_or_grant_denied" || denied.ApprovalValid {
				t.Fatal("other relay identity was not explicitly denied", err, string(denial))
			}
			report["cross_recipient_rejected"] = true
			f.nodeCall("refresh", "") // authenticated remote control still works

			// Loss of a relay uplink does not kill the colocated controller API.
			netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "down")
			phase("relay0_uplink_down", otherRelay)
			f.nodeCall("refresh", "")
			for _, r := range f.recipients {
				r.ready()
			}
			netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "up")
			phase("relay0_uplink_restored", all)

			// The application can use the second explicitly pinned underlay.
			netOutput(t, f.robot, "ip", "link", "set", "wan0", "down")
			phase("robot_underlay0_down", func(p relayplan.Candidate) bool { return p.UnderlayID == "lan1" })
			netOutput(t, f.robot, "ip", "link", "set", "wan0", "up")
			// Linux removed the device-bound transport routes. Link-up alone
			// must not be mistaken for recovery. Automatic reconcile is #23;
			// explicitly release/reprepare product-owned candidates here.
			phase("robot_underlay0_up_before_reprepare", func(p relayplan.Candidate) bool { return p.UnderlayID == "lan1" })
			report["robot_routes_before_reprepare"] = netOutput(t, f.robot, "ip", "-j", "-4", "route", "show", "table", "all")
			f.nodeCall("refresh", "")
			for i, p := range f.plan.Paths {
				if p.UnderlayID != "lan0" {
					continue
				}
				table := fmt.Sprint(28000 + i)
				netOutput(t, f.robot, "ip", "rule", "del", "priority", table)
				netOutput(t, f.robot, "ip", "route", "del", m3Target+"/32", "table", table)
				f.nodeCall("release", p.PathID)
				f.nodeCall("prepare", p.PathID)
				source := strings.TrimSuffix(p.InnerAddress, "/32")
				netOutput(t, f.robot, "ip", "route", "replace", m3Target+"/32", "dev", p.Pin.WGInterface, "src", source, "table", table)
				netOutput(t, f.robot, "ip", "rule", "add", "priority", table, "from", source+"/32", "lookup", table)
			}
			for _, p := range f.plan.Paths {
				eventually(t, 10*time.Second, "underlay restored "+p.PathID, func() error {
					if !f.probe(p).OK {
						return fmt.Errorf("target not restored")
					}
					return nil
				})
			}
			phase("robot_underlay0_restored", all)
			report["robot_routes_after_reprepare"] = netOutput(t, f.robot, "ip", "-j", "-4", "route", "show", "table", "all")

			// Use actual elapsed approval time. No machine clock, reboot or sleep
			// transition is changed. Expiry is not simulated in this test.
			f.controller.apply(f.spec, 60)
			approval := f.controller.status()
			for _, r := range f.recipients {
				v := r.ready()
				if !v.ApprovalExpiresAt.Equal(approval.ExpiresAt) {
					t.Fatal("did not observe short approval")
				}
			}
			report["approval_expires_at"] = approval.ExpiresAt
			f.controller.process.stop()
			stopped := time.Now()
			report["controller_stopped_at"] = stopped.UTC()
			// Continue beyond a full 10s kernel lease. A single immediate probe
			// would miss a supervisor that failed to maintain its cached grant.
			for time.Since(stopped) < 12*time.Second {
				phase("controller_offline_valid_approval", all)
				time.Sleep(500 * time.Millisecond)
			}
			for _, r := range f.recipients {
				r.awaitOffline(stopped, true, true)
			}

			f.recipients[0].watch.stop()
			crashed := time.Now()
			report["relay0_supervisor_crashed_at"] = crashed.UTC()
			for time.Since(crashed) < 11*time.Second {
				time.Sleep(100 * time.Millisecond)
			}
			phase("relay0_kernel_lease_expired", otherRelay)
			f.recipients[0].start()
			restarted := time.Now()
			f.recipients[0].awaitOffline(restarted, true, false)
			for i := 0; i < 3; i++ {
				phase("offline_restart_cannot_rearm", otherRelay)
			}
			// Keep observing the unaffected relay until just before expiry.
			for time.Until(approval.ExpiresAt) > 6*time.Second {
				phase("offline_valid_remaining_relay", otherRelay)
			}
			for time.Now().Before(approval.ExpiresAt.Add(2 * time.Second)) {
				time.Sleep(100 * time.Millisecond)
			}
			for _, r := range f.recipients {
				r.awaitOffline(approval.ExpiresAt, false, false)
			}
			phase("offline_approval_expired", none)
			for _, r := range f.recipients {
				if netOutput(t, r.ns, "wg", "show", "all", "allowed-ips") != "" {
					t.Fatal("expired managed peer remains")
				}
			}
			report["expired_kernel"] = f.snapshot()

			// Restart the same controller database; merely restoring the API
			// cannot extend or replace expired authorization.
			f.controller.start()
			for _, r := range f.recipients {
				eventually(t, 5*time.Second, "remote expired approval rejected", func() error {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					b, err := r.callContext(ctx, "refresh", -1, 0)
					var v relaycache.DeploymentReport
					if err == nil || json.Unmarshal(b, &v) != nil || v.BlockedReason != "catalog_expired" || v.ApprovalValid {
						return fmt.Errorf("expected authenticated catalog_expired rejection")
					}
					return nil
				})
			}
			phase("controller_restart_expired_approval", none)
			f.controller.apply(f.spec, 3600)
			f.nodeCall("refresh", "")
			for _, r := range f.recipients {
				r.require("refresh", -1, 0)
				for ep := 0; ep < 2; ep++ {
					r.require("apply", ep, 51820+ep)
				}
				r.ready()
			}
			for _, p := range f.plan.Paths {
				eventually(t, 10*time.Second, "fresh approval target "+p.PathID, func() error {
					if !f.probe(p).OK {
						return fmt.Errorf("target not restored")
					}
					return nil
				})
			}
			phase("fresh_approval_restored", all)
			report["restored_wireguard"] = f.checkPathWireGuard()
			completed = true
		})
	}
}

func (r *m3Recipient) awaitOffline(after time.Time, approved, ready bool) m3SupervisorReport {
	r.t.Helper()
	var v m3SupervisorReport
	eventually(r.t, 8*time.Second, "offline supervisor "+r.relay, func() error {
		b, err := os.ReadFile(r.watch.log)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &v); err != nil {
			return err
		}
		if !v.ObservedAt.After(after) || v.Refresh != "unavailable" || v.ApprovalValid != approved || v.Kernel == nil || v.Kernel.KernelReady != ready {
			return fmt.Errorf("unexpected offline state: %s", lines[len(lines)-1])
		}
		return nil
	})
	return v
}

// Check the exact candidate peer and actual bidirectional encrypted traffic;
// a UDP readiness exchange alone cannot satisfy these assertions.
func (f *m3AuthorityFixture) checkPathWireGuard() map[string]any {
	f.t.Helper()
	out := map[string]any{}
	for _, p := range f.plan.Paths {
		handshake := strings.Fields(netOutput(f.t, f.robot, "wg", "show", p.Pin.WGInterface, "latest-handshakes"))
		traffic := strings.Fields(netOutput(f.t, f.robot, "wg", "show", p.Pin.WGInterface, "transfer"))
		if len(handshake) != 2 || len(traffic) != 3 || handshake[0] != p.RelayPublicKey || traffic[0] != p.RelayPublicKey {
			f.t.Fatal("wrong WireGuard peer", p.PathID)
		}
		stamp, e1 := strconv.ParseInt(handshake[1], 10, 64)
		rx, e2 := strconv.ParseUint(traffic[1], 10, 64)
		tx, e3 := strconv.ParseUint(traffic[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || stamp <= 0 || rx == 0 || tx == 0 {
			f.t.Fatal("missing WireGuard handshake or bidirectional traffic", p.PathID)
		}
		out[p.PathID] = map[string]any{"handshake_unix": stamp, "rx_bytes": rx, "tx_bytes": tx, "peer": p.RelayPublicKey}
	}
	return out
}
