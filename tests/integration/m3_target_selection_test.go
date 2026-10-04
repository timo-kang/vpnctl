//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayselect"
)

// This is product observation and desired-path selection, NOT app route apply.
// Remove all fixture source routes first; SO_BINDTODEVICE must prove each WG
// candidate while an ordinary unbound application still has no uplink route.
func TestNetns_M3TargetSelection(t *testing.T) {
	requireNetwork(t)
	for _, placement := range []string{"colocated", "separate"} {
		t.Run(placement, func(t *testing.T) {
			f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: placement == "separate", independentRecipients: true})
			for i, p := range f.plan.Paths {
				table := fmt.Sprint(28000 + i)
				netOutput(t, f.robot, "ip", "rule", "del", "priority", table)
				netOutput(t, f.robot, "ip", "route", "del", m3Target+"/32", "table", table)
				f.nodeCall("release", p.PathID)
				netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", p.PathID, "--probe-routes")
			}
			snapshot := func() string {
				return netOutput(t, f.robot, "ip", "-j", "-4", "route", "show", "table", "all") + netOutput(t, f.robot, "ip", "-j", "-4", "rule", "show")
			}
			before := snapshot()
			t.Log("robot rp_filter", netOutput(t, f.robot, "cat", "/proc/sys/net/ipv4/conf/all/rp_filter"))
			t.Cleanup(func() {
				writeM3Report(t, filepath.Join(f.results, "robot-kernel.json"), map[string]any{
					"routes_rules": snapshot(),
					"transfer":     netOutput(t, f.robot, "wg", "show", "all", "transfer"),
					"handshakes":   netOutput(t, f.robot, "wg", "show", "all", "latest-handshakes"),
					"counters":     netOutput(t, f.robot, "cat", "/proc/net/netstat"),
				})
			})
			phases := []map[string]any{}
			complete := false
			defer func() {
				writeM3Report(t, filepath.Join(f.results, "target-selection.json"), map[string]any{"completed": complete && !t.Failed(), "placement": placement, "scope": "candidate TCP observations and desired path; applied=false, no application route selection", "phases": phases})
			}()
			logfile := filepath.Join(f.results, "target-selection.ndjson")
			watcher := startNetworkProcess(t, f.robot, logfile, nil, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", "app", "--watch", "--interval", "100ms", "--hold-down", "2s", "--minimum-dwell", "3s")
			after := time.Now()
			await := func(name, path string, healthy map[string]bool) relayselect.Decision {
				t.Helper()
				var d relayselect.Decision
				eventually(t, 40*time.Second, name, func() error {
					b, err := os.ReadFile(logfile)
					if err != nil {
						return err
					}
					// The last write may be partial; use the most recent complete JSON line.
					lines := strings.Split(string(b), "\n")
					found := false
					for i := len(lines) - 2; i >= 0; i-- {
						var value relayselect.Decision
						if json.Unmarshal([]byte(lines[i]), &value) == nil {
							d = value
							found = true
							break
						}
					}
					if !found || !d.ObservedAt.After(after) || d.DesiredPathID != path || d.Applied {
						return fmt.Errorf("waiting for %s: state=%s reason=%s desired=%s", name, d.State, d.Reason, d.DesiredPathID)
					}
					if len(d.Candidates) != 4 {
						return fmt.Errorf("missing candidate evidence: %+v", d)
					}
					for _, c := range d.Candidates {
						if (c.State == "reachable") != healthy[c.PathID] {
							return fmt.Errorf("candidate %s=%s, want reachable=%v", c.PathID, c.State, healthy[c.PathID])
						}
					}
					return nil
				})
				phases = append(phases, map[string]any{"name": name, "decision": d})
				if snapshot() != before {
					t.Fatal("observation/selection changed routes or rules")
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if b, err := netCommand(ctx, f.robot, "ip", "route", "get", m3Target).CombinedOutput(); err == nil {
					t.Fatal("unbound application unexpectedly gained a route", string(b))
				}
				return d
			}
			all := map[string]bool{"p00": true, "p01": true, "p10": true, "p11": true}
			await("baseline_all_candidates", "p00", all)
			f.controller.process.stop()
			after = time.Now()
			await("controller_offline_cached_candidates", "p00", all)

			// Packet loss, not route changes: retain owned transport inventory so a
			// failed candidate cannot borrow a working underlay or alternate relay.
			(relayUplink{relay: f.robot}).nft(t, `table inet target_selection_fault {
 chain output { type filter hook output priority filter; policy accept;
 oifname "wan0" udp dport { 51820, 51821 } drop
 }
}`)
			after = time.Now()
			await("underlay0_packet_blackhole", "p01", map[string]bool{"p01": true, "p11": true})
			netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "down")
			after = time.Now()
			await("relay0_down_with_controller_offline", "p11", map[string]bool{"p11": true})
			netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "down")
			after = time.Now()
			d := await("all_targets_unreachable", "", map[string]bool{})
			if d.State != "no_verified_path" {
				t.Fatal(d)
			}
			netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "up")
			after = time.Now()
			await("alternate_recovers", "p11", map[string]bool{"p11": true})
			netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "up")
			netOutput(t, f.robot, "nft", "delete", "table", "inet", "target_selection_fault")
			after = time.Now()
			await("preferred_recovers_after_confirmation", "p00", all)

			// A foreign peer is an ownership conflict; observing must neither adopt
			// it nor remove it. The other approved path remains selectable.
			_, foreign := wgKeyPair(t)
			iface := ""
			for _, p := range f.plan.Paths {
				if p.PathID == "p00" {
					iface = p.Pin.WGInterface
				}
			}
			netOutput(t, f.robot, "wg", "set", iface, "peer", foreign, "allowed-ips", "203.0.113.5/32")
			after = time.Now()
			d = await("foreign_peer_preserved", "p01", map[string]bool{"p01": true, "p10": true, "p11": true})
			if !strings.Contains(netOutput(t, f.robot, "wg", "show", iface, "peers"), foreign) {
				t.Fatal("foreign peer removed")
			}
			for _, c := range d.Candidates {
				if c.PathID == "p00" && c.State != "unknown" {
					t.Fatal(c)
				}
			}
			watcher.stop()
			// Manual pin does not silently use the healthy alternate.
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			b, err := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", "app", "--mode", "manual", "--path-id", "p00", "--samples", "2", "--interval", "100ms").CombinedOutput()
			cancel()
			if err == nil {
				t.Fatal("manual pin unexpectedly succeeded", string(b))
			}
			var manual relayselect.Decision
			for _, line := range strings.Split(string(b), "\n") {
				var v relayselect.Decision
				if json.Unmarshal([]byte(line), &v) == nil {
					manual = v
				}
			}
			if manual.DesiredPathID != "" || manual.Reason != "manual_pin_unavailable" {
				t.Fatal("manual fallback", string(b))
			}
			phases = append(phases, map[string]any{"name": "manual_pin_blocks", "decision": manual})
			if snapshot() != before {
				t.Fatal("manual selector mutated routes")
			}
			netOutput(t, f.robot, "wg", "set", iface, "peer", foreign, "remove")
			for _, p := range f.plan.Paths {
				f.nodeCall("release", p.PathID)
			}
			clean := snapshot()
			// Real process death after the new target route and source rule. Recovery
			// must remove exactly the journaled candidate and restore the clean table.
			faultDir := filepath.Join(f.private, "probe-fault-bin")
			if err := os.Mkdir(faultDir, 0700); err != nil {
				t.Fatal(err)
			}
			ip, err := exec.LookPath("ip")
			if err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\n" + ip + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ] && { { [ \"$VPNCTL_PROBE_FAULT\" = route ] && [ \"$1 $2 $3 $4\" = '-4 route add 198.18.0.2/32' ]; } || { [ \"$VPNCTL_PROBE_FAULT\" = source ] && [ \"$1 $2 $3\" = '-4 rule add' ] && [ \"$6\" = from ]; }; }; then printf fired > \"$VPNCTL_PROBE_FAULT_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
			if err = os.WriteFile(filepath.Join(faultDir, "ip"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			for _, point := range []string{"route", "source"} {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				cmd := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", f.plan.Paths[0].PathID, "--probe-routes")
				marker := filepath.Join(f.private, "probe-kill-"+point)
				cmd.Env = append(os.Environ(), "PATH="+faultDir+":"+os.Getenv("PATH"), "VPNCTL_PROBE_FAULT="+point, "VPNCTL_PROBE_FAULT_MARKER="+marker)
				b, err := cmd.CombinedOutput()
				cancel()
				if err == nil {
					t.Fatal("probe prepare not killed", point, string(b))
				}
				if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("wrong process fault", err)
				}
				if markerData, err := os.ReadFile(marker); err != nil || string(markerData) != "fired" {
					t.Fatal("fault point not exercised", point, err)
				}
				f.nodeCall("recover", "")
				if snapshot() != clean {
					t.Fatal("probe-route crash left resources", point)
				}
				phases = append(phases, map[string]any{"name": "sigkill_recovery_" + point})
			}
			complete = true
		})
	}
}
