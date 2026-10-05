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

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayselect"
)

func TestNetns_M3TargetGuard(t *testing.T) {
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
			// Disposable direct fallback to the server: the target has a local address
			// on eth0, and answers packets arriving via this second veth too.
			netOutput(t, f.robot, "ip", "link", "add", "fallback0", "type", "veth", "peer", "name", "fallback1", "netns", f.target)
			netOutput(t, f.robot, "ip", "addr", "add", "203.0.113.1/30", "dev", "fallback0")
			netOutput(t, f.target, "ip", "addr", "add", "203.0.113.2/30", "dev", "fallback1")
			netOutput(t, f.robot, "ip", "link", "set", "fallback0", "up")
			netOutput(t, f.target, "ip", "link", "set", "fallback1", "up")
			netOutput(t, f.robot, "ip", "route", "add", "default", "via", "203.0.113.2", "dev", "fallback0")
			startNetworkProcess(t, f.target, filepath.Join(f.private, "other-echo.log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=203.0.113.2"}, f.worker, "-test.run=^TestNetworkWorker$")
			// A separate client forwards through the robot to the same app.
			// App quarantine must not take ownership of this transit traffic.
			transit := f.robot + "-t"
			run(t, ".", "ip", "netns", "add", transit)
			t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", transit).Run() })
			netOutput(t, transit, "ip", "link", "set", "lo", "up")
			netOutput(t, f.robot, "ip", "link", "add", "transit0", "type", "veth", "peer", "name", "transit1", "netns", transit)
			netOutput(t, f.robot, "ip", "addr", "add", "10.55.0.1/30", "dev", "transit0")
			netOutput(t, transit, "ip", "addr", "add", "10.55.0.2/30", "dev", "transit1")
			netOutput(t, f.robot, "ip", "link", "set", "transit0", "up")
			netOutput(t, transit, "ip", "link", "set", "transit1", "up")
			netOutput(t, transit, "ip", "route", "add", "default", "via", "10.55.0.1")
			netOutput(t, f.target, "ip", "route", "add", "10.55.0.0/30", "via", "203.0.113.1")
			(relayUplink{relay: f.robot}).forwarding(t, true)

			probeFrom := func(namespace, target string) m3Probe {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := netCommand(ctx, namespace, f.worker, "-test.run=^TestNetworkWorker$")
				cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE=", "VPNCTL_PROBE_TARGET="+target)
				b, err := cmd.Output()
				var out m3Probe
				if err != nil || json.Unmarshal(b, &out) != nil {
					t.Fatalf("app probe: %v %s", err, b)
				}
				return out
			}
			probe := func(target string) m3Probe { return probeFrom(f.robot, target) }
			call := func(action string, wantSuccess bool) relayapply.TargetGuardResult {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
				defer cancel()
				b, err := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "target", action, "--config", f.node, "--target-id", "app").CombinedOutput()
				var out relayapply.TargetGuardResult
				// Error text follows the one JSON result on failed CLI operations.
				if json.Unmarshal([]byte(strings.Split(string(b), "\n")[0]), &out) != nil || (err == nil) != wantSuccess {
					t.Fatalf("target %s: %v %s", action, err, b)
				}
				if out.Activated {
					t.Fatal("guard claimed activation", out)
				}
				return out
			}
			snapshot := func() string {
				return netOutput(t, f.robot, "ip", "-j", "-N", "-4", "route", "show", "table", "all") + netOutput(t, f.robot, "ip", "-j", "-N", "-4", "rule", "show")
			}
			phases := []string{}
			complete := false
			defer func() {
				writeM3Report(t, filepath.Join(f.results, "target-guard.json"), map[string]any{"completed": complete && !t.Failed(), "placement": placement, "phases": phases, "scope": "unbound IPv4 mark-zero target quarantine, source probes retained; no route activation or kernel expiry qualification"})
			}()
			eventually(t, 5*time.Second, "direct fallback baseline", func() error {
				p := probe(m3Target)
				if !p.OK || p.Source != "203.0.113.1" {
					return fmt.Errorf("wrong fallback %+v", p)
				}
				return nil
			})
			eventually(t, 5*time.Second, "unrelated target baseline", func() error {
				if p := probeFrom(transit, m3Target); !p.OK || p.Source != "10.55.0.2" {
					t.Fatal("transit interrupted", p)
				}
				if !probe("203.0.113.2").OK {
					return fmt.Errorf("unrelated target unavailable")
				}
				return nil
			})
			if p := probeFrom(transit, m3Target); !p.OK || p.Source != "10.55.0.2" {
				t.Fatal("transit baseline", p)
			}
			clean := snapshot()
			// An earlier foreign selector is preserved, and reservation has no effects.
			netOutput(t, f.robot, "ip", "rule", "add", "priority", "10000", "to", m3Target+"/32", "lookup", "main")
			foreign := snapshot()
			call("reserve", false)
			if snapshot() != foreign {
				t.Fatal("foreign priority rule altered")
			}
			netOutput(t, f.robot, "ip", "rule", "del", "priority", "10000", "to", m3Target+"/32", "lookup", "main")
			phases = append(phases, "foreign_rule_rejected_and_preserved")
			out := call("reserve", true)
			if !out.Guarded || out.Reservation == nil {
				t.Fatal(out)
			}
			reserved := snapshot()
			for i := 0; i < 3; i++ {
				call("reserve", true)
				call("inspect", true)
				call("recover", true)
				if snapshot() != reserved {
					t.Fatal("duplicate or changed reservation")
				}
				if p := probe(m3Target); p.OK || p.Failure != "unreachable" {
					t.Fatal("default bypass", p)
				}
				if p := probeFrom(transit, m3Target); !p.OK || p.Source != "10.55.0.2" {
					t.Fatal("transit interrupted", p)
				}
				if !probe("203.0.113.2").OK {
					t.Fatal("unrelated app interrupted")
				}
			}
			phases = append(phases, "unbound_default_blocked_unrelated_app_preserved", "repeated_operations_no_duplicates", "transit_to_same_target_preserved")
			// Candidate mutations share the journal and must retain target ownership.
			f.nodeCall("inspect", "")
			candidate := f.plan.Paths[0]
			f.nodeCall("release", candidate.PathID)
			call("inspect", true)
			if p := probe(m3Target); p.OK {
				t.Fatal("candidate release reopened target", p)
			}
			netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", candidate.PathID, "--probe-routes")
			call("inspect", true)
			// The recreated candidate has a new random owner metric. Compare
			// only resources untouched by subsequent target operations.
			call("release", true)
			clean = snapshot()
			out = call("reserve", true)
			phases = append(phases, "candidate_mutations_preserve_target_journal")
			// Product selector must still prove all four pinned candidate connections.
			b := netOutput(t, f.robot, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", "app", "--samples", "2", "--interval", "100ms")
			lines := strings.Split(strings.TrimSpace(b), "\n")
			var decision relayselect.Decision
			if json.Unmarshal([]byte(lines[len(lines)-1]), &decision) != nil || decision.DesiredPathID == "" || decision.Applied || len(decision.Candidates) != 4 {
				t.Fatal("candidate observation unavailable", b)
			}
			for _, candidate := range decision.Candidates {
				if candidate.State != "reachable" {
					t.Fatal(candidate)
				}
			}
			if p := probe(m3Target); p.OK {
				t.Fatal("selection opened target", p)
			}
			phases = append(phases, "all_candidate_probes_continue_without_activation")
			// Altering our table is a conflict. Release must preserve the foreign route.
			table := fmt.Sprint(out.Reservation.Table)
			netOutput(t, f.robot, "ip", "route", "add", "unreachable", "203.0.114.0/24", "table", table, "proto", "99")
			foreign = snapshot()
			call("inspect", false)
			call("release", false)
			if snapshot() != foreign {
				t.Fatal("foreign table content deleted")
			}
			netOutput(t, f.robot, "ip", "route", "del", "unreachable", "203.0.114.0/24", "table", table, "proto", "99")
			call("recover", true) // finishes the explicitly requested release
			if snapshot() != clean || !probe(m3Target).OK {
				t.Fatal("release failed to restore fallback")
			}
			phases = append(phases, "foreign_route_preserved_release_recovery")
			// Kill only this test's CLI after each new kernel mutation.
			faultDir := filepath.Join(f.private, "target-fault-bin")
			if err := os.Mkdir(faultDir, 0700); err != nil {
				t.Fatal(err)
			}
			ip, err := exec.LookPath("ip")
			if err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\n" + ip + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ] && { { [ \"$VPNCTL_TARGET_FAULT\" = route ] && [ \"$1 $2 $3 $4\" = '-4 route add unreachable' ]; } || { [ \"$VPNCTL_TARGET_FAULT\" = rule ] && [ \"$1 $2 $3\" = '-4 rule add' ]; }; }; then printf fired > \"$VPNCTL_TARGET_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
			if err = os.WriteFile(filepath.Join(faultDir, "ip"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			for _, point := range []string{"route", "rule"} {
				ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
				cmd := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", "app")
				marker := filepath.Join(f.private, "target-kill-"+point)
				cmd.Env = append(os.Environ(), "PATH="+faultDir+":"+os.Getenv("PATH"), "VPNCTL_TARGET_FAULT="+point, "VPNCTL_TARGET_MARKER="+marker)
				b, err := cmd.CombinedOutput()
				cancel()
				if err == nil || cmd.ProcessState == nil {
					t.Fatal("missing kill", point, string(b))
				}
				if s, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !s.Signaled() || s.Signal() != syscall.SIGKILL {
					t.Fatal("wrong kill", point, err)
				}
				if b, err := os.ReadFile(marker); err != nil || string(b) != "fired" {
					t.Fatal("mutation not exercised", point, err)
				}
				call("inspect", false)
				call("recover", true)
				if p := probe(m3Target); p.OK || p.Failure != "unreachable" {
					t.Fatal("recovery reopened default", p)
				}
				call("release", true)
				if snapshot() != clean || !probe(m3Target).OK {
					t.Fatal("crash recovery leaked resources")
				}
				phases = append(phases, "sigkill_recovery_"+point)
			}
			call("reserve", true)
			f.controller.process.stop()
			call("inspect", true)
			call("recover", true)
			if p := probe(m3Target); p.OK {
				t.Fatal("controller outage reopened target")
			}
			call("release", true)
			phases = append(phases, "controller_offline_reservation_retained")
			complete = true
		})
	}
}
