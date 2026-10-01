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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayplan"
)

func checkM3PreparedPaths(t *testing.T, robot string, relays []string, target, private, configPath string, relayKeys []string, plan relayplan.Plan, issuer *planIssuer) {
	t.Helper()
	bin := integrationBinary(t)
	results, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-prepare-")
	if err != nil {
		t.Fatal(err)
	}
	report := struct {
		SchemaVersion int      `json:"schema_version"`
		Completed     bool     `json:"completed"`
		Scope         string   `json:"scope"`
		Phases        []string `json:"phases"`
	}{SchemaVersion: 1, Scope: "production candidate/relay apply and kernel lease supervision; fixture mTLS approval issuer, forwarding/NAT and app routes; process/storage/expiry packet faults; no host clock/suspend/reboot or automatic failover/SLO qualification", Phases: []string{}}
	defer func() {
		report.Completed = report.Completed && !t.Failed()
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		if err = os.WriteFile(filepath.Join(results, "report.json"), b, 0600); err != nil {
			t.Error(err)
		}
	}()
	baseline := func() string {
		t.Helper()
		parts := []string{}
		for _, args := range [][]string{{"ip", "-j", "-4", "route", "show", "table", "all"}, {"ip", "-j", "-4", "rule", "show"}} {
			raw := netOutput(t, robot, args...)
			var values []any
			if err := json.Unmarshal([]byte(raw), &values); err != nil {
				t.Fatal(err)
			}
			canonical := []string{}
			for _, v := range values {
				b, _ := json.Marshal(v)
				canonical = append(canonical, string(b))
			}
			slices.Sort(canonical)
			parts = append(parts, strings.Join(canonical, "\n"))
		}
		parts = append(parts, netOutput(t, robot, "wg", "show", "plan-sentinel", "fwmark"))
		return strings.Join(parts, "\n")
	}
	beforeKernel := baseline()
	forbiddenSecret := ""
	call := func(action, path string, want bool) relayapply.Result {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		args := []string{"node", "relay", action, "--config", configPath}
		if path != "" {
			args = append(args, "--path-id", path)
		}
		cmd := netCommand(ctx, robot, append([]string{bin}, args...)...)
		b, err := cmd.CombinedOutput()
		if forbiddenSecret != "" && strings.Contains(string(b), forbiddenSecret) {
			t.Fatal("CLI exposed the external preshared key")
		}
		if (err == nil) != want {
			for _, read := range [][]string{{"ip", "-j", "-d", "link", "show"}, {"ip", "-j", "-N", "-4", "route", "show", "table", "all"}, {"ip", "-j", "-N", "-4", "rule", "show"}, {"wg", "show", "all", "fwmark"}} {
				t.Log(netOutput(t, robot, read...))
			}
			t.Fatalf("%s %s: %v %s", action, path, err, b)
		}
		// A failed CLI prints JSON then its bounded error to stderr.
		var out relayapply.Result
		if err := json.Unmarshal([]byte(strings.SplitN(string(b), "\n", 2)[0]), &out); err != nil {
			t.Fatalf("apply output: %v %s", err, b)
		}
		if out.UplinkHealth != "unknown" {
			t.Fatal("kernel setup advertised uplink health")
		}
		return out
	}
	first := plan.Paths[0]
	// Refuse preexisting resources without adopting or deleting them.
	netOutput(t, robot, "ip", "link", "add", first.Pin.WGInterface, "type", "wireguard")
	before := netOutput(t, robot, "ip", "-j", "link", "show", "dev", first.Pin.WGInterface)
	call("prepare", first.PathID, false)
	if before != netOutput(t, robot, "ip", "-j", "link", "show", "dev", first.Pin.WGInterface) {
		t.Fatal("foreign interface changed")
	}
	netOutput(t, robot, "ip", "link", "del", first.Pin.WGInterface)
	table := strconv.FormatUint(uint64(first.Pin.Table), 10)
	netOutput(t, robot, "ip", "route", "add", "unreachable", "203.0.113.0/24", "table", table)
	call("prepare", first.PathID, false)
	if !strings.Contains(netOutput(t, robot, "ip", "route", "show", "table", table), "203.0.113.0/24") {
		t.Fatal("foreign route deleted")
	}
	netOutput(t, robot, "ip", "route", "del", "unreachable", "203.0.113.0/24", "table", table)
	netOutput(t, robot, "ip", "rule", "add", "priority", "100", "fwmark", "0x76000000/0xff000000", "lookup", "123")
	call("prepare", first.PathID, false)
	netOutput(t, robot, "ip", "rule", "del", "priority", "100", "fwmark", "0x76000000/0xff000000", "lookup", "123")
	report.Phases = append(report.Phases, "foreign_interface_route_and_mark_mask_preserved")
	for _, p := range plan.Paths {
		out := call("prepare", p.PathID, true)
		if !out.KernelReady {
			t.Fatal("candidate not ready", out)
		}
		call("prepare", p.PathID, true)
	}
	if p := call("inspect", "", true); len(p.Paths) != 4 {
		t.Fatal("candidate count", p)
	}
	// A newly added external peer must prevent deleting the interface.
	netOutput(t, robot, "wg", "set", first.Pin.WGInterface, "peer", plan.Paths[1].PublicKey, "allowed-ips", "203.0.113.1/32")
	call("release", first.PathID, false)
	if !strings.Contains(netOutput(t, robot, "wg", "show", first.Pin.WGInterface, "peers"), plan.Paths[1].PublicKey) {
		t.Fatal("external peer deleted")
	}
	netOutput(t, robot, "wg", "set", first.Pin.WGInterface, "peer", plan.Paths[1].PublicKey, "remove")
	call("recover", "", true)
	call("prepare", first.PathID, true)
	report.Phases = append(report.Phases, "four_candidates_idempotent_prepare_and_external_peer_conflict")
	// A PSK on the approved peer changes the cryptographic configuration even
	// though peer identity, endpoint and AllowedIPs still match the approval.
	forbiddenSecret, _ = wgKeyPair(t)
	pskFile := filepath.Join(private, "external-prepare.psk")
	mustWrite(t, pskFile, forbiddenSecret)
	netOutput(t, robot, "wg", "set", first.Pin.WGInterface, "peer", first.RelayPublicKey, "preshared-key", pskFile)
	if out := call("inspect", "", false); out.KernelReady {
		t.Fatal("unapproved preshared key reported ready")
	}
	call("prepare", first.PathID, false)
	call("release", first.PathID, false)
	if strings.TrimSpace(netOutput(t, robot, "wg", "show", first.Pin.WGInterface, "public-key")) != first.PublicKey {
		t.Fatal("interface carrying external PSK was changed")
	}
	netOutput(t, robot, "wg", "set", first.Pin.WGInterface, "peer", first.RelayPublicKey, "preshared-key", "/dev/null")
	call("recover", "", true)
	call("prepare", first.PathID, true)
	report.Phases = append(report.Phases, "external_preshared_key_conflict_without_secret_disclosure")
	relayInterfaces, releaseRelays, lease := checkM3RelayApply(t, relays, private, configPath, relayKeys, plan, issuer, &report.Phases)
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	echo := startNetworkProcess(t, target, filepath.Join(private, "prepare-echo.log"), []string{"VPNCTL_WORKER=m3-echo"}, worker, "-test.run=^TestNetworkWorker$")
	defer echo.stop()
	for i, p := range plan.Paths {
		netOutput(t, robot, "ip", "route", "add", m3Target+"/32", "dev", p.Pin.WGInterface, "src", strings.TrimSuffix(p.InnerAddress, "/32"))
		deadline := time.Now().Add(10 * time.Second)
		var probe m3Probe
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			cmd := netCommand(ctx, robot, worker, "-test.run=^TestNetworkWorker$")
			cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe")
			b, e := cmd.Output()
			cancel()
			if e != nil || json.Unmarshal(b, &probe) != nil {
				t.Fatal("prepare probe failed", e)
			}
			if probe.OK || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !probe.OK || probe.Source != fmt.Sprintf("198.18.0.%d", 11+i/2) {
			t.Fatal("prepared candidate cannot reach target", p.PathID, probe)
		}
		actual := netOutput(t, relays[i/2], "wg", "show", relayInterfaces[i/2][i%2], "endpoints")
		if !strings.Contains(actual, p.PublicKey) || !strings.Contains(actual, p.Pin.Source+":") {
			t.Fatal("outer UDP source differs", actual)
		}
		report.Phases = append(report.Phases, "wireguard_source_and_target_echo_"+p.PathID)
		if i == 1 {
			lease.checkPause(robot, 0, relayInterfaces[0][1], "stop", &report.Phases)
		}
		if i == 3 {
			lease.checkPause(robot, 1, relayInterfaces[1][1], "kill", &report.Phases)
			lease.checkPause(robot, 1, relayInterfaces[1][1], "enospc", &report.Phases)
			lease.checkExpiry(robot, relayInterfaces, &report.Phases)
		}
		if i == 0 {
			// A tempting main-table route on the other physical network must
			// never receive marked packets when the candidate route disappears.
			dst := strings.Split(p.Endpoint, ":")[0]
			mark := strconv.FormatUint(uint64(p.Pin.FWMark), 10)
			lookup := func(want bool) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				b, e := netCommand(ctx, robot, "ip", "-j", "-4", "route", "get", dst, "mark", mark).CombinedOutput()
				if (e == nil) != want {
					t.Fatalf("marked lookup: %v %s", e, b)
				}
				if want && (!strings.Contains(string(b), p.Pin.Interface) || !strings.Contains(string(b), p.Pin.Source)) {
					t.Fatal("wrong pin", string(b))
				}
			}
			lookup(true)
			netOutput(t, robot, "ip", "route", "add", dst+"/32", "dev", "wan1", "src", "198.51.100.10")
			netOutput(t, robot, "nft", "add", "table", "ip", "prepare_check")
			netOutput(t, robot, "nft", "add", "chain", "ip", "prepare_check", "output", "{ type filter hook output priority 0; policy accept; }")
			netOutput(t, robot, "nft", "add", "rule", "ip", "prepare_check", "output", "oifname", "wan1", "ip", "daddr", dst, "udp", "dport", "51820", "counter")
			checkBlocked := func() {
				t.Helper()
				lookup(false)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := netCommand(ctx, robot, worker, "-test.run=^TestNetworkWorker$")
				cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe")
				b, e := cmd.Output()
				var got m3Probe
				if e != nil || json.Unmarshal(b, &got) != nil || got.OK {
					t.Fatal("blocked path transmitted", e, string(b))
				}
				counter := netOutput(t, robot, "nft", "list", "chain", "ip", "prepare_check", "output")
				if !strings.Contains(counter, "counter packets 0 bytes 0") {
					t.Fatal("outer UDP escaped through other underlay", counter)
				}
			}
			netOutput(t, robot, "ip", "route", "del", p.Pin.EndpointPrefix, "table", table)
			checkBlocked()
			netOutput(t, robot, "ip", "link", "set", "wan0", "down")
			checkBlocked()
			netOutput(t, robot, "ip", "link", "set", "wan0", "up")
			report.Phases = append(report.Phases, "endpoint_delete_and_link_down_block_fallback_udp")
			netOutput(t, robot, "ip", "route", "del", dst+"/32")
			netOutput(t, robot, "nft", "delete", "table", "ip", "prepare_check")
			// Link loss invalidated all candidates on wan0. They are released
			// and prepared again after removing this fixture-owned app route.
			netOutput(t, robot, "ip", "route", "del", m3Target+"/32")
			for _, other := range plan.Paths {
				if other.UnderlayID == p.UnderlayID {
					call("release", other.PathID, true)
					call("prepare", other.PathID, true)
				}
			}
			continue
		}
		netOutput(t, robot, "ip", "route", "del", m3Target+"/32")
	}
	for _, p := range plan.Paths {
		call("release", p.PathID, true)
	}
	if out := call("inspect", "", true); out.State != "empty" {
		t.Fatal("owned resources not released", out)
	}
	// This case proves gateway installation/readback, not forwarding through
	// the fixture gateway (which has no forwarding policy for this transit).
	netOutput(t, robot, "ip", "route", "add", first.Pin.EndpointPrefix, "via", "192.0.2.12", "dev", "wan0")
	call("prepare", first.PathID, true)
	if routes := netOutput(t, robot, "ip", "route", "show", "table", table); !strings.Contains(routes, "via 192.0.2.12") {
		t.Fatal("gateway lost", routes)
	}
	call("release", first.PathID, true)
	netOutput(t, robot, "ip", "route", "del", first.Pin.EndpointPrefix)
	report.Phases = append(report.Phases, "gateway_install_readback_release")
	releaseRelays()
	// Kill the real CLI at four boundaries after successful kernel mutations. The wrapper
	// never reads stdin (the WG key), and the next process owns recovery.
	faultDir := filepath.Join(private, "fault-bin")
	if err = os.Mkdir(faultDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"ip", "wg"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\n" + real + " \"$@\"\nstatus=$?\nif [ \"$status\" = 0 ] && [ \"$*\" = \"$VPNCTL_TEST_KILL_AFTER\" ]; then printf fired > \"$VPNCTL_TEST_KILL_MARKER\"; kill -KILL \"$PPID\"; fi\nexit \"$status\"\n"
		// The link step contains per-attempt random values, so it is matched by prefix.
		script = strings.Replace(script, "[ \"$*\" = \"$VPNCTL_TEST_KILL_AFTER\" ]", "{ [ \"$*\" = \"$VPNCTL_TEST_KILL_AFTER\" ] || { [ \"$VPNCTL_TEST_KILL_AFTER\" = link-create ] && [ \"$1 $2\" = 'link add' ]; }; }", 1)
		if err = os.WriteFile(filepath.Join(faultDir, tool), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for pointIndex, point := range []string{"link-create", "-4 rule add priority " + strconv.FormatUint(uint64(first.Pin.RulePriority), 10) + " fwmark " + strconv.FormatUint(uint64(first.Pin.FWMark), 10) + "/0xffffffff lookup " + table + " protocol 186", "setconf " + first.Pin.WGInterface + " /dev/stdin", "link set dev " + first.Pin.WGInterface + " up"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := netCommand(ctx, robot, bin, "node", "relay", "prepare", "--config", configPath, "--path-id", first.PathID)
		marker := filepath.Join(private, fmt.Sprintf("kill-%d", pointIndex))
		cmd.Env = append(os.Environ(), "PATH="+faultDir+":"+os.Getenv("PATH"), "VPNCTL_TEST_KILL_AFTER="+point, "VPNCTL_TEST_KILL_MARKER="+marker)
		b, e := cmd.CombinedOutput()
		cancel()
		if e == nil {
			t.Fatal("CLI was not killed", point, string(b))
		}
		if data, err := os.ReadFile(marker); err != nil || string(data) != "fired" {
			t.Fatal("fault point was not exercised", point, err, string(b))
		}
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("CLI did not die by injected SIGKILL", e)
		}
		if out := call("recover", "", true); out.State != "empty" {
			t.Fatal("crashed prepare not recovered", out)
		}
		call("prepare", first.PathID, true)
		call("release", first.PathID, true)
		report.Phases = append(report.Phases, fmt.Sprintf("sigkill_recovery_%d", pointIndex))
	}
	if after := baseline(); after != beforeKernel {
		t.Fatal("unrelated routes/rules/sentinel changed")
	}
	report.Phases = append(report.Phases, "original_routes_rules_and_sentinel_preserved")
	report.Completed = true
	t.Log("M3 prepare: production CLI prepares four candidates and relay peers/return routes; fixture forwarding/NAT and target route yield real WG/source/target proof; exact release")
}
