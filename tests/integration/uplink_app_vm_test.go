//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/uplinkclient"
)

// Progress is a sampled upper bound. It is never an API receipt timestamp or
// proof that the selector's TCP probe authenticated the application service.
type appVMProgress struct {
	Snapshot uint64            `json:"snapshot_boot_ns,string"`
	API      uplinkclient.View `json:"api"`
	Records  uint64            `json:"api_records"`
	Payload  struct {
		Attempts    uint64 `json:"attempts"`
		Connections uint64 `json:"authenticated_connections"`
		Correct     uint64 `json:"correct"`
		Last        uint64 `json:"last_correct_boot_ns,string"`
	} `json:"payload"`
}

func appVMBoot(t *testing.T) uint64 {
	t.Helper()
	_, ns, err := relayapply.LocalUplinkClock()
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func appVMRead(t *testing.T, path string) appVMProgress {
	t.Helper()
	var r appVMProgress
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 16384 || json.Unmarshal(b, &r) != nil || r.Snapshot == 0 {
		t.Fatal("missing or invalid bounded app progress", path)
	}
	return r
}

// drainAppVMClient gives failed trials the same chance to emit final request
// events as the normal termination path. It never changes the test verdict or
// stops another client's cleanup. These clients write directly to files, so
// Wait joins only the child (there is no inherited stdout pipe to drain).
func drainAppVMClient(p *networkProcess, timeout time.Duration) string {
	if p == nil {
		return "not_started"
	}
	if p.stopped {
		return "already_stopped"
	}
	p.stopped = true
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return "failed"
		}
		return "drained"
	case <-timer.C:
		_ = p.cmd.Process.Kill()
		<-done
		return "forced"
	}
}

// All mutations below require a provisioned VM identity before fixture/cgroup
// creation. Neither the host namespace nor physical network devices are used.
func TestVMUplinkApplications(t *testing.T) {
	if os.Getenv("VPNCTL_VM_WORKER") != "1" {
		t.Skip("requires disposable VM runner")
	}
	requireIsolatedGuest(t)
	paths, err := strconv.Atoi(os.Getenv("VPNCTL_APP_PATHS"))
	if err != nil || paths != 4 && paths != 8 || runtime.NumCPU() != 2 {
		t.Fatal("explicit 4/8 paths and split two-vCPU guest required")
	}
	server := newCapacityGroup(t, "1", "1")
	server.scope = "controller-relays-and-measurement"
	server.moveWorker(t)
	hypothesis := os.Getenv("VPNCTL_APP_HYPOTHESIS")
	robotCPU := "0.5"
	if hypothesis != "" {
		robotCPU = os.Getenv("VPNCTL_APP_DIAGNOSTIC_CPU")
		if paths != 8 || (hypothesis != "control" && hypothesis != "api" && hypothesis != "stall") || (robotCPU != "0.5" && robotCPU != "1") {
			t.Fatal("invalid isolated diagnostic profile")
		}
	}
	robot := newCapacityGroup(t, robotCPU, "0")
	robot.scope = "robot-supervisor-two-actuators-and-two-apps"
	f := applicationFixtureWithGroup(t, true, paths, false, robot.file)
	// The older deployment fixture forwards/SNATs only its plaintext probe
	// port. Add this trial's TLS service to that fixture-owned chain; product
	// source/target ACLs and lease guards still run first and remain unchanged.
	for i, r := range f.recipients {
		var interfaces []string
		for _, ep := range r.require("inspect", -1, 0).Endpoints {
			interfaces = append(interfaces, strconv.Quote(ep.Interface))
		}
		(relayUplink{relay: r.ns}).nft(t, fmt.Sprintf(`add rule ip m3 forward iifname { %s } oifname "uplink0" ip daddr { 198.18.0.2, 198.18.0.3 } tcp dport 9193 counter accept
add rule ip m3 postrouting oifname "uplink0" ip saddr 10.78.0.0/16 ip daddr { 198.18.0.2, 198.18.0.3 } tcp dport 9193 counter snat to 198.18.0.%d
`, strings.Join(interfaces, ", "), 11+i))
	}
	report := map[string]any{"schema_version": 1, "paths": paths, "cpu_layout": "split",
		"resource_profile": robot.evidence(t), "server_resource_profile": server.evidence(t),
		"phase_watchdog_seconds": 75, "blocked_window_seconds": 20,
		"app_slo_ns": nil, "server_session_seconds": 600, "server_max_requests": 12000,
		"selector_probe_port": 9192, "application_tls_port": 9193,
		"publication_boot_ns": nil, "receipt_boot_ns": nil, "route_applied_boot_ns": nil}
	if hypothesis != "" {
		report["diagnostic_mode"] = hypothesis
		report["diagnostic_robot_cpu"] = robotCPU
		report["diagnostic_window_seconds"] = 45
	}
	phases := []map[string]any{}
	var clients [2]*networkProcess
	clientCleanup := map[string]string{}
	report["client_cleanup"] = clientCleanup
	// Registered before process cleanups: failures preserve available final/progress
	// evidence after bounded client drain. Cleanup-time responses are diagnostic
	// only: they cannot finish a phase or qualify a failed trial.
	t.Cleanup(func() {
		report["completed"] = !t.Failed()
		report["phases"] = phases
		report["resource_profile_after"] = robot.evidence(t)
		report["server_resource_profile_after"] = server.evidence(t)
		for i, name := range []string{"app", "app2"} {
			if clients[i] != nil {
				var value map[string]any
				b, _ := os.ReadFile(clients[i].log)
				if len(b) <= 4*1024*1024 && json.Unmarshal(b, &value) == nil {
					report[name] = value
				}
			}
			var sampled map[string]any
			if b, err := os.ReadFile(filepath.Join(f.results, "progress-"+name+".json")); err == nil && len(b) <= 16384 && json.Unmarshal(b, &sampled) == nil {
				report["last_progress_"+name] = sampled
			}
			report["last_route_"+name] = latestApplicationResult(filepath.Join(f.results, "watch-"+name+".jsonl"))
		}
		writeM3Report(t, filepath.Join(f.results, "uplink-applications.json"), report)
	})

	ca, caKey := filepath.Join(f.private, "echo-ca.pem"), filepath.Join(f.private, "echo-ca.key")
	cert, key := filepath.Join(f.private, "echo.pem"), filepath.Join(f.private, "echo.key")
	if err := pki.GenerateCA(caKey, ca, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateServerCert(ca, caKey, key, cert, []string{"uplink.test"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	const root = "/opt/vpnctl-vm"
	serverCommand := []string{"python3", "-B", root + "/uplink-python/echo_server.py", "--host", "0.0.0.0", "--port", "9193",
		"--cert", cert, "--key", key, "--duration", "600", "--session-seconds", "600", "--max-requests", "12000"}
	if hypothesis != "" {
		serverCommand = append(serverCommand, "--diagnostics")
	}
	startNetworkProcess(t, f.target, filepath.Join(f.results, "echo-server.log"), nil, serverCommand...)

	applicationFallback(t, f)
	addresses := []string{m3Target, "198.18.0.3"}
	var dirs, progress, watchLogs [2]string
	var watches [2]*networkProcess
	// An actually usable fallback must exist before testing that reservations
	// prevent retry from escaping. Reuse the same authenticated TLS service.
	for i, name := range []string{"app", "app2"} {
		nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "release", "--config", f.node, "--target-id", name)
		probe := startNetworkProcessInGroup(t, robot.file, f.robot, filepath.Join(f.results, "fallback-"+name+".json"), []string{"GOMAXPROCS=1"},
			root+"/uplink-go", "--address", addresses[i]+":9193", "--server-name", "uplink.test", "--ca", ca,
			"--runtime", "/nonexistent/vpnctl-fixture", "--target", name, "--duration", "2s")
		probe.finishWithin(t, 5*time.Second)
		if r := appVMRead(t, probe.log); r.Payload.Correct == 0 {
			t.Fatal("TLS fallback baseline absent", name)
		}
		nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", name)
		dirs[i], progress[i] = apiRuntime(t, f, name), filepath.Join(f.results, "progress-"+name+".json")
		watchLogs[i] = filepath.Join(f.results, "watch-"+name+".jsonl")
	}
	report["authenticated_default_fallback_baseline"] = true
	startWatch := func(i int) *networkProcess {
		name := []string{"app", "app2"}[i]
		return startNetworkProcessInGroup(t, robot.file, f.robot, watchLogs[i], nil,
			integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", name,
			"--watch", "--interval", "500ms", "--probe-timeout", "150ms", "--hold-down", "10s", "--minimum-dwell", "15s",
			"--uplink-api-dir", dirs[i], "--uplink-api-allow-uids", "0")
	}
	for i, name := range []string{"app", "app2"} {
		watches[i] = startWatch(i)
		command, duration := []string{root + "/uplink-go"}, "580s"
		if i == 1 {
			command, duration = []string{"python3", "-B", root + "/uplink-python/main.py"}, "580"
		}
		command = append(command, "--address", addresses[i]+":9193", "--server-name", "uplink.test", "--ca", ca,
			"--runtime", dirs[i], "--server-uid", "0", "--target", name, "--duration", duration, "--progress", progress[i])
		clients[i] = startNetworkProcessInGroup(t, robot.file, f.robot, filepath.Join(f.results, "client-"+name+".json"), []string{"GOMAXPROCS=1"}, command...)
		// Register immediately, before membership/readiness can fail. LIFO runs
		// this before the generic forced stop and before report collection.
		client := clients[i]
		t.Cleanup(func() { clientCleanup[name] = drainAppVMClient(client, 12*time.Second) })
		robot.requireMembership(t, watches[i].cmd.Process.Pid, true)
		robot.requireMembership(t, clients[i].cmd.Process.Pid, true)
		eventually(t, 5*time.Second, "app progress ready", func() error { _, err := os.Stat(progress[i]); return err })
	}
	robot.requireMembership(t, f.nodeSupervisor.cmd.Process.Pid, true)
	server.requireMembership(t, f.controller.process.cmd.Process.Pid, true)
	for _, r := range f.recipients {
		server.requireMembership(t, r.watch.cmd.Process.Pid, true)
	}
	report["role_membership_verified"] = true

	// A phase timeout reports failed/unrecovered evidence; it is not an app SLO.
	// Blocking phases deliberately last 20 s, enough for multiple capped retries.
	var diagnosticWindowStart uint64
	phase := func(name string, healthy [2]bool, path string, action func(), extra func([2]appVMProgress) bool) {
		t.Helper()
		p := map[string]any{"name": name, "started_boot_ns": strconv.FormatUint(appVMBoot(t), 10), "healthy": healthy}
		phases = append(phases, p)
		if action != nil {
			action()
		}
		cutoff := appVMBoot(t)
		if name == "diagnostic_window" {
			diagnosticWindowStart = cutoff
		}
		p["fault_completed_boot_ns"] = strconv.FormatUint(cutoff, 10)
		before := [2]appVMProgress{appVMRead(t, progress[0]), appVMRead(t, progress[1])}
		p["before"] = before
		blocked := !healthy[0] || !healthy[1]
		var sampled [2]appVMProgress
		eventually(t, 75*time.Second, "app phase "+name, func() error {
			for i := range sampled {
				sampled[i] = appVMRead(t, progress[i])
				if sampled[i].Snapshot <= cutoff {
					return fmt.Errorf("awaiting new progress")
				}
				if healthy[i] && (sampled[i].Payload.Correct <= before[i].Payload.Correct+1 || sampled[i].Payload.Last <= cutoff) {
					return fmt.Errorf("awaiting post-fault authenticated app %d", i)
				}
				if !healthy[i] && sampled[i].Payload.Attempts < before[i].Payload.Attempts+2 {
					return fmt.Errorf("awaiting repeated retry %d", i)
				}
				if path != "" {
					r := latestApplicationResult(watchLogs[i])
					if !r.Applied || r.Selection.DesiredPathID != path {
						return fmt.Errorf("awaiting route %s for %d", path, i)
					}
				}
			}
			if blocked && appVMBoot(t)-cutoff < uint64(20*time.Second) {
				return fmt.Errorf("blocked observation window")
			}
			if extra != nil && !extra(sampled) {
				return fmt.Errorf("awaiting phase-specific evidence")
			}
			return nil
		})
		p["after"], p["finished_boot_ns"] = sampled, strconv.FormatUint(appVMBoot(t), 10)
		p["route_sampled_boot_ns"] = strconv.FormatUint(appVMBoot(t), 10)
		p["routes"] = [2]relayapply.TargetReconcileResult{latestApplicationResult(watchLogs[0]), latestApplicationResult(watchLogs[1])}
		if blocked {
			// A dead/expired test server must not masquerade as approval or
			// fallback isolation. Verify TLS locally after each blocked window,
			// outside the robot routes and the target-IP service fault rule.
			check := startNetworkProcess(t, f.target, filepath.Join(f.results, "server-check-"+name+".json"), []string{"GOMAXPROCS=1"},
				root+"/uplink-go", "--address", "127.0.0.1:9193", "--server-name", "uplink.test", "--ca", ca,
				"--runtime", "/nonexistent/vpnctl-fixture", "--duration", "1s")
			check.finishWithin(t, 5*time.Second)
			alive := appVMRead(t, check.log)
			if alive.Payload.Correct == 0 || alive.Payload.Last <= sampled[0].Snapshot {
				t.Fatal("blocked phase has no independent live TLS service", name)
			}
			p["server_check"] = alive
		}
	}
	both := [2]bool{true, true}
	none := [2]bool{}
	phase("baseline", both, "p00", nil, func(r [2]appVMProgress) bool {
		return r[0].Records > 0 && r[1].Records > 0 && r[0].API.APIAvailable && r[1].API.APIAvailable
	})
	initial := [2]appVMProgress{appVMRead(t, progress[0]), appVMRead(t, progress[1])}
	if hypothesis != "" {
		initial = phases[0]["after"].([2]appVMProgress)
		report["diagnostic_resource_before"] = robot.evidence(t)
		phase("diagnostic_window", both, "p00", func() {
			fault := map[string]any{"started_boot_ns": strconv.FormatUint(appVMBoot(t), 10)}
			report["diagnostic_fault"] = fault
			if hypothesis == "api" {
				for _, dir := range dirs {
					if err := os.Rename(filepath.Join(dir, "uplink.sock"), filepath.Join(dir, "offline.sock")); err != nil {
						t.Fatal(err)
					}
				}
			} else if hypothesis == "stall" {
				// Positive control: only this disposable guest's Go app pauses.
				// Resume even if the action fails; never pause the guest/host.
				func() {
					defer clients[0].cmd.Process.Signal(syscall.SIGCONT)
					if err := clients[0].cmd.Process.Signal(syscall.SIGSTOP); err != nil {
						t.Fatal(err)
					}
					time.Sleep(3 * time.Second)
					if err := clients[0].cmd.Process.Signal(syscall.SIGCONT); err != nil {
						t.Fatal(err)
					}
				}()
			}
			fault["completed_boot_ns"] = strconv.FormatUint(appVMBoot(t), 10)
		}, func(r [2]appVMProgress) bool {
			wantAPI := hypothesis != "api"
			return appVMBoot(t)-diagnosticWindowStart >= uint64(45*time.Second) && r[0].API.APIAvailable == wantAPI && r[1].API.APIAvailable == wantAPI
		})
		report["diagnostic_resource_after"] = robot.evidence(t)
		for i := range clients {
			current := appVMRead(t, progress[i])
			if current.Payload.Connections != initial[i].Payload.Connections {
				t.Fatalf("diagnostic app %d replaced initial authenticated connection", i)
			}
		}
		for _, client := range clients {
			client.terminate(t)
		}
		return // Diagnostic windows never qualify the original 15-phase trial.
	}
	phase("api_outage", both, "p00", func() {
		// Existing streams expire naturally; selectors and routes keep running.
		for _, dir := range dirs {
			if err := os.Rename(filepath.Join(dir, "uplink.sock"), filepath.Join(dir, "offline.sock")); err != nil {
				t.Fatal(err)
			}
		}
	}, func(r [2]appVMProgress) bool { return !r[0].API.APIAvailable && !r[1].API.APIAvailable })
	// Require fresh payload after outage has actually been observed, not merely
	// counters accumulated during the existing API stream's drain time.
	phase("api_outage_payload", both, "p00", nil, func(r [2]appVMProgress) bool {
		return !r[0].API.APIAvailable && !r[1].API.APIAvailable && r[0].Payload.Connections == initial[0].Payload.Connections && r[1].Payload.Connections == initial[1].Payload.Connections
	})
	phase("producer_restart", both, "p00", func() {
		for i := range watches {
			watches[i].terminate(t)
			watches[i] = startWatch(i)
			robot.requireMembership(t, watches[i].cmd.Process.Pid, true)
		}
	}, func(r [2]appVMProgress) bool {
		return r[0].API.APIAvailable && r[1].API.APIAvailable && r[0].API.ProducerID != initial[0].API.ProducerID && r[1].API.ProducerID != initial[1].API.ProducerID
	})
	phase("one_app_down", [2]bool{false, true}, "p00", func() {
		(relayUplink{relay: f.target}).nft(t, `table inet app_service_fault {
 chain input { type filter hook input priority -10; policy accept;
 ip daddr 198.18.0.2 tcp dport 9193 counter drop
 }
}`)
	}, func(r [2]appVMProgress) bool { return r[0].API.APIAvailable && r[0].API.Availability == "reachable" })
	phase("one_app_recovered", both, "p00", func() { netOutput(t, f.target, "nft", "delete", "table", "inet", "app_service_fault") }, nil)
	phase("underlay_change", both, "p01", func() {
		(relayUplink{relay: f.robot}).nft(t, `table inet app_underlay_fault {
 chain output { type filter hook output priority filter; policy accept;
 oifname "wan0" udp dport { 51820, 51821 } counter drop
 }
}`)
	}, nil)
	phase("relay_change", both, "p11", func() { netOutput(t, f.recipients[0].ns, "ip", "link", "set", "uplink0", "down") }, nil)
	phase("all_uplinks_down", none, "", func() { netOutput(t, f.recipients[1].ns, "ip", "link", "set", "uplink0", "down") }, nil)
	phase("uplink_recovered", both, "p00", func() {
		for _, r := range f.recipients {
			netOutput(t, r.ns, "ip", "link", "set", "uplink0", "up")
		}
		netOutput(t, f.robot, "nft", "delete", "table", "inet", "app_underlay_fault")
	}, nil)
	grant := f.controller.apply(f.spec, 60)
	nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--once")
	for i := range watches {
		eventually(t, 30*time.Second, "short approval applied", func() error {
			r := latestApplicationResult(watchLogs[i])
			if !r.Applied || r.Selection.Generation != grant.Generation {
				return fmt.Errorf("approval generation")
			}
			return nil
		})
	}
	phase("offline_valid", both, "p00", func() { nodeControllerOutage(t, f); f.controller.apply(f.spec, 3600) }, nil)
	if time.Until(grant.ExpiresAt) <= 0 {
		t.Fatal("offline valid window was not exercised")
	}
	phase("approval_expired", none, "", func() { time.Sleep(max(0, time.Until(grant.ExpiresAt.Add(time.Second)))) }, nil)
	for _, r := range f.recipients {
		if !r.require("inspect", -1, 0).KernelReady {
			t.Fatal("relay independently expired")
		}
	}
	phase("approval_recovered", both, "p00", func() { netOutput(t, f.robot, "nft", "delete", "table", "inet", "node_outage") }, nil)
	cfg, err := config.Load(f.node)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := pki.LoadCredentials(cfg.Node.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	nodeCert, err := pki.ParseCertificate(creds.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	phase("approval_revoked", none, "", func() {
		f.controller.admin(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(nodeCert)})
		// Existing contract allows the bounded refresh interval to observe denial.
		time.Sleep(11 * time.Second)
	}, nil)
	phase("denied_offline", none, "", func() { nodeControllerOutage(t, f) }, nil)
	for _, r := range f.recipients {
		if !r.require("inspect", -1, 0).KernelReady {
			t.Fatal("relay independently revoked")
		}
	}
	for _, client := range clients {
		client.terminate(t)
	}
}
