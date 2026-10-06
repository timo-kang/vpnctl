//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayplan"
)

// Root-namespace manager actions require all the independent identities used
// by the VM agent. A container env flag alone never authorizes these commands.
func requireManagerGuest(t *testing.T) {
	t.Helper()
	if os.Getenv("VPNCTL_VM_MANAGERS") != "1" {
		t.Fatal("manager guest not requested")
	}
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]string{}
	for _, s := range strings.Fields(string(b)) {
		k, v, _ := strings.Cut(s, "=")
		args[k] = v
	}
	boot, e1 := os.ReadFile("/proc/sys/kernel/random/boot_id")
	uuid, e2 := os.ReadFile("/sys/class/dmi/id/product_uuid")
	_, marker := args["vpnctl_vm_test"]
	own, e3 := os.Readlink("/proc/self/ns/net")
	root, e4 := os.Readlink("/proc/1/ns/net")
	if !marker || len(args["vpnctl_vm_token"]) != 32 || args["vpnctl_host_boot"] == "" || args["vpnctl_host_boot"] == strings.TrimSpace(string(boot)) || args["vpnctl_vm_uuid"] != strings.ToLower(strings.TrimSpace(string(uuid))) || e1 != nil || e2 != nil || e3 != nil || e4 != nil || own != root {
		t.Fatal("refusing manager changes outside identity-guarded guest root namespace")
	}
	requireNetwork(t)
}

func managerCommand(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if e != nil {
		t.Fatalf("manager command %v: %v: %s", args, e, b)
	}
	return strings.TrimSpace(string(b))
}
func managerWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0644)
	if strings.HasPrefix(path, "/etc/netplan/") {
		mode = 0600
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}
func managerDigest(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// Probe the actual unbound app socket, validating both random payload and the
// server's view of its source. No process exit, ping or wg installation proxy.
func managerPayload(target, expectedSource string) error {
	c, e := net.DialTimeout("tcp4", target+":9192", time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	if _, e = c.Write(nonce); e != nil {
		return e
	}
	r := bufio.NewReader(io.LimitReader(c, 256))
	line, e := r.ReadString('\n')
	if e != nil {
		return e
	}
	source, _, e := net.SplitHostPort(strings.TrimSpace(line))
	if e != nil {
		return e
	}
	got := make([]byte, 16)
	if _, e = io.ReadFull(r, got); e != nil {
		return e
	}
	if source != expectedSource || !bytes.Equal(nonce, got) {
		return fmt.Errorf("wrong source or nonce: %s", source)
	}
	return nil
}

type managerTraffic struct {
	mu        sync.Mutex
	OK        int    `json:"ok"`
	Failed    int    `json:"failed"`
	MaxGapMS  int64  `json:"max_gap_ms"`
	LastError string `json:"last_error,omitempty"`
	last      time.Time
}

func (s *managerTraffic) sample(ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.MaxGapMS = max(s.MaxGapMS, now.Sub(s.last).Milliseconds())
	if ok {
		s.OK++
		s.last = now
	} else {
		s.Failed++
		s.LastError = err.Error()
	}
}
func (s *managerTraffic) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"ok": s.OK, "failed": s.Failed, "max_gap_ms": max(s.MaxGapMS, time.Since(s.last).Milliseconds()), "last_error": s.LastError}
}
func managerTrafficStart(t *testing.T) map[string]*managerTraffic {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	result := map[string]*managerTraffic{}
	for target, source := range map[string]string{m3Target: "198.18.0.11", "198.18.0.3": "198.18.0.11", "172.20.10.2": "172.20.10.1", "172.20.20.2": "172.20.20.1"} {
		s := &managerTraffic{last: time.Now()}
		result[target] = s
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				e := managerPayload(target, source)
				s.sample(e == nil, e)
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
		}()
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
	return result
}

func TestVMNetworkManagers(t *testing.T) {
	if os.Getenv("VPNCTL_VM_MANAGERS") != "1" {
		t.Skip("requires manager VM runner")
	}
	requireManagerGuest(t)
	report := map[string]any{"schema_version": 1, "completed": false, "steps": []map[string]any{}, "scope": "virtual Ethernet; Netplan renderer networkd; no Wi-Fi RF or EtherCAT real-time qualification"}
	t.Cleanup(func() {
		report["completed"] = !t.Failed()
		writeM3Report(t, "/var/lib/vpnctl-vm/managers.json", report)
	})
	report["versions"] = managerCommand(t, "dpkg-query", "-W", "network-manager", "netplan.io", "systemd", "udev", "dnsmasq-base", "iptables")
	// Both manager services are masked in the image. Explicitly permit only
	// wan0/shared0 in NM, and only RF/gimbal in networkd. Other fixture links,
	// management NIC, EtherCAT role and product WG resources stay excluded.
	nmConfig := "/etc/NetworkManager/conf.d/99-vpnctl-test.conf"
	managerWrite(t, nmConfig, "[main]\nplugins=keyfile\nno-auto-default=*\ndns=none\nrc-manager=unmanaged\n[keyfile]\nunmanaged-devices=*,except:interface-name:wan0,except:interface-name:shared0\n[device-vpnctl-test]\nmatch-device=interface-name:wan0;interface-name:shared0\nmanaged=1\n")
	managerWrite(t, "/etc/systemd/networkd.conf.d/90-vpnctl-test.conf", "[Network]\nManageForeignRoutes=no\nManageForeignRoutingPolicyRules=no\n")
	managerWrite(t, "/etc/systemd/network/99-vpnctl-unmanaged.network", "[Match]\nName=*\n[Link]\nUnmanaged=yes\n")
	t.Log("creating authenticated topology")
	f := applicationFixtureWithGuestRobot(t, true, 4, true)
	t.Log("topology ready; provisioning manager profiles")
	t.Cleanup(func() {
		diagnostic := map[string]string{}
		for name, args := range map[string][]string{
			"routes":           {"ip", "-j", "-N", "route", "show", "table", "all"},
			"rules":            {"ip", "-j", "-N", "rule"},
			"networkd_config":  {"systemd-analyze", "cat-config", "systemd/networkd.conf"},
			"networkd_journal": {"journalctl", "--no-pager", "-n", "100", "-u", "systemd-networkd"},
			"nm_config":        {"NetworkManager", "--print-config"},
			"journal":          {"journalctl", "--no-pager", "-n", "100", "-u", "NetworkManager", "-u", "systemd-networkd"},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			cancel()
			if len(b) > 24000 {
				b = b[len(b)-24000:]
			}
			diagnostic[name] = fmt.Sprintf("%s\nerror=%v", b, e)
		}
		for _, name := range []string{"manager-app.jsonl", "manager-app2.jsonl", "kernel-events.log"} {
			b, _ := os.ReadFile(filepath.Join(f.results, name))
			if len(b) > 16000 {
				b = append(append(b[:8000:8000], []byte("\n[bounded middle omitted]\n")...), b[len(b)-8000:]...)
			}
			diagnostic[name] = string(b)
		}
		report["diagnostic"] = diagnostic
	})
	startNetworkProcess(t, f.robot, filepath.Join(f.results, "kernel-events.log"), nil, "ip", "-ts", "monitor", "all")

	report["roles"] = map[string]any{"uplinks": []string{"wan0", "wan1"}, "networkmanager": []string{"wan0", "shared0"}, "netplan_renderer": "networkd", "netplan_lan": []string{"rf0", "gimbal0"}, "udev_excluded": "ecat0", "robot_namespace": f.robot, "controller_separate": true, "relays": 2}
	for _, p := range f.plan.Paths {
		enablePreparation(t, f, p.PathID)
	}
	logs := map[string]string{}
	for target, path := range map[string]string{"app": "p00", "app2": "p01"} {
		log := filepath.Join(f.results, "manager-"+target+".jsonl")
		logs[target] = log
		startNetworkProcess(t, f.robot, log, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", target, "--watch", "--interval", "500ms", "--mode", "manual", "--path-id", path)
	}
	lanNS := map[string]string{}
	for i, iface := range []string{"rf0", "gimbal0", "shared0"} {
		ns := fmt.Sprintf("manager-lan-%d", i)
		lanNS[iface] = ns
		managerCommand(t, "ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		managerCommand(t, "ip", "link", "add", iface, "type", "veth", "peer", "name", "lan0", "netns", ns)
		netOutput(t, ns, "ip", "link", "set", "lo", "up")
		netOutput(t, ns, "ip", "link", "set", "lan0", "up")
		if i < 2 {
			addr := fmt.Sprintf("172.20.%d.2", 10*(i+1))
			netOutput(t, ns, "ip", "addr", "add", addr+"/24", "dev", "lan0")
			startNetworkProcess(t, ns, filepath.Join(f.results, iface+"-echo.log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=" + addr}, f.worker, "-test.run=^TestNetworkWorker$")
		}
	}
	netplan := "/etc/netplan/90-vpnctl-test.yaml"
	managerWrite(t, netplan, "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    rf0:\n      addresses: [172.20.10.1/24]\n      link-local: []\n    gimbal0:\n      addresses: [172.20.20.1/24]\n      link-local: []\n")
	udev := "/etc/udev/rules.d/70-vpnctl-ethercat-test.rules"
	managerWrite(t, udev, "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==\"02:00:00:ec:00:01\", NAME=\"ecat0\"\n")
	managerCommand(t, "udevadm", "control", "--reload")
	createEtherCAT := func() int {
		managerCommand(t, "ip", "link", "add", "ecat-seed", "address", "02:00:00:ec:00:01", "type", "veth", "peer", "name", "ecat-peer")
		managerCommand(t, "udevadm", "settle", "--timeout=10")
		var links []struct {
			Index   int    `json:"ifindex"`
			Address string `json:"address"`
		}
		if e := json.Unmarshal([]byte(managerCommand(t, "ip", "-j", "link", "show", "ecat0")), &links); e != nil || len(links) != 1 || links[0].Address != "02:00:00:ec:00:01" {
			t.Fatal("udev rename missing", e, links)
		}
		return links[0].Index
	}
	etherIndex := createEtherCAT()
	// networkd runs as systemd-network: a root-only 0600 drop-in is ignored
	// and silently leaves destructive foreign route/rule cleanup at defaults.
	for _, path := range []string{"/etc/systemd/networkd.conf.d/90-vpnctl-test.conf", "/etc/systemd/network/99-vpnctl-unmanaged.network"} {
		managerCommand(t, "runuser", "-u", "systemd-network", "--", "test", "-r", path)
	}
	managerCommand(t, "systemctl", "unmask", "NetworkManager.service", "systemd-networkd.service")
	managerCommand(t, "netplan", "apply")
	managerCommand(t, "systemctl", "start", "NetworkManager.service")
	managerCommand(t, "nmcli", "connection", "add", "type", "ethernet", "ifname", "wan0", "con-name", "vpnctl-wan", "ipv4.method", "manual", "ipv4.addresses", "192.0.2.10/24", "ipv4.never-default", "yes", "ipv6.method", "disabled", "connection.autoconnect", "yes")
	managerCommand(t, "nmcli", "--wait", "15", "connection", "up", "vpnctl-wan")
	configDigests := map[string]string{}
	for _, path := range []string{nmConfig, netplan, udev, "/run/systemd/network/10-netplan-rf0.network", "/run/systemd/network/10-netplan-gimbal0.network"} {
		configDigests[path] = managerDigest(t, path)
	}
	report["configuration_sha256"] = configDigests
	ready := func() error {
		for _, log := range logs {
			if !latestApplicationResult(log).Applied {
				return fmt.Errorf("target not applied: %+v", latestApplicationResult(log).Application)
			}
		}
		for target, source := range map[string]string{m3Target: "198.18.0.11", "198.18.0.3": "198.18.0.11", "172.20.10.2": "172.20.10.1", "172.20.20.2": "172.20.20.1"} {
			if e := managerPayload(target, source); e != nil {
				return fmt.Errorf("payload %s: %w", target, e)
			}
		}
		return nil
	}
	t.Log("manager profiles applied; waiting for baseline")
	eventually(t, 120*time.Second, "manager baseline", ready)
	traffic := managerTrafficStart(t)
	t.Cleanup(func() {
		snap := map[string]any{}
		for name, s := range traffic {
			snap[name] = s.snapshot()
		}
		report["traffic"] = snap
	})
	snapshot := func() map[string]any {
		return map[string]any{"addresses": managerCommand(t, "ip", "-j", "address"), "routes": managerCommand(t, "ip", "-j", "-N", "route", "show", "table", "all"), "rules": managerCommand(t, "ip", "-j", "-N", "rule"), "nm_devices": managerCommand(t, "nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"), "networkd": managerCommand(t, "networkctl", "--no-pager", "list"), "nft": managerCommand(t, "nft", "-j", "list", "ruleset")}
	}
	// Raw inventories contain public kernel metadata only, never WG private keys.
	report["baseline"] = snapshot()
	steps := []struct {
		name   string
		action func()
	}{
		{"baseline", func() { time.Sleep(time.Second) }},
		{"nm-reload", func() { managerCommand(t, "nmcli", "general", "reload") }},
		{"nm-restart", func() { managerCommand(t, "systemctl", "restart", "NetworkManager.service") }},
		{"nm-disconnect-reconnect", func() {
			managerCommand(t, "nmcli", "--wait", "15", "connection", "down", "vpnctl-wan")
			eventually(t, 20*time.Second, "stale path invalidated while NM disconnected", func() error {
				if latestApplicationResult(logs["app"]).Applied {
					return fmt.Errorf("old app still applied")
				}
				return nil
			})
			if e := managerPayload(m3Target, "198.18.0.11"); e == nil {
				t.Fatal("disconnected path still passed")
			}
			// The independent underlay remains usable while wan0 is absent.
			if e := managerPayload("198.18.0.3", "198.18.0.11"); e != nil {
				t.Fatal("independent app lost", e)
			}
			managerCommand(t, "nmcli", "--wait", "15", "connection", "up", "vpnctl-wan")
		}},
		{"netplan-apply", func() { managerCommand(t, "netplan", "apply") }},
		{"networkd-reload", func() { managerCommand(t, "networkctl", "reload") }},
		{"networkd-restart", func() { managerCommand(t, "systemctl", "restart", "systemd-networkd.service") }},
		{"nm-shared-up", func() {
			managerCommand(t, "nmcli", "connection", "add", "type", "ethernet", "ifname", "shared0", "con-name", "vpnctl-shared", "ipv4.method", "shared", "ipv4.addresses", "10.42.0.1/24", "ipv6.method", "disabled", "connection.autoconnect", "no")
			managerCommand(t, "nmcli", "--wait", "15", "connection", "up", "vpnctl-shared")
			ns := lanNS["shared0"]
			netOutput(t, ns, "ip", "addr", "add", "10.42.0.2/24", "dev", "lan0")
			var lease struct {
				Address string `json:"address"`
			}
			leaseJSON := netOutput(t, ns, "python3", "/opt/vpnctl-vm/manager_dhcp.py")
			if e := json.Unmarshal([]byte(leaseJSON), &lease); e != nil || net.ParseIP(lease.Address) == nil {
				t.Fatal("invalid DHCP proof", e, leaseJSON)
			}
			report["shared_dhcp"] = json.RawMessage(leaseJSON)
			netOutput(t, ns, "ip", "addr", "del", "10.42.0.2/24", "dev", "lan0")
			netOutput(t, ns, "ip", "addr", "add", lease.Address+"/24", "dev", "lan0")
			netOutput(t, ns, "ip", "route", "add", "default", "via", "10.42.0.1")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := netCommand(ctx, ns, f.worker, "-test.run=^TestNetworkWorker$")
			cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_TARGET=172.20.10.2")
			b, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatal(e, string(b))
			}
			var probe m3Probe
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, `"ok"`) {
					if e := json.Unmarshal([]byte(line), &probe); e != nil {
						t.Fatal(e)
					}
				}
			}
			if !probe.OK || probe.Source != "172.20.10.1" {
				t.Fatal("NM shared NAT did not carry payload", probe)
			}
			report["shared"] = snapshot()
			report["shared_services"] = managerCommand(t, "ss", "-lunp")
		}},
		{"nm-shared-down", func() { managerCommand(t, "nmcli", "--wait", "15", "connection", "down", "vpnctl-shared") }},
		{"udev-recreate", func() {
			managerCommand(t, "ip", "link", "del", "ecat0")
			next := createEtherCAT()
			if next == etherIndex {
				t.Fatal("udev replacement reused ifindex unexpectedly")
			}
			report["ethercat_identity"] = map[string]int{"before": etherIndex, "after": next}
		}},
	}
	for _, step := range steps {
		t.Log("manager step", step.name)
		started := time.Now()
		baselineResults := len(applicationResults(logs["app"]))
		beforeApp := latestApplicationResult(logs["app"])
		beforeGeneration := ""
		for _, c := range beforeApp.Selection.Candidates {
			if c.PathID == "p00" {
				beforeGeneration = c.UnderlayGeneration
			}
		}
		before := map[string]any{}
		for name, s := range traffic {
			before[name] = s.snapshot()
		}
		row := map[string]any{"name": step.name, "passed": false, "traffic_before": before}
		report["steps"] = append(report["steps"].([]map[string]any), row)
		step.action()
		eventually(t, 120*time.Second, "manager recovery "+step.name, func() error {
			for _, log := range logs {
				if !latestApplicationResult(log).StartedAt.After(started) {
					return fmt.Errorf("waiting for new application evidence")
				}
			}
			for name, stats := range traffic {
				if stats.snapshot()["ok"].(int) <= before[name].(map[string]any)["ok"].(int) {
					return fmt.Errorf("waiting for payload samples: %s", name)
				}
			}
			return ready()
		})
		observed := map[string]any{}
		for target, log := range logs {
			observed[target] = latestApplicationResult(log)
		}
		row["application_after"] = observed
		if step.name == "nm-disconnect-reconnect" {
			reconfirmed := false
			for _, r := range applicationResults(logs["app"])[baselineResults:] {
				for _, c := range r.Selection.Candidates {
					if c.PathID == "p00" && c.UnderlayGeneration != "" && c.UnderlayGeneration != beforeGeneration && c.ConsecutiveSuccesses == 1 && !c.Eligible {
						reconfirmed = true
					}
				}
			}
			if !reconfirmed {
				t.Fatal("missing fresh underlay generation and two-observation confirmation")
			}
			row["fresh_generation_confirmed"] = true
		}
		for path, digest := range configDigests {
			if managerDigest(t, path) != digest {
				t.Fatal("manager source/generated configuration changed", path)
			}
		}
		for _, p := range f.plan.Paths {
			if state := managerCommand(t, "nmcli", "-g", "GENERAL.STATE", "device", "show", p.Pin.WGInterface); !strings.HasPrefix(state, "10 ") {
				t.Fatal("product WG not unmanaged", p.PathID, state)
			}
		}
		after := map[string]any{}
		for name, s := range traffic {
			after[name] = s.snapshot()
		}
		for _, name := range []string{"172.20.10.2", "172.20.20.2", "198.18.0.3"} {
			if after[name].(map[string]any)["failed"] != before[name].(map[string]any)["failed"] {
				t.Fatal("independent application or LAN traffic interrupted", step.name, name, after[name])
			}
		}
		row["traffic_after"] = after
		row["elapsed_ms"] = time.Since(started).Milliseconds()
		row["passed"] = true
	}
	report["final"] = snapshot()
	var finalPlan relayplan.Plan
	planReads := 0
	eventually(t, 10*time.Second, "read final plan while supervisors retain ownership", func() error {
		planReads++
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, e := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "plan", "--config", f.node).CombinedOutput()
		// This is a read-only CLI. Its initial cache Open is intentionally
		// nonblocking; unlike mutations, retrying this precise busy rejection
		// neither adopts ownership nor replays a partially completed change.
		if e != nil && strings.Contains(string(b), relaycache.ErrBusy.Error()) {
			return fmt.Errorf("read admission busy")
		}
		if e != nil {
			t.Fatal("final plan read", e, string(b))
		}
		if e := json.Unmarshal(b, &finalPlan); e != nil {
			t.Fatal(e, string(b))
		}
		return nil
	})
	report["final_plan_read_attempts"] = planReads
	if len(finalPlan.Paths) != 4 {
		t.Fatal("unexpected candidate inventory", len(finalPlan.Paths))
	}
	report["final_plan"] = finalPlan
	for _, p := range finalPlan.Paths {
		if p.Pin == nil || p.Pin.Interface != "wan0" && p.Pin.Interface != "wan1" {
			t.Fatal("unapproved underlay adopted", p)
		}
	}
	for _, iface := range []string{"rf0", "gimbal0", "ecat0"} {
		if state := managerCommand(t, "nmcli", "-g", "GENERAL.STATE", "device", "show", iface); !strings.HasPrefix(state, "10 ") {
			t.Fatal("foreign LAN/EtherCAT adopted by NM", iface, state)
		}
	}
}
