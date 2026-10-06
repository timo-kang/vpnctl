//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/config"
)

func TestNetns_DirectDataplane(t *testing.T) {
	requireNetwork(t)
	sizes := os.Getenv("VPNCTL_DIRECT_SIZES")
	if sizes == "" {
		sizes = "2"
	}
	for _, raw := range strings.Split(sizes, ",") {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 2 || n > 32 {
			t.Fatal("invalid direct size")
		}
		t.Run(fmt.Sprint(n), func(t *testing.T) { testDirectDataplane(t, n) })
	}
}
func testDirectDataplane(t *testing.T, size int) {
	ns := newNamespaces(t, size)
	private := t.TempDir()
	root := os.Getenv("VPNCTL_ARTIFACT_DIR")
	if root == "" {
		root = t.TempDir()
	}
	results, err := os.MkdirTemp(root, fmt.Sprintf("direct-dataplane-%d-", size))
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{"nodes": size, "completed": false, "scope": "actual WG/overlay reachability and local relay fallback; not application target or multi-relay selection SLO"}
	for _, name := range []string{"memory.events", "memory.peak", "cpu.stat"} {
		b, _ := os.ReadFile(filepath.Join("/sys/fs/cgroup", name))
		report[name+"_before"] = string(b)
	}
	defer func() {
		for _, name := range []string{"memory.events", "memory.peak", "cpu.stat"} {
			b, _ := os.ReadFile(filepath.Join("/sys/fs/cgroup", name))
			report[name+"_after"] = string(b)
		}
		writeM3Report(t, filepath.Join(results, "report.json"), report)
	}()
	c := newM3Controller(t, ns[0], "192.0.2.1", private, results)
	// Keep the established independent controller/PKI helper; enable its hub
	// dataplane before enrollment, then stop only the API process during faults.
	c.process.stop()
	cfg, err := config.Load(filepath.Join(private, "controller.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	priv, pub := wgKeyPair(t)
	cfg.Controller.WGApply = true
	cfg.Controller.WGInterface = "wg0"
	cfg.Controller.WGAddress = "10.77.0.1/24"
	cfg.Controller.WGPrivateKey = priv
	cfg.Controller.WGPort = 51820
	cfg.Controller.ServerPublicKey = pub
	cfg.Controller.ServerEndpoint = "192.0.2.1:51820"
	if err = config.Save(filepath.Join(private, "controller.yaml"), cfg); err != nil {
		t.Fatal(err)
	}
	c.start()
	// Relay health has an independent lifecycle from the controller API, as in
	// a separated controller/relay deployment. Killing the API must not also
	// silently remove the required standby verification service.
	startNetworkProcess(t, ns[0], filepath.Join(private, "relay-probe.log"), nil, integrationBinary(t), "direct", "serve", "--listen", ":51901")
	report["relay_probe_independent_process"] = true
	defer func() {
		snapshots := map[string]kernelSnapshot{}
		for _, space := range ns {
			snapshots[space] = snapshotKernel(t, space)
		}
		report["kernel"] = snapshots
		report["node0_ip_stats"] = netOutput(t, ns[1], "ip", "-s", "link", "show", "wg0")
		report["node0_udp_stats"] = netOutput(t, ns[1], "cat", "/proc/net/snmp")
		report["node0_udp_sockets"] = netOutput(t, ns[1], "ss", "-u", "-a", "-m", "-n")
		report["socket_wmem_max"] = netOutput(t, ns[1], "cat", "/proc/sys/net/core/wmem_max")
		report["node0_neighbours"] = netOutput(t, ns[1], "ip", "-s", "neigh", "show")
		report["arp_cache_stats"] = "global cache counters are not exposed in this network namespace"
	}()
	(relayUplink{relay: ns[0]}).forwarding(t, true)
	paths := make([]string, size)
	nodes := make([]config.Config, size)
	agents := make([]*networkProcess, size)
	for i := 0; i < size; i++ {
		id := fmt.Sprintf("node-%d", i)
		paths[i] = c.enroll(ns[i+1], id)
		nodes[i], err = config.Load(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		n := nodes[i].Node
		n.WGConfigPath = filepath.Join(private, id+"-wg.conf")
		n.WGListenPort = 51820
		n.DirectMode = "auto"
		n.ProbePort = 51900
		n.ServerProbePort = 51901
		n.AdvertiseWGEndpoint = fmt.Sprintf("192.0.2.%d:51820", i+2)
		n.AdvertisePublicAddr = fmt.Sprintf("192.0.2.%d:51900", i+2)
		n.KeepaliveIntervalSec = 1
		n.CandidatesIntervalSec = 1
		n.DirectIntervalSec = 1
		n.HealthCheckIntervalSec = 3600
		n.STUNServers = nil
		if err = config.Save(paths[i], nodes[i]); err != nil {
			t.Fatal(err)
		}
		netOutput(t, ns[i+1], integrationBinary(t), "node", "sync-config", "--config", paths[i])
		netOutput(t, ns[i+1], integrationBinary(t), "up", "--config", paths[i])
		nodes[i], err = config.Load(paths[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	// Many simulated robots share one kernel neighbour table. Pin the fixture's
	// static underlay and NOARP VPN neighbours instead of changing global GC
	// sysctls on a shared host. Real robot kernels do not share this population.
	macs := make([]string, len(ns))
	vpnAddresses := make([]string, len(ns))
	vpnAddresses[0] = "10.77.0.1"
	for i, space := range ns {
		var links []struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal([]byte(netOutput(t, space, "ip", "-j", "link", "show", "dev", "eth0")), &links); err != nil || len(links) != 1 {
			t.Fatal("fixture MAC unavailable", err)
		}
		macs[i] = links[0].Address
		if i > 0 {
			prefix, err := netip.ParsePrefix(nodes[i-1].Node.VPNIP)
			if err != nil {
				t.Fatal(err)
			}
			vpnAddresses[i] = prefix.Addr().String()
		}
	}
	for i, space := range ns {
		var batch strings.Builder
		for j := range ns {
			if i == j {
				continue
			}
			fmt.Fprintf(&batch, "neigh replace 192.0.2.%d lladdr %s nud permanent dev eth0\n", j+1, macs[j])
			fmt.Fprintf(&batch, "neigh replace %s nud permanent dev wg0\n", vpnAddresses[j])
		}
		path := filepath.Join(private, fmt.Sprintf("neighbours-%d.txt", i))
		mustWrite(t, path, batch.String())
		netOutput(t, space, "ip", "-batch", path)
	}
	report["fixture_neighbours"] = "static permanent underlay and NOARP VPN entries; host sysctls unchanged"

	t.Cleanup(func() {
		for _, a := range agents {
			if a != nil {
				b, _ := os.ReadFile(a.log)
				os.WriteFile(filepath.Join(results, filepath.Base(a.log)), b, 0600)
			}
		}
	})
	start := func(i int) *networkProcess {
		return startNetworkProcess(t, ns[i+1], filepath.Join(private, fmt.Sprintf("agent-%d.log", i)), nil, integrationBinary(t), "node", "run", "--config", paths[i])
	}
	_, foreignKey := wgKeyPair(t)
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", foreignKey, "endpoint", "192.0.2.254:51999", "allowed-ips", "172.31.99.1/32")
	for i := range agents {
		agents[i] = start(i)
	}
	// Wait for kernel IPv6 DAD before taking a full IPv4/IPv6 route snapshot.
	eventually(t, 5*time.Second, "underlay address initialization", func() error {
		if strings.Contains(netOutput(t, ns[1], "ip", "-j", "-6", "addr", "show"), "tentative") {
			return fmt.Errorf("IPv6 DAD pending")
		}
		return nil
	})
	// This is fixture-owned unrelated routing state. Direct application must not
	// flush policy tables or alter any pre-existing rules/routes.
	netOutput(t, ns[1], "ip", "route", "add", "unreachable", "203.0.113.0/24", "table", "51820", "metric", "876")
	routesBefore := netOutput(t, ns[1], "ip", "-j", "route", "show", "table", "all")
	rulesBefore := netOutput(t, ns[1], "ip", "-j", "rule", "show")
	state := func(i, j int) string {
		data, _ := os.ReadFile(agents[i].log)
		out := ""
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "msg=\"direct dataplane\"") && strings.Contains(line, fmt.Sprintf("peer=node-%d ", j)) {
				for _, part := range strings.Fields(line) {
					if strings.HasPrefix(part, "state=") {
						out = strings.TrimPrefix(part, "state=")
					}
				}
			}
		}
		return out
	}
	// All pair directions must pass the actual VPN check, not just WG presence.
	eventually(t, 60*time.Second, "all direct overlay paths active", func() error {
		for i := 0; i < size; i++ {
			for j := 0; j < size; j++ {
				if i != j && state(i, j) != "active" {
					return fmt.Errorf("%d -> %d: %s", i, j, state(i, j))
				}
			}
		}
		return nil
	})
	report["initial_all_pairs_active"] = true
	endpoint := strings.TrimSuffix(nodes[1].Node.VPNIP, "/32") + ":51900"
	probe := func() error {
		worker, err := os.Executable()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := netCommand(ctx, ns[1], worker, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=peer-probe", "VPNCTL_PROBE_ENDPOINT="+endpoint)
		b, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, b)
		}
		return nil
	}
	if err = probe(); err != nil {
		t.Fatal("active overlay probe failed", err)
	}
	// The controller API is gone but the hub WG dataplane remains installed.
	c.process.stop()
	report["controller_stopped_at"] = time.Now().UTC()
	// Underlay UDP readiness (51900) stays available. Drop only A<->B WG.
	for _, i := range []int{0, 1} {
		other := 3 - i
		faultPath := filepath.Join(private, fmt.Sprintf("fault-%d.nft", i))
		mustWrite(t, faultPath, "table inet direct_fault {\n chain output {\n type filter hook output priority 0; policy accept;\n ip daddr 192.0.2."+fmt.Sprint(other)+" udp dport 51820 drop\n }\n}\n")
		netOutput(t, ns[i+1], "nft", "-f", faultPath)
	}
	failedAt := time.Now()
	report["wg_fault_installed_at"] = failedAt.UTC()
	eventually(t, 5*time.Second, "local direct removal with controller offline", func() error {
		for _, i := range []int{0, 1} {
			other := 1 - i
			if strings.Contains(netOutput(t, ns[i+1], "wg", "show", "wg0", "peers"), nodes[other].Node.WGPublicKey) {
				return fmt.Errorf("direct peer remains")
			}
			// Peer removal precedes publication of the completed Step result.
			// Wait for both observations inside the same fallback deadline;
			// a pre-fault active log is not evidence of reactivation.
			if observed := state(i, other); observed != "relay_unverified" && observed != "cooldown" {
				return fmt.Errorf("direct withdrawal not yet published: %d -> %d: %s", i, other, observed)
			}
		}
		return probe()
	})
	report["withdrawal_observed_at"] = time.Now().UTC()
	report["fallback_seconds"] = time.Since(failedAt).Seconds()
	report["fallback_overlay_ok"] = true
	// Stay beyond cooldown. One persistent worker measures actual nonce replies
	// independently of coordinator subprocess/log overhead. Keep the same 12s
	// fault exposure and 5s loss gate; finish the last outage before removing it.
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	watch := startNetworkProcess(t, ns[1], filepath.Join(results, "retry-packets.jsonl"), []string{"VPNCTL_WORKER=direct-loss-watch", "VPNCTL_PROBE_ENDPOINT=" + endpoint}, worker, "-test.run=^TestNetworkWorker$")
	beganWatch := time.Now()
	var samples []directLossSample
	for {
		if state(0, 1) == "active" || state(1, 0) == "active" {
			t.Fatal("broken WG advertised active despite successful UDP")
		}
		data, err := os.ReadFile(watch.log)
		if err != nil {
			t.Fatal(err)
		}
		samples = nil
		for _, line := range strings.Split(string(data), "\n") {
			var sample directLossSample
			if json.Unmarshal([]byte(line), &sample) == nil && sample.Sequence > 0 {
				samples = append(samples, sample)
			}
		}
		var maxGap time.Duration
		losses := 0
		for i, sample := range samples {
			if sample.Sequence != i+1 || i > 0 && sample.Elapsed < samples[i-1].Elapsed {
				t.Fatal("invalid loss sample sequence")
			}
			maxGap = max(maxGap, sample.Gap)
			if !sample.OK {
				losses++
			}
		}
		report["retry_max_observed_loss_seconds"], report["retry_failed_probes"], report["retry_samples"] = maxGap.Seconds(), losses, len(samples)
		if maxGap > 5*time.Second {
			t.Fatal("retry trial caused prolonged overlay loss", maxGap)
		}
		if len(samples) > 0 {
			if !samples[0].OK {
				t.Fatal("loss worker baseline unavailable")
			}
			last := samples[len(samples)-1]
			if last.Completed {
				if !last.OK || last.Elapsed < 12*time.Second {
					t.Fatal("loss worker ended before fault interval closed")
				}
				report["retry_watch_seconds"] = last.Elapsed.Seconds()
				watch.finish(t)
				break
			}
			if time.Since(last.At) > 2*time.Second {
				t.Fatal("loss worker stopped reporting")
			}
		} else if time.Since(beganWatch) > 2*time.Second {
			t.Fatal("loss worker did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	report["udp_success_not_dataplane_success"] = true
	for _, i := range []int{0, 1} {
		netOutput(t, ns[i+1], "nft", "delete", "table", "inet", "direct_fault")
	}
	eventually(t, 15*time.Second, "cached candidate reverified after cooldown", func() error {
		if state(0, 1) != "active" || state(1, 0) != "active" {
			return fmt.Errorf("not reverified")
		}
		return probe()
	})
	report["offline_recovery_verified"] = true
	routesAfter := netOutput(t, ns[1], "ip", "-j", "route", "show", "table", "all")
	rulesAfter := netOutput(t, ns[1], "ip", "-j", "rule", "show")
	report["routes_before"], report["routes_after"] = routesBefore, routesAfter
	report["rules_before"], report["rules_after"] = rulesBefore, rulesAfter
	if routesBefore != routesAfter || rulesBefore != rulesAfter {
		t.Fatal("foreign route/rule changed")
	}
	report["foreign_routes_preserved"] = true
	// A second vpnctl writer must be refused, without changing current paths.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = netCommand(ctx, ns[1], integrationBinary(t), "up", "--config", paths[0]).Run()
	cancel()
	if err == nil {
		t.Fatal("concurrent up accepted")
	}
	if err = probe(); err != nil {
		t.Fatal("concurrent writer damaged dataplane", err)
	}
	report["concurrent_writer_rejected"] = true
	// Abrupt agent death retains its intent. Restart recovery runs BEFORE the
	// unreachable controller registration. The hub peer must remain installed.
	agents[0].stop()
	journalPath := nodes[0].Node.WGConfigPath + ".direct.json"
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, journalPath, "{corrupt")
	agents[0] = startNetworkProcess(t, ns[1], agents[0].log, nil, integrationBinary(t), "node", "serve", "--config", paths[0])
	eventually(t, 3*time.Second, "corrupt journal rejected before mutation", func() error {
		b, _ := os.ReadFile(agents[0].log)
		if !strings.Contains(string(b), "invalid direct journal") {
			return fmt.Errorf("journal rejection not observed")
		}
		if len(strings.Fields(netOutput(t, ns[1], "wg", "show", "wg0", "peers"))) != size+1 {
			t.Fatal("corrupt journal authorized peer removal")
		}
		return nil
	})
	report["corrupt_journal_preserves_kernel"] = true
	mustWrite(t, journalPath, string(journalBytes))
	eventually(t, 5*time.Second, "restart recovery before controller registration", func() error {
		peers := strings.Fields(netOutput(t, ns[1], "wg", "show", "wg0", "peers"))
		if len(peers) != 2 || !slices.Contains(peers, pub) || !slices.Contains(peers, foreignKey) {
			return fmt.Errorf("managed direct peers not recovered")
		}
		return nil
	})
	report["offline_restart_recovers_owned_peers"] = true
	if routesAfter != netOutput(t, ns[1], "ip", "-j", "route", "show", "table", "all") || rulesAfter != netOutput(t, ns[1], "ip", "-j", "rule", "show") {
		t.Fatal("serve restart changed foreign routes/rules")
	}
	report["serve_restart_preserves_routes"] = true
	if !strings.Contains(netOutput(t, ns[1], "wg", "show", "wg0", "allowed-ips"), foreignKey+"\t172.31.99.1/32") || !strings.Contains(netOutput(t, ns[1], "wg", "show", "wg0", "endpoints"), foreignKey+"\t192.0.2.254:51999") {
		t.Fatal("foreign peer changed")
	}
	report["foreign_peer_preserved"] = true
	// Config edits must neither be silently ignored nor authorize destructive
	// syncconf on a cached baseline with foreign state.
	agents[0].stop()
	changed := *nodes[0].Node
	changed.ServerEndpoint = "192.0.2.254:51820"
	if err := config.Save(paths[0], config.Config{Node: &changed}); err != nil {
		t.Fatal(err)
	}
	agents[0] = startNetworkProcess(t, ns[1], agents[0].log, nil, integrationBinary(t), "node", "serve", "--config", paths[0])
	eventually(t, 3*time.Second, "baseline config change explicitly blocked", func() error {
		b, _ := os.ReadFile(agents[0].log)
		if !strings.Contains(string(b), "baseline configuration changed") {
			return fmt.Errorf("config conflict not reported")
		}
		return nil
	})
	if !strings.Contains(netOutput(t, ns[1], "wg", "show", "wg0", "endpoints"), pub+"\t192.0.2.1:51820") || len(strings.Fields(netOutput(t, ns[1], "wg", "show", "wg0", "peers"))) != 2 {
		t.Fatal("config conflict altered baseline/foreign peer")
	}
	report["baseline_config_change_rejected"] = true
	report["completed"] = true
}
