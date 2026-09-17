// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
)

type kernelSnapshot struct {
	Link       string `json:"link"`
	Routes     string `json:"ipv4_routes"`
	Rules      string `json:"rules"`
	PublicKey  string `json:"public_key"`
	Peers      string `json:"peers"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoints  string `json:"endpoints"`
	Handshakes string `json:"handshakes"`
	Transfer   string `json:"transfer"`
}

func snapshotKernel(t *testing.T, ns string) kernelSnapshot {
	t.Helper()
	return kernelSnapshot{
		Link:       netOutput(t, ns, "ip", "-o", "link", "show", "dev", "wg0"),
		Routes:     netOutput(t, ns, "ip", "-4", "route", "show", "table", "all"),
		Rules:      netOutput(t, ns, "ip", "rule", "show"),
		PublicKey:  netOutput(t, ns, "wg", "show", "wg0", "public-key"),
		Peers:      netOutput(t, ns, "wg", "show", "wg0", "peers"),
		AllowedIPs: netOutput(t, ns, "wg", "show", "wg0", "allowed-ips"),
		Endpoints:  netOutput(t, ns, "wg", "show", "wg0", "endpoints"),
		Handshakes: netOutput(t, ns, "wg", "show", "wg0", "latest-handshakes"),
		Transfer:   netOutput(t, ns, "wg", "show", "wg0", "transfer"),
	}
}

func TestNetns_PKILifecycleUplink(t *testing.T) {
	requireNetwork(t)
	bin := integrationBinary(t)
	sizes := os.Getenv("VPNCTL_NETNS_SIZES")
	if sizes == "" {
		sizes = "1,3,8,32"
	}
	for _, part := range strings.Split(sizes, ",") {
		size, err := strconv.Atoi(part)
		if err != nil || size < 1 || size > 64 {
			t.Fatalf("invalid mesh size %q (1..64)", part)
		}
		t.Run(fmt.Sprintf("nodes_%d", size), func(t *testing.T) { testPKINetwork(t, bin, size) })
	}
}

func testPKINetwork(t *testing.T, bin string, size int) {
	namespaces := newNamespaces(t, size)
	uplink := newRelayUplink(t, namespaces[0])
	// Private keys and bootstrap tokens only live in temporary container storage.
	dir := t.TempDir()
	resultRoot := os.Getenv("VPNCTL_ARTIFACT_DIR")
	if resultRoot == "" {
		resultRoot = t.TempDir()
	}
	results, err := os.MkdirTemp(resultRoot, fmt.Sprintf("nodes-%d-", size))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("artifacts: %s", results)
	ctrlPrivate, ctrlPublic := wgKeyPair(t)
	ctrlDir := filepath.Join(dir, "controller")
	ctrlPath := filepath.Join(dir, "controller.yaml")
	controllerCfg := config.Config{Controller: &config.ControllerConfig{
		Listen: "0.0.0.0:8443", DataDir: ctrlDir, VPNCIDR: "10.77.0.0/24",
		WGApply: true, WGInterface: "wg0", WGPort: 51820, MTU: 1280, WGAddress: "10.77.0.1/24",
		WGPrivateKey: ctrlPrivate, ServerPublicKey: ctrlPublic, ServerEndpoint: "192.0.2.1:51820",
		ServerAllowedIPs: []string{"10.77.0.0/24", relayTargetIP + "/32"}, ServerKeepaliveSec: 1,
		PKI: &config.PKIConfig{CAExpiry: "10m", ServerExpiry: "10s", ClientExpiry: "30s", ServerRenewBefore: "7s", ClientRenewBefore: "20s", CheckInterval: "100ms", CAOverlap: "2s", ServerSANs: []string{"192.0.2.1", "10.77.0.1"}},
	}}
	if err := config.Save(ctrlPath, controllerCfg); err != nil {
		t.Fatal(err)
	}
	ctrlLog := filepath.Join(dir, "controller.log")
	ctrlEnv, injectSlowReconcile := slowReconcileEnvironment(t, dir)
	ctrl := startNetworkProcess(t, namespaces[0], ctrlLog, ctrlEnv, bin, "controller", "init", "--config", ctrlPath)
	admin := func(req api.AdminRequest) (api.AdminResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return api.Admin(ctx, ctrlDir, req)
	}
	action := func(op string) *pki.AuthorityStatus {
		t.Helper()
		r, err := admin(api.AdminRequest{Operation: op})
		if err != nil {
			t.Fatal(op, err)
		}
		return r.PKI
	}
	eventually(t, 5*time.Second, "controller IPC", func() error { _, err := admin(api.AdminRequest{Operation: "pki.status"}); return err })
	original := action("pki.status")
	caFile := filepath.Join(dir, "bootstrap-ca.crt")
	mustWrite(t, caFile, original.CACert)
	tokenResp, err := admin(api.AdminRequest{Operation: "token.create", TTL: "5m"})
	if err != nil {
		t.Fatal(err)
	}
	testBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	echo := startNetworkProcess(t, uplink.server, filepath.Join(dir, "echo.log"), []string{
		"VPNCTL_WORKER=echo", "VPNCTL_UPLINK_ADDR=" + relayTargetIP, "VPNCTL_ECHO_FRAGMENT=1",
		"VPNCTL_ECHO_OBSERVATIONS=" + filepath.Join(results, "uplink-sources.jsonl"),
	}, testBin, "-test.run=^TestNetworkWorker$")
	eventually(t, 5*time.Second, "separate uplink server", func() error {
		if netOutput(t, uplink.server, "ss", "-H", "-lnt", "sport", "=", ":9191") == "" {
			return fmt.Errorf("echo server not listening")
		}
		return nil
	})
	phaseFile := filepath.Join(dir, "phase")
	mustWrite(t, phaseFile, "warmup")
	stopResources := startResourceSampler(t, results, phaseFile)
	phase := func(name string) {
		t.Helper()
		if err := pki.WriteAtomic(phaseFile, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("phase: %s", name)
	}
	configs := make([]config.Config, size)
	paths := make([]string, size)
	agents := make([]*networkProcess, size)
	initialCerts := make([]string, size)
	probes := make([]*networkProcess, size)
	fleet := func(n int) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := netCommand(ctx, namespaces[n+1], testBin, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=fleet", "VPNCTL_PKI="+configs[n].Node.PKIDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, output)
		}
		return nil
	}
	startAgent := func(n int) *networkProcess {
		t.Helper()
		process := startNetworkProcess(t, namespaces[n+1], filepath.Join(dir, fmt.Sprintf("node-%d.log", n)), nil, bin, "node", "serve", "--config", paths[n], "--retry-delay", "100ms", "--retry-max-delay", "1s")
		// Fleet API readiness does not prove that the agent has bound its UDP
		// responder. An early client with an ephemeral port could take 51900.
		eventually(t, 5*time.Second, "agent UDP responder ready", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out, err := netCommand(ctx, namespaces[n+1], "ss", "-H", "-lun", "sport", "=", ":51900").CombinedOutput()
			if err != nil {
				return err
			}
			if len(strings.TrimSpace(string(out))) == 0 {
				return fmt.Errorf("agent has not bound its responder")
			}
			return nil
		})
		return process
	}
	for n := 0; n < size; n++ {
		id := fmt.Sprintf("node-%d", n)
		private, public := wgKeyPair(t)
		policyEnabled := n%2 == 0
		cfg := config.Config{Node: &config.NodeConfig{
			Name: id, Controller: "https://192.0.2.1:8443", WGInterface: "wg0", WGConfigPath: filepath.Join(dir, id+"-wg.conf"),
			WGPrivateKey: private, WGPublicKey: public, WGListenPort: 51820, MTU: 1280, DirectMode: "off", PolicyRoutingEnabled: &policyEnabled,
			KeepaliveIntervalSec: 1, CandidatesIntervalSec: 60, DirectIntervalSec: 60, HealthCheckIntervalSec: 3600,
			PKIDir: filepath.Join(dir, id+"-pki"),
		}}
		paths[n] = filepath.Join(dir, id+".yaml")
		if err := config.Save(paths[n], cfg); err != nil {
			t.Fatal(err)
		}
		// An initial provisioning network is available only during enrollment.
		netOutput(t, namespaces[n+1], bin, "node", "join", "--config", paths[n], "--token", tokenResp.Token, "--ca-cert", caFile)
		netOutput(t, namespaces[n+1], bin, "node", "sync-config", "--config", paths[n])
		netOutput(t, namespaces[n+1], bin, "up", "--config", paths[n])
		cfg, err = config.Load(paths[n])
		if err != nil {
			t.Fatal(err)
		}
		cfg.Node.Controller = "https://10.77.0.1:8443"
		if err := config.Save(paths[n], cfg); err != nil {
			t.Fatal(err)
		}
		configs[n] = cfg
		creds, err := pki.LoadCredentials(cfg.Node.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		initialCerts[n] = creds.ClientCert
		// No route to the VPN subnet exists before WG up; controller/app traffic
		// must go through wg0. The underlay has no default route or Internet.
		route := netOutput(t, namespaces[n+1], "ip", "route", "get", "10.77.0.1")
		if !strings.Contains(route, "dev wg0") {
			t.Fatal("uplink bypassed WG:", route)
		}
		if route := netOutput(t, namespaces[n+1], "ip", "route", "get", relayTargetIP); !strings.Contains(route, "dev wg0") {
			t.Fatal("separate uplink server bypassed WG:", route)
		}
		agents[n] = startAgent(n)
		eventually(t, 5*time.Second, "node API over WG", func() error { return fleet(n) })
		probes[n] = startNetworkProcess(t, namespaces[n+1], filepath.Join(dir, id+"-probe.log"), []string{
			"VPNCTL_UPLINK_ADDR=" + relayTargetIP, "VPNCTL_WORKER=probe", "VPNCTL_NODE=" + id, "VPNCTL_PHASE=" + phaseFile, "VPNCTL_PKI=" + cfg.Node.PKIDir, "VPNCTL_EVENTS=" + filepath.Join(results, id+".jsonl"),
		}, testBin, "-test.run=^TestNetworkWorker$")
	}
	telemetry := startNetworkProcess(t, namespaces[0], filepath.Join(dir, "telemetry.log"), []string{
		"VPNCTL_WORKER=telemetry", "VPNCTL_PHASE=" + phaseFile, "VPNCTL_PKI=" + configs[0].Node.PKIDir, "VPNCTL_TELEMETRY=" + filepath.Join(results, "telemetry.jsonl"),
	}, testBin, "-test.run=^TestNetworkWorker$")
	// Save sanitized logs on failure; never export generated credentials/state.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
		for _, path := range files {
			data, _ := os.ReadFile(path)
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if strings.Contains(line, "bootstrap token:") {
					lines[i] = "bootstrap token: [redacted]"
				}
			}
			_ = os.WriteFile(filepath.Join(results, filepath.Base(path)), []byte(strings.Join(lines, "\n")), 0600)
		}
	})
	checkFleetHistory := exerciseFleetHistory(t, bin, namespaces, paths, results)
	time.Sleep(time.Second)
	before := make([]kernelSnapshot, size)
	for n := range before {
		before[n] = snapshotKernel(t, namespaces[n+1])
	}
	phase("renewal")
	time.Sleep(time.Second)
	eventually(t, 20*time.Second, "automatic client/server renewal over WG", func() error {
		status, err := admin(api.AdminRequest{Operation: "pki.status"})
		if err != nil {
			return err
		}
		if status.PKI.Server.Fingerprint == original.Server.Fingerprint {
			return fmt.Errorf("server has not renewed")
		}
		for n := range configs {
			creds, err := pki.LoadCredentials(configs[n].Node.PKIDir)
			if err != nil {
				return err
			}
			if creds.ClientCert == initialCerts[n] {
				return fmt.Errorf("node %d has not renewed", n)
			}
		}
		return nil
	})
	awaitAction := func(op string) *pki.AuthorityStatus {
		var status *pki.AuthorityStatus
		eventually(t, 15*time.Second, op, func() error { r, err := admin(api.AdminRequest{Operation: op}); status = r.PKI; return err })
		return status
	}
	phase("revocation")
	// Preserve a valid superseded credential, then prove repeated use is denied
	// over WG while the re-enrolled agent and application remain available.
	agents[0].stop()
	frozen, err := pki.LoadCredentials(configs[0].Node.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	frozenDir := filepath.Join(dir, "revoked-replay")
	if err := pki.SaveCredentials(frozenDir, frozen, ""); err != nil {
		t.Fatal(err)
	}
	netOutput(t, namespaces[1], bin, "node", "join", "--config", paths[0], "--token", tokenResp.Token, "--ca-cert", caFile)
	agents[0] = startAgent(0)
	eventually(t, 5*time.Second, "new enrollment over WG", func() error { return fleet(0) })
	runFrozen := func(mode string) {
		t.Helper()
		// Fifty iterations retain their own 1s request budget. The batch
		// timeout must cover the entire sequence on a small CI runner.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := netCommand(ctx, namespaces[1], testBin, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER="+mode, "VPNCTL_PKI="+frozenDir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("frozen credential %s: %v: %s", mode, err, out)
		}
	}
	runFrozen("fleet") // Still valid before explicit revocation.
	frozenCert, err := pki.ParseCertificate(frozen.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(frozenCert)}); err != nil {
		t.Fatal(err)
	}
	runFrozen("replay") // 50 fleet + 50 renewal attempts, all must be HTTP 403.
	time.Sleep(time.Second)
	phase("rotation")
	prepared := action("ca.prepare")
	for i := 0; i < 20; i++ {
		if _, err := admin(api.AdminRequest{Operation: "ca.prepare"}); err == nil {
			t.Fatal("repeated prepare succeeded")
		}
	}
	if action("pki.status").Generation != prepared.Generation {
		t.Fatal("rejected operations changed trust generation")
	}
	activated := awaitAction("ca.activate")
	if activated.Active == original.Active {
		t.Fatal("CA issuer did not change")
	}
	retired := awaitAction("ca.retire")
	if retired.Phase != "stable" || retired.Previous != "" {
		t.Fatal("CA not retired")
	}
	phase("rollback")
	action("ca.prepare")
	awaitAction("ca.activate")
	// Wait until EVERY node has used the new signer before testing rollback.
	eventually(t, 15*time.Second, "new certificates before rollback", func() error {
		status := action("pki.status")
		for n := range configs {
			creds, err := pki.LoadCredentials(configs[n].Node.PKIDir)
			if err != nil {
				return err
			}
			cert, err := pki.ParseCertificate(creds.ClientCert)
			if err != nil {
				return err
			}
			ack := status.Acks[configs[n].Node.Name]
			if ack.Generation != status.Generation || ack.Fingerprint != pki.Fingerprint(cert) {
				return fmt.Errorf("node %d not acknowledged", n)
			}
			issuer := ""
			for _, r := range status.Certificates {
				if r.Fingerprint == ack.Fingerprint {
					issuer = r.Issuer
				}
			}
			if issuer != status.Active {
				return fmt.Errorf("node %d still uses previous issuer", n)
			}
		}
		return nil
	})
	rolledBack := action("ca.rollback")
	if rolledBack.Active != retired.Active {
		t.Fatal("rollback did not restore prior issuer")
	}
	for i := 0; i < 20; i++ {
		if _, err := admin(api.AdminRequest{Operation: "ca.rollback"}); err == nil {
			t.Fatal("repeated rollback succeeded")
		}
	}
	awaitAction("ca.retire")
	time.Sleep(time.Second)
	after := make([]kernelSnapshot, size)
	for n := range after {
		after[n] = snapshotKernel(t, namespaces[n+1])
		a, b := before[n], after[n]
		if a.Link != b.Link || a.Routes != b.Routes || a.Rules != b.Rules || a.PublicKey != b.PublicKey || a.Peers != b.Peers || a.AllowedIPs != b.AllowedIPs || a.Endpoints != b.Endpoints {
			t.Errorf("PKI transition changed node %d WireGuard configuration\nbefore: %+v\nafter: %+v", n, a, b)
		}
		for _, line := range strings.Split(b.Handshakes, "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[1] == "0" {
				t.Fatalf("no real WireGuard handshake for node %d", n)
			}
		}
		if a.Transfer == b.Transfer {
			t.Fatal("WireGuard counters did not increase")
		}
	}
	snapshots, _ := json.MarshalIndent(map[string]any{"before": before, "after": after}, "", "  ")
	mustWrite(t, filepath.Join(results, "kernel.json"), string(snapshots))
	phase("slow_reconcile")
	injectSlowReconcile()
	phase("controller_graceful_restart")
	savedStatus := action("pki.status")
	ctrl.terminate(t)
	ctrl = startNetworkProcess(t, namespaces[0], ctrlLog, ctrlEnv, bin, "controller", "init", "--config", ctrlPath)
	eventually(t, 5*time.Second, "controller graceful restart", func() error { _, err := admin(api.AdminRequest{Operation: "pki.status"}); return err })
	gracefulStatus := action("pki.status")
	if savedStatus.Generation != gracefulStatus.Generation || savedStatus.Active != gracefulStatus.Active || savedStatus.Phase != gracefulStatus.Phase {
		t.Fatal("graceful restart changed persisted CA state")
	}
	for n := range configs {
		eventually(t, 5*time.Second, "node after graceful restart", func() error { return fleet(n) })
	}
	time.Sleep(time.Second)
	phase("controller_restart")
	ctrl.stop()
	ctrl = startNetworkProcess(t, namespaces[0], ctrlLog, ctrlEnv, bin, "controller", "init", "--config", ctrlPath)
	eventually(t, 5*time.Second, "controller restart", func() error { _, err := admin(api.AdminRequest{Operation: "pki.status"}); return err })
	restartedStatus := action("pki.status")
	if savedStatus.Generation != restartedStatus.Generation || savedStatus.Active != restartedStatus.Active || savedStatus.Phase != restartedStatus.Phase {
		t.Fatal("controller restart changed persisted CA state")
	}
	for n := range configs {
		eventually(t, 5*time.Second, "node after controller restart", func() error { return fleet(n) })
	}
	checkFleetHistory("after-restart")
	time.Sleep(time.Second)
	phase("network_loss")
	// Drop encrypted underlay packets for one node; positive control proves the
	// probes detect an actual outage and recover after the fault is removed.
	netOutput(t, namespaces[1], "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%")
	time.Sleep(2 * time.Second)
	netOutput(t, namespaces[1], "tc", "qdisc", "del", "dev", "eth0", "root")
	eventually(t, 5*time.Second, "recovery after packet loss", func() error { return fleet(0) })
	time.Sleep(time.Second)
	phase("agent_restart")
	// Model a reboot with the device gone and controller reachable only over WG.
	agents[0].stop()
	netOutput(t, namespaces[1], "ip", "link", "del", "wg0")
	agents[0] = startAgent(0)
	eventually(t, 8*time.Second, "cold node restart via saved WireGuard config", func() error { return fleet(0) })
	time.Sleep(time.Second)
	recoveredConfig, err := config.Load(paths[0])
	if err != nil || recoveredConfig.Node.VPNIP != configs[0].Node.VPNIP || recoveredConfig.Node.WGPublicKey != configs[0].Node.WGPublicKey {
		t.Fatal("cold restart did not preserve node identity/address", err)
	}
	recoveredKernel := snapshotKernel(t, namespaces[1])
	if recoveredKernel.PublicKey != after[0].PublicKey || recoveredKernel.Peers != after[0].Peers || recoveredKernel.AllowedIPs != after[0].AllowedIPs || recoveredKernel.Routes != after[0].Routes || recoveredKernel.Rules != after[0].Rules {
		t.Fatal("cold restart did not restore the cached WireGuard path")
	}
	phase("recovered")
	time.Sleep(2 * time.Second)
	phase("done")
	telemetry.finish(t)
	stopResources()
	for _, p := range probes {
		p.finish(t)
	}
	evaluateNetworkEvents(t, results, size)
	uplink.verify(t, testBin, namespaces[1:], configs, results)
	echo.stop()
	verifyEchoSources(t, results, configs)
}

type probeSummary struct {
	Sent            int     `json:"sent"`
	Failed          int     `json:"failed"`
	Reconnects      int     `json:"reconnects"`
	MaxFailureMS    float64 `json:"max_failure_ms"`
	MaxSuccessGapMS float64 `json:"max_success_gap_ms"`
}

func evaluateNetworkEvents(t *testing.T, dir string, size int) {
	t.Helper()
	summaries := map[string]*probeSummary{}
	for n := 0; n < size; n++ {
		f, err := os.Open(filepath.Join(dir, fmt.Sprintf("node-%d.jsonl", n)))
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		failedAt := map[string]time.Time{}
		lastSuccess := map[string]time.Time{}
		var events []probeEvent
		for scanner.Scan() {
			var e probeEvent
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		// UDP timeout records arrive later than replies; order by send time when
		// calculating consecutive loss duration and successful-sample gaps.
		sort.SliceStable(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
		for _, e := range events {
			if e.Phase == "warmup" {
				continue
			}
			key := fmt.Sprintf("node-%d/%s/%s", n, accountingPhase(e), e.Kind)
			s := summaries[key]
			if s == nil {
				s = &probeSummary{}
				summaries[key] = s
			}
			s.Sent++
			if e.Reconnected {
				s.Reconnects++
			}
			if !e.OK {
				s.Failed++
				if failedAt[e.Kind].IsZero() {
					failedAt[e.Kind] = e.At
				}
				s.MaxFailureMS = max(s.MaxFailureMS, e.At.Sub(failedAt[e.Kind]).Seconds()*1000+e.DurationMS)
			} else {
				if !failedAt[e.Kind].IsZero() {
					s.MaxFailureMS = max(s.MaxFailureMS, e.At.Sub(failedAt[e.Kind]).Seconds()*1000+e.DurationMS)
					failedAt[e.Kind] = time.Time{}
				}
				if !lastSuccess[e.Kind].IsZero() {
					s.MaxSuccessGapMS = max(s.MaxSuccessGapMS, e.At.Sub(lastSuccess[e.Kind]).Seconds()*1000)
				}
				lastSuccess[e.Kind] = e.At
			}
		}
	}
	data, _ := json.MarshalIndent(summaries, "", "  ")
	mustWrite(t, filepath.Join(dir, "summary.json"), string(data))
	total, failed := 0, 0
	for n := 0; n < size; n++ {
		for _, phase := range []string{"renewal", "revocation", "rotation", "rollback", "slow_reconcile", "recovered"} {
			for _, kind := range []string{"udp", "tcp", "https"} {
				key := fmt.Sprintf("node-%d/%s/%s", n, phase, kind)
				s := summaries[key]
				if s == nil || s.Sent < 3 {
					t.Errorf("insufficient samples: %s: %+v", key, s)
					continue
				}
				total += s.Sent
				failed += s.Failed
				if s.Failed != 0 || s.Reconnects != 0 {
					t.Errorf("planned lifecycle interrupted uplink %s: %+v", key, s)
				}
			}
		}
	}
	control := summaries["node-0/network_loss/udp"]
	if control == nil || control.Failed == 0 {
		t.Error("loss injection was not detected by UDP probe")
	}
	for n := 0; n < size; n++ {
		for _, kind := range []string{"udp", "tcp"} {
			for _, phase := range []string{"controller_restart", "controller_graceful_restart"} {
				s := summaries[fmt.Sprintf("node-%d/%s/%s", n, phase, kind)]
				if s == nil || s.Sent == 0 || s.Failed != 0 || s.Reconnects != 0 {
					t.Errorf("%s disrupted independent WG application: %+v", phase, s)
				}
			}
		}
	}
	t.Logf("planned PKI phases: probes=%d failures=%d; injected packet loss: %+v", total, failed, control)
}

// Only transport closure or an explicit shutdown rejection overlapping a stop belongs to
// its restart window. Deadline/authentication errors remain in their start phase.
// Raw events retain both phase markers; no failure samples are discarded.
func accountingPhase(e probeEvent) string {
	if e.Kind == "https" && (e.EndPhase == "controller_restart" || e.EndPhase == "controller_graceful_restart") && (strings.HasSuffix(e.Error, ": EOF") || strings.Contains(e.Error, "connection reset by peer") || strings.HasSuffix(strings.TrimSpace(e.Error), "503 Service Unavailable: controller shutting down")) {
		return e.EndPhase
	}
	return e.Phase
}
func TestNetworkAccountingPreservesFailures(t *testing.T) {
	for _, tc := range []struct{ kind, end, err, want string }{
		{"https", "controller_restart", "Get: EOF", "controller_restart"},
		{"https", "controller_graceful_restart", "Get: EOF", "controller_graceful_restart"},
		{"https", "controller_restart", "context deadline exceeded", "rollback"},
		{"https", "controller_restart", "403 Forbidden", "rollback"},
		{"https", "controller_graceful_restart", "request failed: 503 Service Unavailable: controller shutting down", "controller_graceful_restart"},
		{"https", "controller_restart", "request failed: 503 Service Unavailable: certificate authorization failed", "rollback"},
		{"https", "rollback", "Get: EOF", "rollback"},
		{"udp", "controller_restart", "Get: EOF", "rollback"},
		{"tcp", "controller_restart", "connection reset by peer", "rollback"},
	} {
		got := accountingPhase(probeEvent{Kind: tc.kind, Phase: "rollback", EndPhase: tc.end, Error: tc.err})
		if got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
}
