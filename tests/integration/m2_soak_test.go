// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
//go:build integration

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
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
	uplinkobs "vpnctl/internal/uplink"
)

// Unlike the short lifecycle suite, all node and monitor producers remain alive
// across the complete measured interval, except the explicitly injected faults.
func TestNetns_M2Soak(t *testing.T) {
	raw := os.Getenv("VPNCTL_SOAK_DURATION")
	if raw == "" {
		t.Skip("explicit duration required for persistent mixed soak")
	}
	duration, e := time.ParseDuration(raw)
	if e != nil || duration < time.Minute || duration > 7*24*time.Hour {
		t.Fatal("soak duration must be 1m..168h")
	}
	size, e := strconv.Atoi(os.Getenv("VPNCTL_SOAK_NODES"))
	if e != nil || size < 3 || size > 32 {
		t.Fatal("soak nodes must be 3..32")
	}
	phaseEvery, e := time.ParseDuration(os.Getenv("VPNCTL_SOAK_PHASE_INTERVAL"))
	if e != nil || phaseEvery < 20*time.Second {
		t.Fatal("phase interval must be >=20s")
	}
	if phaseEvery > duration/7 {
		t.Fatal("duration cannot cover all seven phases at this interval")
	}
	requireNetwork(t)
	bin := integrationBinary(t)
	worker, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ns := newNamespaces(t, size)
	u := newRelayUplink(t, ns[0])
	dir := t.TempDir()
	results, e := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m2-soak-")
	if e != nil {
		t.Fatal(e)
	}
	t.Log("soak results:", results)
	exposeSoakArtifact(t, results)
	trace, e := os.OpenFile(filepath.Join(results, "trace.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer trace.Close()
	exposeSoakArtifact(t, trace.Name())
	emit := func(v any) {
		t.Helper()
		if e := json.NewEncoder(trace).Encode(v); e != nil {
			t.Fatal(e)
		}
		if e := trace.Sync(); e != nil {
			t.Fatal(e)
		}
	}
	start := time.Time{}
	completed := false
	phases := map[string]int{}
	// Write an explicit incomplete verdict even on assertion failure. Process
	// kill/host loss can leave no verdict; consumers must also treat that as incomplete.
	defer func() {
		verdict := map[string]any{"schema_version": 1, "started_at": start, "finished_at": time.Now().UTC(), "requested_seconds": duration.Seconds(), "nodes": size, "completed": completed && !t.Failed(), "phases": phases, "m2_gate": "pending_review", "wall_clock_24h": !start.IsZero() && time.Since(start) >= 24*time.Hour}
		b, _ := json.MarshalIndent(verdict, "", "  ")
		verdictPath := filepath.Join(results, "verdict.json")
		if err := os.WriteFile(verdictPath, b, 0600); err != nil {
			t.Error(err)
		} else {
			exposeSoakArtifact(t, verdictPath)
		}
	}()
	cadence := 60
	leaf, renew := "1h", "40m"
	if duration < 24*time.Hour {
		cadence = 2
		leaf, renew = "60s", "40s"
	}
	private, public := wgKeyPair(t)
	ctrlPath, ctrlDir := filepath.Join(dir, "controller.yaml"), filepath.Join(dir, "controller")
	c := config.Config{Controller: &config.ControllerConfig{Listen: "0.0.0.0:8443", DataDir: ctrlDir, VPNCIDR: "10.77.0.0/24", WGApply: true, WGInterface: "wg0", WGPort: 51820, MTU: 1280, WGAddress: "10.77.0.1/24", WGPrivateKey: private, ServerPublicKey: public, ServerEndpoint: "192.0.2.1:51820", ServerAllowedIPs: []string{"10.77.0.0/24", relayTargetIP + "/32"}, ServerKeepaliveSec: 1, PKI: &config.PKIConfig{CAExpiry: "240h", ServerExpiry: leaf, ClientExpiry: leaf, ServerRenewBefore: renew, ClientRenewBefore: renew, CheckInterval: "1s", CAOverlap: "2s", ServerSANs: []string{"192.0.2.1", "10.77.0.1"}}}}
	if e = config.Save(ctrlPath, c); e != nil {
		t.Fatal(e)
	}
	// Explicit offline feature activation before any controller owns the database.
	if e = os.MkdirAll(ctrlDir, 0700); e != nil {
		t.Fatal(e)
	}
	store, e := history.Open(filepath.Join(ctrlDir, "history.db"), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if e = store.EnableTiering(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = store.EnableReclamation(ctx); e != nil {
		t.Fatal(e)
	}
	if e = store.EnableJitter(ctx); e != nil {
		t.Fatal(e)
	}
	ctrl := startNetworkProcess(t, ns[0], filepath.Join(dir, "controller.log"), nil, bin, "controller", "init", "--config", ctrlPath)
	admin := func(req api.AdminRequest) (api.AdminResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return api.Admin(ctx, ctrlDir, req)
	}
	eventually(t, 10*time.Second, "soak controller ready", func() error { _, e := admin(api.AdminRequest{Operation: "pki.status"}); return e })
	echoStart := func() *networkProcess {
		return startNetworkProcess(t, u.server, filepath.Join(dir, "echo.log"), []string{"VPNCTL_WORKER=echo", "VPNCTL_UPLINK_ADDR=" + relayTargetIP}, worker, "-test.run=^TestNetworkWorker$")
	}
	echo := echoStart()
	paths := make([]string, size)
	cfgs := make([]config.Config, size)
	agents := make([]*networkProcess, size)
	monitors := make([]*networkProcess, size)
	startAgent := func(n int) *networkProcess {
		return startNetworkProcess(t, ns[n+1], filepath.Join(dir, fmt.Sprintf("node-%d.log", n)), nil, bin, "node", "serve", "--config", paths[n], "--retry-delay", "100ms", "--retry-max-delay", "1s")
	}
	startMonitor := func(n int) *networkProcess {
		return startNetworkProcess(t, ns[n+1], filepath.Join(dir, fmt.Sprintf("monitor-%d.log", n)), nil, bin, "monitor", "--interface", "wg0", "--watch", "--history-config", paths[n], "--data", filepath.Join(dir, fmt.Sprintf("monitor-%d.db", n)), "--metrics-port", "19100", "--interval", fmt.Sprintf("%ds", cadence))
	}
	join := func(n int) {
		t.Helper()
		status, e := admin(api.AdminRequest{Operation: "pki.status"})
		if e != nil {
			t.Fatal(e)
		}
		ca := filepath.Join(dir, "bootstrap.crt")
		mustWrite(t, ca, status.PKI.CACert)
		token, e := admin(api.AdminRequest{Operation: "token.create", TTL: "2m", SingleUse: true})
		if e != nil {
			t.Fatal(e)
		}
		cfgs[n].Node.Controller = "https://192.0.2.1:8443"
		if e = config.Save(paths[n], cfgs[n]); e != nil {
			t.Fatal(e)
		}
		netOutput(t, ns[n+1], bin, "node", "join", "--config", paths[n], "--token", token.Token, "--ca-cert", ca)
		netOutput(t, ns[n+1], bin, "node", "sync-config", "--config", paths[n])
		netOutput(t, ns[n+1], bin, "up", "--config", paths[n])
		cfgs[n], e = config.Load(paths[n])
		if e != nil {
			t.Fatal(e)
		}
		cfgs[n].Node.Controller = "https://10.77.0.1:8443"
		if e = config.Save(paths[n], cfgs[n]); e != nil {
			t.Fatal(e)
		}
		if route := netOutput(t, ns[n+1], "ip", "route", "get", relayTargetIP); !strings.Contains(route, "dev wg0") {
			t.Fatal("uplink bypassed WG", route)
		}
	}
	for n := 0; n < size; n++ {
		key, pub := wgKeyPair(t)
		id := fmt.Sprintf("node-%d", n)
		paths[n] = filepath.Join(dir, id+".yaml")
		cfgs[n] = config.Config{Node: &config.NodeConfig{Name: id, WGInterface: "wg0", WGConfigPath: filepath.Join(dir, id+"-wg.conf"), WGPrivateKey: key, WGPublicKey: pub, WGListenPort: 51820, MTU: 1280, DirectMode: "auto", KeepaliveIntervalSec: 5, CandidatesIntervalSec: 2, DirectIntervalSec: cadence, AdvertiseWGEndpoint: fmt.Sprintf("192.0.2.%d:51820", n+2), AdvertisePublicAddr: fmt.Sprintf("192.0.2.%d:51900", n+2), HealthCheckIntervalSec: 3600, PKIDir: filepath.Join(dir, id+"-pki"), UplinkObservation: &uplinkobs.Config{IntervalSec: max(30, cadence), TimeoutMS: 300, Links: []uplinkobs.LinkConfig{{ID: "lan", Interface: "eth0", Kind: "ethernet"}}, Targets: []uplinkobs.TargetConfig{{ID: "app-server", Endpoint: uplinkobs.Endpoint{Host: relayTargetIP, Port: 9191, Protocol: "tcp"}, Interface: "wg0", RelayID: "controller", RelayProbe: &uplinkobs.Endpoint{Host: "10.77.0.1", Port: 51900, Protocol: "udp-echo"}}}}}}
		join(n)
		agents[n] = startAgent(n)
		monitors[n] = startMonitor(n)
	}
	read := func(n int) (soakObservation, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := netCommand(ctx, ns[n+1], worker, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=soak-read", "VPNCTL_SOAK_CONFIG="+paths[n])
		out, e := cmd.CombinedOutput()
		var v soakObservation
		if e != nil {
			return v, fmt.Errorf("soak reader process: %w", e)
		}
		if e = json.Unmarshal(out, &v); e != nil {
			return v, e
		}
		return v, nil
	}
	// A reader can report failure truthfully; only a complete known baseline starts
	// the clock. The API, not test-side injected observations, supplies the evidence.
	ready := func(n int) error {
		v, e := read(n)
		if e != nil {
			return e
		}
		if v.Error != "" || v.Storage.Validity != "observed" || v.RegisteredNodes != size || v.WGReports == 0 || v.WGPeers != size || v.Delivery.WireGuardDelivery.Delivered == 0 || v.Sources["agent-direct"] == 0 || v.Sources["monitor-overlay"] == 0 || v.UplinkSamples == 0 || v.LatestUplinkStage != "none" {
			return fmt.Errorf("producer not ready: error=%q storage=%s nodes=%d WG_reports=%d WG_peers=%d WG_delivered=%d sources=%v uplinks=%d stage=%s", v.Error, v.Storage.Validity, v.RegisteredNodes, v.WGReports, v.WGPeers, v.Delivery.WireGuardDelivery.Delivered, v.Sources, v.UplinkSamples, v.LatestUplinkStage)
		}
		expected := map[string]bool{}
		for i := range cfgs {
			if i != n {
				expected[cfgs[i].Node.Name] = true
			}
		}
		for _, peer := range v.WGPeerNodes {
			delete(expected, peer)
		}
		if len(expected) != 0 {
			return fmt.Errorf("current WG peer identities missing: %v", expected)
		}
		if v.WGObservedAt == nil || time.Since(*v.WGObservedAt) >= 90*time.Second {
			return fmt.Errorf("WG collection stale")
		}
		return nil
	}
	for n := 0; n < size; n++ {
		node := n
		eventually(t, 150*time.Second, "mixed producer readiness", func() error { return ready(node) })
	}
	phasePath := filepath.Join(dir, "phase")
	mustWrite(t, phasePath, "steady")
	stopResources := startResourceSampler(t, results, phasePath)
	exposeSoakArtifact(t, filepath.Join(results, "resources.jsonl"))
	defer stopResources()
	start = time.Now()
	emit(map[string]any{"kind": "start", "at": start, "nodes": size, "cadence_seconds": cadence, "duration_seconds": duration.Seconds()})
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	nextPhase := start.Add(phaseEvery)
	actionIndex, reporter := 0, 0
	actions := []string{"controller_restart", "underlay_loss", "target_restart", "monitor_restart", "node_remove_rejoin", "ca_rotation", "ca_rollback"}
	sample := func(n int, label string, requireHealthy bool) soakObservation {
		t.Helper()
		v, e := read(n)
		if e != nil {
			t.Fatal(e)
		}
		v.Phase = label
		emit(v)
		if requireHealthy && v.Error != "" {
			t.Fatal("unexpected observation failure", label, v.Error)
		}
		if requireHealthy && (v.HeartbeatUnknown != 0 || v.HeartbeatMaxAgeSeconds > 30) {
			t.Fatal("heartbeat observation unavailable or delayed", v.HeartbeatUnknown, v.HeartbeatMaxAgeSeconds)
		}
		if requireHealthy && v.Storage.Validity != "observed" {
			t.Fatal("storage collector unavailable", label, v.Storage.Reason)
		}
		if v.Storage.Values != nil && (v.Storage.Values.DatabaseBytes > (1<<30) || v.Storage.Values.WALBytes > (64<<20)) {
			t.Fatal("storage byte budget exceeded")
		}
		return v
	}
	for time.Since(start) < duration {
		sample(reporter%size, "steady", true)
		reporter++
		if !time.Now().Before(nextPhase) {
			name := actions[actionIndex%len(actions)]
			actionIndex++
			nextPhase = time.Now().Add(phaseEvery)
			mustWrite(t, phasePath, name)
			began := time.Now()
			emit(map[string]any{"kind": "fault_start", "phase": name, "at": began})
			switch name {
			case "controller_restart":
				ctrl.stop()
				if v := sample(0, name, false); v.Error == "" {
					t.Fatal("injected outage was not observed", name)
				}
				time.Sleep(time.Second)
				ctrl = startNetworkProcess(t, ns[0], filepath.Join(dir, "controller.log"), nil, bin, "controller", "init", "--config", ctrlPath)
			case "underlay_loss":
				netOutput(t, ns[1], "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%")
				if v := sample(0, name, false); v.Error == "" {
					t.Fatal("injected outage was not observed", name)
				}
				time.Sleep(time.Second)
				netOutput(t, ns[1], "tc", "qdisc", "del", "dev", "eth0", "root")
			case "target_restart":
				echo.stop()
				time.Sleep(time.Duration(max(30, cadence)+1) * time.Second)
				if v := sample(0, name, true); v.LatestUplinkStage != "server_endpoint" {
					t.Fatal("target outage not diagnosed", v.LatestUplinkStage)
				}
				echo = echoStart()
			case "monitor_restart":
				sample(0, "before_monitor_restart", true)
				monitors[0].terminate(t)
				monitors[0] = startMonitor(0)
			case "node_remove_rejoin":
				n := size - 1
				sample(n, "before_node_remove", true)
				monitors[n].terminate(t)
				agents[n].terminate(t)
				frozen, e := pki.LoadCredentials(cfgs[n].Node.PKIDir)
				if e != nil {
					t.Fatal(e)
				}
				frozenDir := filepath.Join(dir, "removed-credentials")
				if e := pki.SaveCredentials(frozenDir, frozen, ""); e != nil {
					t.Fatal(e)
				}
				if _, e := admin(api.AdminRequest{Operation: "node.remove", NodeID: cfgs[n].Node.Name}); e != nil {
					t.Fatal(e)
				}
				if v := sample(0, "node_removed", true); v.RegisteredNodes != size-1 {
					t.Fatal("removed node still registered", v.RegisteredNodes)
				}
				// Removed identities are tombstoned. This models replacement with a
				// new identity/key, not bypassing the production deletion barrier.
				cfgs[n].Node.Name = fmt.Sprintf("node-%d-generation-%d", n, actionIndex)
				cfgs[n].Node.WGPrivateKey, cfgs[n].Node.WGPublicKey = wgKeyPair(t)
				cfgs[n].Node.PKIDir = filepath.Join(dir, cfgs[n].Node.Name+"-pki")
				join(n)
				agents[n] = startAgent(n)
				monitors[n] = startMonitor(n)
				// Restore transport with the replacement first. A timeout from
				// the removed WG peer is not evidence of HTTP authorization.
				eventually(t, 20*time.Second, "replacement API before replay", func() error {
					v, e := read(n)
					if e != nil {
						return e
					}
					if v.Error != "" {
						return fmt.Errorf("%s", v.Error)
					}
					return nil
				})
				replayCtx, replayStop := context.WithTimeout(context.Background(), 60*time.Second)
				replay := netCommand(replayCtx, ns[n+1], worker, "-test.run=^TestNetworkWorker$")
				replay.Env = append(os.Environ(), "VPNCTL_WORKER=replay", "VPNCTL_PKI="+frozenDir)
				replayResult, replayError := replay.CombinedOutput()
				replayStop()
				if replayError != nil {
					t.Fatalf("removed credential replay: %v: %s", replayError, replayResult)
				}
			case "ca_rotation", "ca_rollback":
				operations := []string{"ca.prepare", "ca.activate"}
				if name == "ca_rollback" {
					operations = append(operations, "ca.rollback")
				}
				operations = append(operations, "ca.retire")
				for _, op := range operations {
					eventually(t, 30*time.Second, op, func() error { _, e := admin(api.AdminRequest{Operation: op}); return e })
				}
			}
			eventually(t, 150*time.Second, "recovery after "+name, func() error { return ready(0) })
			if name == "node_remove_rejoin" {
				eventually(t, 150*time.Second, "rejoined producer", func() error { return ready(size - 1) })
			}
			phases[name]++
			emit(map[string]any{"kind": "fault_recovered", "phase": name, "at": time.Now().UTC(), "duration_seconds": time.Since(began).Seconds()})
			mustWrite(t, phasePath, "steady")
		}
		if time.Since(start) < duration {
			<-tick.C
		}
	}
	for n := 0; n < size; n++ {
		sample(n, "final", true)
	}
	emit(map[string]any{"kind": "workload_end", "at": time.Now().UTC(), "elapsed_seconds": time.Since(start).Seconds()})
	for n := 0; n < size; n++ {
		monitors[n].terminate(t)
		agents[n].terminate(t)
	}
	ctrl.terminate(t)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
	defer stop()
	if e := history.Check(ctx, filepath.Join(ctrlDir, "history.db")); e != nil {
		t.Fatal(e)
	}
	if len(phases) != len(actions) {
		t.Fatalf("incomplete fault coverage: %v; increase duration or reduce phase interval", phases)
	}
	completed = true
}

// Public progress is readable by the invoking operator during a long run.
// Credentials/configuration remain in the separate private work mount.
func exposeSoakArtifact(t *testing.T, path string) {
	t.Helper()
	if os.Getenv("VPNCTL_RESULT_UID") == "" {
		return
	}
	uid, e := strconv.Atoi(os.Getenv("VPNCTL_RESULT_UID"))
	if e != nil || uid < 0 {
		t.Fatal("invalid result uid")
	}
	gid, e := strconv.Atoi(os.Getenv("VPNCTL_RESULT_GID"))
	if e != nil || gid < 0 {
		t.Fatal("invalid result gid")
	}
	if e := os.Chown(path, uid, gid); e != nil {
		t.Fatal(e)
	}
}
