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

	"vpnctl/internal/monitor"
)

// Exercise the shipped CLI and its HTTP/Prometheus wiring with real WG peers.
func TestNetns_MonitorQuality(t *testing.T) {
	requireNetwork(t)
	ns := newNamespaces(t, 1)
	dir, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "monitor-quality-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("artifacts: %s", dir)
	// Private keys are temporary inputs, never copied into the result artifacts.
	keys := t.TempDir()
	privA, pubA := wgKeyPair(t)
	privB, pubB := wgKeyPair(t)
	for i, priv := range []string{privA, privB} {
		path := filepath.Join(keys, fmt.Sprintf("key-%d", i))
		mustWrite(t, path, priv)
		netOutput(t, ns[i], "ip", "link", "add", "wg0", "type", "wireguard")
		netOutput(t, ns[i], "wg", "set", "wg0", "private-key", path, "listen-port", "51820")
		netOutput(t, ns[i], "ip", "address", "add", fmt.Sprintf("10.77.0.%d/24", i+1), "dev", "wg0")
		netOutput(t, ns[i], "ip", "link", "set", "wg0", "up")
	}
	netOutput(t, ns[0], "wg", "set", "wg0", "peer", pubB, "allowed-ips", "10.77.0.2/32", "endpoint", "192.0.2.2:51820")
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", pubA, "allowed-ips", "10.77.0.1/32", "endpoint", "192.0.2.1:51820")
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startEcho := func() *networkProcess {
		return startNetworkProcess(t, ns[0], filepath.Join(dir, "echo.log"), nil, integrationBinary(t), "direct", "serve", "--listen", "10.77.0.1:9191")
	}
	echo := startEcho()
	process := startNetworkProcess(t, ns[1], filepath.Join(dir, "monitor.log"), nil, integrationBinary(t), "monitor", "--interface", "wg0", "--watch", "--data", filepath.Join(dir, "monitor.db"), "--probe-port", "9191", "--metrics-port", "19100", "--interval", "200ms", "--quality-window", "4s", "--quality-stale-after", "3s")
	read := func(path string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := netCommand(ctx, ns[1], "env", "VPNCTL_WORKER=monitor-http", "VPNCTL_MONITOR_PATH="+path, worker, "-test.run=^TestNetworkWorker$")
		return cmd.CombinedOutput()
	}
	check := func(phase string, want string) {
		t.Helper()
		eventually(t, 10*time.Second, phase, func() error {
			data, err := read("/network/quality")
			if err != nil {
				return err
			}
			var response monitor.QualityResponse
			if err := json.Unmarshal(data, &response); err != nil {
				return fmt.Errorf("decode: %w: %s", err, data)
			}
			if len(response.Peers) != 1 || response.Peers[0].Quality != want {
				return fmt.Errorf("unexpected quality: %s", data)
			}
			q := response.Peers[0]
			if want == "good" && (q.Stale || q.SampleCount < 3 || q.LossPct == nil || *q.LossPct != 0) {
				return fmt.Errorf("good contract: %s", data)
			}
			if want == "offline" && (q.Stale || q.RTTMs != nil || q.LossPct == nil || *q.LossPct != 100 || q.ErrorReason != "responder_unavailable") {
				return fmt.Errorf("offline contract: %s", data)
			}
			if want == "unknown" && (!response.Stale || response.ErrorReason != "discovery_failed") {
				return fmt.Errorf("discovery contract: %s", data)
			}
			metricData, err := read("/metrics")
			if err != nil {
				return err
			}
			level := map[string]string{"good": "3", "offline": "0", "unknown": "-1"}[want]
			if !strings.Contains(string(metricData), "vpnctl_link_quality{peer=\"10.77.0.1\"} "+level+"\n") {
				return fmt.Errorf("metric disagrees: %s", metricData)
			}
			if err := os.WriteFile(filepath.Join(dir, phase+".json"), data, 0600); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, phase+".prom"), metricData, 0600)
		})
	}
	check("healthy", "good")
	// Compare the shipped collector against independent kernel transfer output.
	// Counter snapshots bracket the API observation while ordinary echo traffic
	// continues; do not persist wg dump because it contains private keys.
	kernel := func() (uint64, uint64) {
		rows := strings.Split(strings.TrimSpace(netOutput(t, ns[1], "wg", "show", "wg0", "transfer")), "\n")
		for _, line := range rows {
			f := strings.Fields(line)
			if len(f) == 3 && f[0] == pubA {
				rx, e := strconv.ParseUint(f[1], 10, 64)
				if e != nil {
					t.Fatal(e)
				}
				tx, e := strconv.ParseUint(f[2], 10, 64)
				if e != nil {
					t.Fatal(e)
				}
				return rx, tx
			}
		}
		t.Fatal("missing kernel peer")
		return 0, 0
	}
	lowerRX, lowerTX := kernel()
	var priorGeneration string
	eventually(t, 5*time.Second, "real WireGuard counter and handshake", func() error {
		body, e := read("/network/quality")
		if e != nil {
			return e
		}
		var r monitor.QualityResponse
		if e = json.Unmarshal(body, &r); e != nil {
			return e
		}
		if len(r.WireGuard) != 1 {
			return fmt.Errorf("missing WG observation")
		}
		v := r.WireGuard[0]
		upperRX, upperTX := kernel()
		if v.RX == nil || v.TX == nil || uint64(*v.RX) < lowerRX || uint64(*v.TX) < lowerTX || uint64(*v.RX) > upperRX || uint64(*v.TX) > upperTX || *v.RX == 0 || *v.TX == 0 || v.HandshakeState != "observed" || v.RXPerSecond == nil {
			return fmt.Errorf("kernel/collector not converged: %+v", v)
		}
		priorGeneration = v.Generation
		return os.WriteFile(filepath.Join(dir, "wireguard-kernel.json"), body, 0600)
	})
	// Observe removal before re-add, with no endpoint: the peer remains visible,
	// carries real zero counters and never-handshaken state, and is not a probe.
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", pubA, "remove")
	eventually(t, 5*time.Second, "removed WG peer", func() error {
		body, e := read("/network/quality")
		if e != nil {
			return e
		}
		var r monitor.QualityResponse
		e = json.Unmarshal(body, &r)
		if e != nil {
			return e
		}
		if len(r.WireGuard) != 0 {
			return fmt.Errorf("old peer visible")
		}
		return nil
	})
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", pubA, "allowed-ips", "10.77.0.1/32")
	eventually(t, 5*time.Second, "endpointless WG peer", func() error {
		body, e := read("/network/quality")
		if e != nil {
			return e
		}
		var r monitor.QualityResponse
		e = json.Unmarshal(body, &r)
		if e != nil {
			return e
		}
		if len(r.WireGuard) != 1 {
			return fmt.Errorf("peer absent")
		}
		v := r.WireGuard[0]
		if v.Endpoint || v.HandshakeState != "never" || v.Generation == priorGeneration || v.RX == nil || *v.RX != 0 || v.TX == nil || *v.TX != 0 || len(r.Peers) != 1 || r.Peers[0].ErrorReason != "no_endpoint" || r.Peers[0].SampleCount != 0 {
			return fmt.Errorf("endpointless contract: %+v", r)
		}
		return os.WriteFile(filepath.Join(dir, "wireguard-no-endpoint.json"), body, 0600)
	})
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", pubA, "endpoint", "192.0.2.1:51820")
	check("wireguard-peer-restored", "good")

	// The shipped CLI must reject an occupied metrics port before entering its loop.
	bindCtx, stopBind := context.WithTimeout(context.Background(), 5*time.Second)
	bindCmd := netCommand(bindCtx, ns[1], integrationBinary(t), "monitor", "--interface", "wg0", "--watch", "--data", filepath.Join(dir, "conflict.db"), "--metrics-port", "19100")
	output, bindErr := bindCmd.CombinedOutput()
	stopBind()
	if bindErr == nil || !strings.Contains(string(output), "metrics bind") {
		t.Fatalf("metrics conflict: %v %s", bindErr, output)
	}

	echo.stop()
	check("responder-stopped", "offline")
	echo = startEcho()
	check("responder-restored", "good")
	beforeRecreate, e := read("/network/quality")
	if e != nil {
		t.Fatal(e)
	}
	var saved monitor.QualityResponse
	if e = json.Unmarshal(beforeRecreate, &saved); e != nil {
		t.Fatal(e)
	}
	beforeGeneration := saved.WireGuard[0].Generation
	netOutput(t, ns[1], "ip", "link", "del", "wg0")
	check("interface-removed", "unknown")
	netOutput(t, ns[1], "ip", "link", "add", "wg0", "type", "wireguard")
	eventually(t, 5*time.Second, "empty peer discovery", func() error {
		data, err := read("/network/quality")
		if err != nil {
			return err
		}
		var response monitor.QualityResponse
		if err := json.Unmarshal(data, &response); err != nil {
			return err
		}
		if response.ErrorReason != "no_peers" || response.Stale || len(response.Peers) != 0 {
			return fmt.Errorf("empty contract: %s", data)
		}
		metrics, err := read("/metrics")
		if err != nil {
			return err
		}
		if strings.Contains(string(metrics), "vpnctl_link_quality{") {
			return fmt.Errorf("removed peer remains in metrics")
		}
		return os.WriteFile(filepath.Join(dir, "empty.json"), data, 0600)
	})
	netOutput(t, ns[1], "wg", "set", "wg0", "private-key", filepath.Join(keys, "key-1"), "listen-port", "51820")
	netOutput(t, ns[1], "ip", "address", "add", "10.77.0.2/24", "dev", "wg0")
	netOutput(t, ns[1], "ip", "link", "set", "wg0", "up")
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", pubA, "allowed-ips", "10.77.0.1/32", "endpoint", "192.0.2.1:51820")
	check("interface-recreated", "good")
	current, e := read("/network/quality")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(current, &saved); e != nil {
		t.Fatal(e)
	}
	if saved.WireGuard[0].Generation == beforeGeneration {
		t.Fatal("interface recreation reused counter generation")
	}
	beforeGeneration = saved.WireGuard[0].Generation
	process.terminate(t)
	process = startNetworkProcess(t, ns[1], filepath.Join(dir, "monitor-restarted.log"), nil, integrationBinary(t), "monitor", "--interface", "wg0", "--watch", "--data", filepath.Join(dir, "monitor.db"), "--probe-port", "9191", "--metrics-port", "19100", "--interval", "200ms", "--quality-window", "4s", "--quality-stale-after", "3s")
	check("monitor-restarted", "good")
	current, e = read("/network/quality")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(current, &saved); e != nil {
		t.Fatal(e)
	}
	if saved.WireGuard[0].Generation == beforeGeneration {
		t.Fatal("collector restart reused counter generation")
	}
	process.terminate(t)
}
