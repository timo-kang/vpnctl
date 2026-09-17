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
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/uplink"
)

func TestNetns_UplinkDiagnosis(t *testing.T) {
	requireNetwork(t)
	ns := newNamespaces(t, 1)
	bin := integrationBinary(t)
	dir, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "uplink-diagnosis-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("artifacts: %s", dir)
	keys := t.TempDir()
	privA, pubA := wgKeyPair(t)
	privB, pubB := wgKeyPair(t)
	for i, priv := range []string{privA, privB} {
		path := filepath.Join(keys, fmt.Sprintf("key-%d", i))
		mustWrite(t, path, priv)
		netOutput(t, ns[i], "ip", "link", "add", "wg0", "type", "wireguard")
		netOutput(t, ns[i], "wg", "set", "wg0", "private-key", path, "listen-port", "51820")
		netOutput(t, ns[i], "ip", "addr", "add", fmt.Sprintf("10.77.0.%d/24", i+1), "dev", "wg0")
		netOutput(t, ns[i], "ip", "link", "set", "wg0", "up")
	}
	netOutput(t, ns[0], "wg", "set", "wg0", "peer", pubB, "allowed-ips", "10.77.0.2/32", "endpoint", "192.0.2.2:51820")
	netOutput(t, ns[1], "wg", "set", "wg0", "peer", pubA, "allowed-ips", "10.77.0.1/32,198.18.0.2/32", "endpoint", "192.0.2.1:51820")
	netOutput(t, ns[1], "wg", "set", "wg0", "fwmark", "42")
	netOutput(t, ns[1], "ip", "route", "add", relayTargetIP+"/32", "dev", "wg0")
	// A second real uplink, independently connected to the relay's underlay.
	netOutput(t, ns[0], "ip", "link", "add", "eth1", "type", "veth", "peer", "name", "eth1", "netns", ns[1])
	for i := 0; i < 2; i++ {
		netOutput(t, ns[i], "ip", "addr", "add", fmt.Sprintf("198.19.0.%d/30", i+1), "dev", "eth1")
		netOutput(t, ns[i], "ip", "link", "set", "eth1", "up")
	}
	network := newRelayUplink(t, ns[0])
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	echo := func(namespace, ip, name string) *networkProcess {
		return startNetworkProcess(t, namespace, filepath.Join(dir, name+".log"), []string{"VPNCTL_WORKER=echo", "VPNCTL_UPLINK_ADDR=" + ip}, worker, "-test.run=^TestNetworkWorker$")
	}
	target := echo(network.server, relayTargetIP, "target")
	relay := echo(ns[0], "10.77.0.1", "relay")
	control := echo(ns[0], "192.0.2.1", "control")
	c := uplink.Config{IntervalSec: 60, TimeoutMS: 300, Links: []uplink.LinkConfig{{ID: "lan", Interface: "eth0", Kind: "ethernet"}, {ID: "wifi", Interface: "eth1", Kind: "wifi"}, {ID: "lte", Interface: "wwan0", Kind: "lte", Modem: "0"}}, Controller: &uplink.Endpoint{Host: "192.0.2.1", Port: 9191, Protocol: "tcp"}, Targets: []uplink.TargetConfig{{ID: "server", Endpoint: uplink.Endpoint{Host: relayTargetIP, Port: 9191, Protocol: "tcp"}, Interface: "wg0", RelayID: "hub", RelayProbe: &uplink.Endpoint{Host: "10.77.0.1", Port: 9191, Protocol: "udp-echo"}}}}
	cfg := config.Config{Node: &config.NodeConfig{Name: "lab", Controller: "http://192.0.2.1:9191", UplinkObservation: &c}}
	path := filepath.Join(keys, "node.yaml")
	if err = config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	check := func(phase, stage, state string) uplink.Snapshot {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		raw, e := netCommand(ctx, ns[1], bin, "node", "diagnose", "--config", path).Output()
		if e != nil {
			t.Fatal(e)
		}
		body := string(raw)
		var s uplink.Snapshot
		if e := json.Unmarshal([]byte(body), &s); e != nil {
			t.Fatal(e, body)
		}
		if len(s.Targets) != 1 || s.Targets[0].Service.State != state || s.Targets[0].FailureStage != stage {
			t.Fatalf("%s: %s", phase, body)
		}
		if len(s.Links) != 3 || s.Links[2].Present == nil || *s.Links[2].Present || s.Links[2].Modem.State != "unknown" {
			t.Fatal("optional modem collector", body)
		}
		mustWrite(t, filepath.Join(dir, phase+".json"), body)
		return s
	}
	// Fresh processes/listeners settle before taking the first observation.
	for _, entry := range []struct{ namespace, ip string }{{network.server, relayTargetIP}, {ns[0], "10.77.0.1"}, {ns[0], "192.0.2.1"}} {
		eventually(t, 5e9, "echo ready", func() error {
			if netOutput(t, entry.namespace, "ss", "-H", "-lnt", "src", entry.ip+":9191") == "" {
				return fmt.Errorf("not listening")
			}
			return nil
		})
	}
	s := check("healthy", "none", "up")
	if s.Targets[0].TransportRoute.Interface != "eth0" || s.Targets[0].RelayPeerFingerprint == "" {
		t.Fatal("missing selected transport", s)
	}
	// Mark-specific route selection is observable, but changed only by the test.
	netOutput(t, ns[1], "ip", "route", "add", "table", "42", "192.0.2.1/32", "via", "198.19.0.1", "dev", "eth1")
	netOutput(t, ns[1], "ip", "rule", "add", "priority", "100", "fwmark", "42", "lookup", "42")
	s = check("selected-second-uplink", "none", "up")
	if s.Targets[0].TransportRoute.Interface != "eth1" {
		t.Fatal("outer fwmark ignored", s)
	}
	netOutput(t, ns[1], "ip", "rule", "del", "priority", "100")
	for cycle := 0; cycle < 3; cycle++ {
		prefix := fmt.Sprintf("cycle-%d-", cycle)
		control.stop()
		s = check(prefix+"controller-down", "none", "up")
		if s.Links[0].Controller.State != "down" {
			t.Fatal("controller failure hidden", s)
		}
		control = echo(ns[0], "192.0.2.1", "control")
		target.stop()
		check(prefix+"service-down", "server_endpoint", "down")
		target = echo(network.server, relayTargetIP, "target")
		relay.stop()
		network.forwarding(t, false)
		check(prefix+"tunnel-no-response", "relay_tunnel", "down")
		relay = echo(ns[0], "10.77.0.1", "relay")
		network.forwarding(t, true)
		netOutput(t, ns[1], "ip", "route", "del", relayTargetIP+"/32")
		check(prefix+"route-missing", "overlay_route", "down")
		netOutput(t, ns[1], "ip", "route", "add", relayTargetIP+"/32", "dev", "wg0")
		netOutput(t, ns[1], "ip", "link", "set", "eth0", "down")
		netOutput(t, ns[1], "ip", "link", "set", "eth1", "down")
		s = check(prefix+"no-uplink", "underlay", "down")
		if s.Underlay.Reason != "no_uplink" {
			t.Fatal(s)
		}
		netOutput(t, ns[1], "ip", "link", "set", "eth0", "up")
		netOutput(t, ns[1], "ip", "link", "set", "eth1", "up")
		check(prefix+"recovered", "none", "up")
	}
}
