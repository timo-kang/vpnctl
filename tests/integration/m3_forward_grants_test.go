//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

// Both destinations and both sources are valid in this same relay endpoint.
// A union of permitted sources/targets would incorrectly allow the cross pairs.
func TestNetns_M3ForwardingGrantSeparation(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixture(t)
	r := f.recipients[0]
	r.watch.terminate(t)
	otherCfg := f.controller.enroll(f.robot, "other-robot")
	cfg, err := config.Load(otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Node.RelayUnderlays = []relayplan.Underlay{{ID: "lan0", Interface: "wan0", Kind: "ethernet"}}
	if err := config.Save(otherCfg, cfg); err != nil {
		t.Fatal(err)
	}
	const otherTarget = "198.18.0.3"
	netOutput(t, f.target, "ip", "address", "add", otherTarget+"/32", "dev", "eth0")
	startNetworkProcess(t, f.target, filepath.Join(f.private, "other-target.log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=" + otherTarget}, f.worker, "-test.run=^TestNetworkWorker$")
	f.spec.Targets = append(f.spec.Targets, relaycatalog.Target{ID: "other-app", Prefixes: []string{otherTarget + "/32"}, ProbeAddress: otherTarget, Port: 9192, Protocol: "tcp"})
	f.spec.Paths = append(f.spec.Paths, relaycatalog.Path{ID: "other-path", NodeID: "other-robot", RelayID: r.relay, EndpointID: "ep0", UnderlayID: "lan0", TargetIDs: []string{"other-app"}})
	f.controller.apply(f.spec, 3600)
	netOutput(t, f.robot, integrationBinary(t), "node", "relay", "refresh", "--config", otherCfg)
	var plan relayplan.Plan
	if err := json.Unmarshal([]byte(netOutput(t, f.robot, integrationBinary(t), "node", "relay", "plan", "--config", otherCfg)), &plan); err != nil || len(plan.Paths) != 1 {
		t.Fatal(err, plan)
	}
	other := plan.Paths[0]
	netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", otherCfg, "--path-id", other.PathID)
	r.require("release", 0, 0)
	r.require("refresh", -1, 0)
	r.start()
	r.ready()
	r.require("apply", 0, 51820)
	r.ready()
	// The fixture allows all target traffic: only the product enforces pairs.
	netOutput(t, r.ns, "nft", "delete", "table", "ip", "m3")
	(relayUplink{relay: r.ns}).nft(t, `table ip m3 {
 chain forward { type filter hook forward priority filter; policy accept; }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
 oifname "uplink0" ip saddr 10.78.0.0/16 ip daddr 198.18.0.0/24 snat to 198.18.0.11
 }
}`)
	original := f.plan.Paths[0]
	for i, p := range []relayplan.Candidate{original, other} {
		table := fmt.Sprint(29000 + i)
		source := strings.TrimSuffix(p.InnerAddress, "/32")
		netOutput(t, f.robot, "wg", "set", p.Pin.WGInterface, "peer", p.RelayPublicKey, "allowed-ips", m3Target+"/32,"+otherTarget+"/32")
		netOutput(t, f.robot, "ip", "rule", "add", "priority", table, "from", p.InnerAddress, "lookup", table)
		for _, target := range []string{m3Target, otherTarget} {
			netOutput(t, f.robot, "ip", "route", "add", target+"/32", "dev", p.Pin.WGInterface, "src", source, "table", table)
		}
	}
	// Original source's existing priority-28000 table must also offer both
	// targets, so rejection cannot be attributed to a missing node route.
	netOutput(t, f.robot, "ip", "route", "add", otherTarget+"/32", "dev", original.Pin.WGInterface, "src", strings.TrimSuffix(original.InnerAddress, "/32"), "table", "28000")
	probe := func(p relayplan.Candidate, target string) m3Probe {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := netCommand(ctx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE="+strings.TrimSuffix(p.InnerAddress, "/32"), "VPNCTL_PROBE_TARGET="+target)
		b, err := cmd.Output()
		var result m3Probe
		if err != nil || json.Unmarshal(b, &result) != nil {
			t.Fatal(err, string(b))
		}
		return result
	}
	results := []map[string]any{}
	for i, p := range []relayplan.Candidate{original, other} {
		targets := []string{m3Target, otherTarget}
		allowed, forbidden := targets[i], targets[1-i]
		eventually(t, 5*time.Second, "approved target positive control", func() error {
			if !probe(p, allowed).OK {
				return fmt.Errorf("not reachable")
			}
			return nil
		})
		for attempt := 0; attempt < 3; attempt++ {
			if result := probe(p, forbidden); result.OK {
				t.Fatal("cross-grant access", p.PathID, result)
			}
		}
		if !probe(p, allowed).OK {
			t.Fatal("denial also broke authorized connection", p.PathID)
		}
		results = append(results, map[string]any{"path": p.PathID, "allowed": allowed, "denied": forbidden, "repeated_denials": 3})
	}
	writeM3Report(t, filepath.Join(f.results, "grant-separation.json"), map[string]any{"completed": true, "same_relay_endpoint": true, "grants": results})
}
