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
)

// The deployment firewall deliberately allows every forwarded packet here.
// Negative results therefore exercise the product policy, not a restrictive
// fixture firewall or a missing target listener/return path.
func TestNetns_M3ForwardingPolicy(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixture(t)
	phases := []string{}
	defer func() {
		writeM3Report(t, filepath.Join(f.results, "forwarding.json"), map[string]any{"completed": !t.Failed(), "phases": phases, "scope": "product source/target enforcement; deployment-owned SNAT and explicit return routes; no automatic selection or failover SLO"})
	}()
	probe := func(ns, source, target string, want bool) m3Probe {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		var result m3Probe
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			cmd := netCommand(ctx, ns, f.worker, "-test.run=^TestNetworkWorker$")
			cmd.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE="+source, "VPNCTL_PROBE_TARGET="+target)
			b, err := cmd.Output()
			cancel()
			if err != nil || json.Unmarshal(b, &result) != nil {
				t.Fatalf("probe process: %v %s", err, b)
			}
			// A newly started echo process must be listening before its
			// positive control is used. Do not retry negative results to pass.
			if want && !result.OK && result.Failure == "refused" && time.Now().Before(deadline) {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			if result.OK != want {
				t.Fatalf("probe %s -> %s want=%v: %s", source, target, want, b)
			}
			break
		}
		return result
	}
	const forbidden = "198.18.0.3"
	netOutput(t, f.target, "ip", "address", "add", forbidden+"/32", "dev", "eth0")
	startNetworkProcess(t, f.target, filepath.Join(f.private, "forbidden-echo.log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=" + forbidden}, f.worker, "-test.run=^TestNetworkWorker$")
	for i, r := range f.recipients {
		netOutput(t, r.ns, "nft", "delete", "table", "ip", "m3")
		(relayUplink{relay: r.ns}).nft(t, fmt.Sprintf(`table ip m3 {
 chain forward { type filter hook forward priority filter; policy accept; }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
 oifname "uplink0" ip saddr 10.78.0.0/16 ip daddr 198.18.0.0/24 snat to 198.18.0.%d
 }
}`, 11+i))
		probe(r.ns, "", forbidden, true) // Independent positive listener control.
	}
	for i, p := range f.plan.Paths {
		r := f.recipients[i/2]
		source := strings.TrimSuffix(p.InnerAddress, "/32")
		table := fmt.Sprint(28000 + i)
		if v := probe(f.robot, source, m3Target, true); v.Source != fmt.Sprintf("198.18.0.%d", 11+i/2) {
			t.Fatal("wrong SNAT source", v)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		udp := netCommand(ctx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
		udp.Env = append(os.Environ(), "VPNCTL_WORKER=m3-probe", "VPNCTL_PROBE_SOURCE="+source, "VPNCTL_PROBE_UDP_ERROR=1")
		b, err := udp.Output()
		cancel()
		var icmp m3Probe
		if err != nil || json.Unmarshal(b, &icmp) != nil || !icmp.OK {
			t.Fatalf("related ICMP lost: %v %s", err, b)
		}
		phases = append(phases, "related_icmp_for_approved_connection_"+p.PathID)
		// A compromised client can widen its own WG AllowedIPs and routes, but
		// cannot widen the relay's authenticated source/target authorization.
		netOutput(t, f.robot, "wg", "set", p.Pin.WGInterface, "peer", p.RelayPublicKey, "allowed-ips", m3Target+"/32,"+forbidden+"/32")
		netOutput(t, f.robot, "ip", "route", "add", forbidden+"/32", "dev", p.Pin.WGInterface, "src", source, "table", table)
		for attempt := 0; attempt < 3; attempt++ {
			probe(f.robot, source, forbidden, false)
		}
		netOutput(t, f.robot, "ip", "route", "del", forbidden+"/32", "table", table)
		netOutput(t, f.robot, "wg", "set", p.Pin.WGInterface, "peer", p.RelayPublicKey, "allowed-ips", m3Target+"/32")
		phases = append(phases, "approved_snat_and_repeated_unapproved_target_"+p.PathID)
		// Force another approved binding's source into this peer's encrypted
		// tunnel. The relay must reject it even though that source exists locally.
		otherSource := strings.TrimSuffix(f.plan.Paths[(i+1)%len(f.plan.Paths)].InnerAddress, "/32")
		netOutput(t, f.robot, "ip", "rule", "add", "priority", "27000", "from", otherSource+"/32", "lookup", table)
		probe(f.robot, otherSource, m3Target, false)
		netOutput(t, f.robot, "ip", "rule", "del", "priority", "27000", "from", otherSource+"/32", "lookup", table)
		probe(f.robot, source, m3Target, true)
		phases = append(phases, "cross_binding_source_spoof_rejected_"+p.PathID)
		// Exercise explicit server return routing, including an absent-route
		// failure. The application source must be the node's approved /32.
		netOutput(t, r.ns, "nft", "flush", "chain", "ip", "m3", "postrouting")
		probe(f.robot, source, m3Target, false)
		netOutput(t, f.target, "ip", "route", "add", p.InnerAddress, "via", fmt.Sprintf("198.18.0.%d", 11+i/2), "dev", "eth0")
		if v := probe(f.robot, source, m3Target, true); v.Source != source {
			t.Fatal("explicit return route hid source", v)
		}
		// The same target may reply to an uplink connection, but it may not
		// initiate a new connection to a node. Prove the node listener is live.
		listener := startNetworkProcess(t, f.robot, filepath.Join(f.private, p.PathID+"-node-echo.log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=" + source}, f.worker, "-test.run=^TestNetworkWorker$")
		probe(f.robot, source, source, true)
		probe(f.target, m3Target, source, false)
		listener.stop()
		phases = append(phases, "unsolicited_server_connection_blocked_"+p.PathID)
		// Deployment firewall drops have final authority even if vpnctl grants
		// this path. A different manager's reload must not be undone.
		(relayUplink{relay: r.ns}).nft(t, `table inet external_policy {
 chain forward { type filter hook forward priority 10; policy drop;
 }
}`)
		probe(f.robot, source, m3Target, false)
		if out := r.require("inspect", -1, 0); out.UplinkHealth != "unknown" {
			t.Fatal("kernel install claimed application health", out)
		}
		netOutput(t, r.ns, "nft", "delete", "table", "inet", "external_policy")
		probe(f.robot, source, m3Target, true)
		phases = append(phases, "return_route_and_external_firewall_"+p.PathID)
		netOutput(t, f.target, "ip", "route", "del", p.InnerAddress)
		netOutput(t, r.ns, "nft", "add", "rule", "ip", "m3", "postrouting", "oifname", "uplink0", "ip", "saddr", "10.78.0.0/16", "ip", "daddr", "198.18.0.0/24", "snat", "to", fmt.Sprintf("198.18.0.%d", 11+i/2))
	}
}
