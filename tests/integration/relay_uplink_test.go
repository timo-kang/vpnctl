// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/config"
)

const relayTargetIP = "198.18.0.2"
const relayGatewayIP = "198.18.0.1"

// The target has exactly one link: the relay's separate uplink. It has neither
// an underlay/management connection to the nodes nor a WireGuard interface.
type relayUplink struct{ relay, server string }

func newRelayUplink(t *testing.T, relay string) relayUplink {
	t.Helper()
	u := relayUplink{relay: relay, server: relay + "-uplink"}
	run(t, ".", "ip", "netns", "add", u.server)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", u.server).Run() })
	netOutput(t, relay, "ip", "link", "add", "uplink0", "type", "veth", "peer", "name", "eth0", "netns", u.server)
	for _, end := range []struct{ ns, iface, ip string }{
		{relay, "uplink0", relayGatewayIP}, {u.server, "eth0", relayTargetIP},
	} {
		netOutput(t, end.ns, "ip", "link", "set", "lo", "up")
		netOutput(t, end.ns, "ip", "addr", "add", end.ip+"/30", "dev", end.iface)
		netOutput(t, end.ns, "ip", "link", "set", end.iface, "up")
	}
	u.returnRoute(t, true)
	u.forwarding(t, true)
	u.nft(t, `table ip vpnctl_lab {
        chain forward {
            type filter hook forward priority filter; policy drop;
            iifname "wg0" oifname "uplink0" ip saddr 10.77.0.0/24 ip daddr 198.18.0.2 counter accept
            iifname "uplink0" oifname "wg0" ip saddr 198.18.0.2 ip daddr 10.77.0.0/24 counter accept
        }
    }`)
	return u
}

func (u relayUplink) nft(t *testing.T, rules string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := netCommand(ctx, u.relay, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandbox nft: %v: %s", err, out)
	}
}

func (u relayUplink) forwarding(t *testing.T, enabled bool) {
	t.Helper()
	value := "0"
	if enabled {
		value = "1"
	}
	// Docker masks /proc/sys read-only. ip netns exec creates a private mount
	// namespace; mount a fresh proc ONLY there, within the disposable container.
	// No host sysctl, host-network mode or privileged container is required.
	netOutput(t, u.relay, "sh", "-c", `mount -t proc proc /proc && printf '%s' "$1" > /proc/sys/net/ipv4/ip_forward`, "sh", value)
	if got := netOutput(t, u.relay, "cat", "/proc/sys/net/ipv4/ip_forward"); got != value {
		t.Fatalf("forwarding=%s, want %s", got, value)
	}
}

func (u relayUplink) returnRoute(t *testing.T, enabled bool) {
	t.Helper()
	if enabled {
		netOutput(t, u.server, "ip", "route", "add", "10.77.0.0/24", "via", relayGatewayIP)
	} else {
		netOutput(t, u.server, "ip", "route", "del", "10.77.0.0/24")
	}
}

func (u relayUplink) snapshot(t *testing.T, results, phase string) {
	t.Helper()
	data := map[string]string{
		"target":           relayTargetIP,
		"relay_ipv4":       netOutput(t, u.relay, "ip", "-4", "addr", "show"),
		"relay_routes":     netOutput(t, u.relay, "ip", "-4", "route", "show", "table", "all"),
		"relay_rules":      netOutput(t, u.relay, "nft", "list", "ruleset"),
		"relay_forwarding": netOutput(t, u.relay, "cat", "/proc/sys/net/ipv4/ip_forward"),
		"server_ipv4":      netOutput(t, u.server, "ip", "-4", "addr", "show"),
		"server_routes":    netOutput(t, u.server, "ip", "-4", "route", "show", "table", "all"),
		"server_wg":        netOutput(t, u.server, "wg", "show", "interfaces"),
	}
	if data["server_wg"] != "" {
		t.Fatal("target unexpectedly has a WG interface")
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(results, "relay-"+phase+"-topology.json"), string(b))
}

// Use fresh sockets after mutations; persistent PKI-phase traffic was evaluated
// separately. Each failed data path must retain a working VPN-only control API.
func (u relayUplink) verify(t *testing.T, testBin string, nodes []string, configs []config.Config, results string) {
	t.Helper()
	round := func(phase string, reachable bool) {
		t.Helper()
		started := time.Now()
		var workers []*networkProcess
		for n, ns := range nodes {
			stem := filepath.Join(results, fmt.Sprintf("relay-%s-node-%d", phase, n))
			workers = append(workers, startNetworkProcess(t, ns, stem+".log", []string{
				"VPNCTL_WORKER=relay-check", "VPNCTL_UPLINK_ADDR=" + relayTargetIP,
				"VPNCTL_PKI=" + configs[n].Node.PKIDir, "VPNCTL_RELAY_REPORT=" + stem + ".json",
			}, testBin, "-test.run=^TestNetworkWorker$"))
		}
		for n, p := range workers {
			p.finish(t)
			stem := filepath.Join(results, fmt.Sprintf("relay-%s-node-%d", phase, n))
			data, err := os.ReadFile(stem + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var report relayCheckReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.ControlError != "" {
				t.Errorf("%s node %d control API failed: %s", phase, n, report.ControlError)
			}
			if len(report.Probes) != 4 {
				t.Fatalf("%s node %d missing protocol/payload probes", phase, n)
			}
			for _, p := range report.Probes {
				if !p.OK && p.FailureKind != "timeout" && p.FailureKind != "unreachable" {
					t.Errorf("%s node %d unexpected failure type: %+v", phase, n, p)
				}
				if p.OK != reachable {
					t.Errorf("%s node %d unexpected result: %+v, reachable=%t", phase, n, p, reachable)
				}
				if p.OK && p.At.Add(time.Duration(p.DurationMS*float64(time.Millisecond))).Sub(started) > 5*time.Second {
					t.Errorf("%s node %d check exceeded 5s including worker launch: %+v", phase, n, p)
				}
			}
		}
		u.snapshot(t, results, phase)
		t.Logf("relay phase=%s nodes=%d expected_reachable=%t elapsed=%v", phase, len(nodes), reachable, time.Since(started))
	}
	round("routed", true)
	for cycle := 0; cycle < 3; cycle++ {
		prefix := fmt.Sprintf("cycle-%d-", cycle)
		u.forwarding(t, false)
		round(prefix+"forwarding-off", false)
		u.forwarding(t, true)
		round(prefix+"forwarding-restored", true)
		u.returnRoute(t, false)
		round(prefix+"return-route-missing", false)
		u.returnRoute(t, true)
		round(prefix+"return-route-restored", true)
		u.nft(t, `table ip vpnctl_block {
            chain forward { type filter hook forward priority -10; policy drop; }
        }`)
		round(prefix+"firewall-drop", false)
		u.nft(t, "delete table ip vpnctl_block")
		round(prefix+"firewall-restored", true)
		netOutput(t, u.relay, "ip", "link", "set", "uplink0", "down")
		round(prefix+"uplink-down", false)
		netOutput(t, u.relay, "ip", "link", "set", "uplink0", "up")
		round(prefix+"uplink-restored", true)
	}
	// No server VPN route exists in this profile. Only the scoped relay SNAT
	// can make a reply possible. Flush namespace-local conntrack between modes
	// so an old NAT mapping cannot make a missing-rule check accidentally pass.
	u.returnRoute(t, false)
	for cycle := 0; cycle < 3; cycle++ {
		prefix := fmt.Sprintf("nat-%d-", cycle)
		u.nft(t, `table ip vpnctl_nat {
            chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                oifname "uplink0" ip saddr 10.77.0.0/24 ip daddr 198.18.0.2 counter snat to 198.18.0.1
            }
        }`)
		netOutput(t, u.relay, "conntrack", "-F")
		round(prefix+"enabled", true)
		u.nft(t, "delete table ip vpnctl_nat")
		netOutput(t, u.relay, "conntrack", "-F")
		round(prefix+"removed", false)
	}
	u.returnRoute(t, true)
	round("routed-restored", true)
}
