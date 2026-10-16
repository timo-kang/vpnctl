//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"strings"
	"testing"
)

type uplinkPath struct {
	ID        string `json:"id"`
	Interface string `json:"interface,omitempty"`
	Relay     int    `json:"relay"`
	Underlay  int    `json:"underlay"`
	Port      int    `json:"udp_port"`
}

var uplinkPrefixes = []string{"192.0.2", "198.51.100", "203.0.113", "198.19.0"}

// Entire rulesets are installed atomically inside the fixture-owned namespace.
// Newlines between closing braces are required by nft's file grammar.
func injectUplinkFault(t *testing.T, f *uplinkFixture, fault string) {
	t.Helper()
	switch fault {
	case "link-down":
		netOutput(t, f.robot, "ip", "link", "set", "wan0", "down")
	case "endpoint-drop":
		(relayUplink{relay: f.relays[0]}).nft(t, fmt.Sprintf(`table inet comparison_fault {
 chain input { type filter hook input priority -100; policy accept;
  ip daddr 192.0.2.11 udp dport %d counter drop
 }
}`, f.endpointPort))
	case "relay-drop":
		(relayUplink{relay: f.relays[0]}).nft(t, `table inet comparison_fault {
 chain input { type filter hook input priority -100; policy drop; }
 chain output { type filter hook output priority -100; policy drop; }
 chain forward { type filter hook forward priority -100; policy drop; }
 }`)
	case "uplink-drop":
		(relayUplink{relay: f.relays[0]}).nft(t, `table inet comparison_fault {
 chain forward { type filter hook forward priority -100; policy accept;
  ip daddr 198.18.0.2 tcp dport 9192 counter drop
 }
}`)
	case "last-endpoint-only":
		for relay, ns := range f.relays {
			var rules strings.Builder
			rules.WriteString("table inet comparison_fault {\n chain input { type filter hook input priority -100; policy accept;\n")
			for i, p := range f.paths {
				if p.Relay != relay || i == len(f.paths)-1 {
					continue
				}
				fmt.Fprintf(&rules, " ip daddr %s.%d udp dport %d counter drop\n", uplinkPrefixes[p.Underlay], 11+relay, p.Port)
			}
			rules.WriteString(" }\n}\n")
			(relayUplink{relay: ns}).nft(t, rules.String())
		}
	case "app1-last-path":
		var rules strings.Builder
		rules.WriteString("table inet comparison_fault {\n chain output { type filter hook output priority -100; policy accept;\n")
		for _, p := range f.paths[:len(f.paths)-1] {
			fmt.Fprintf(&rules, " oifname %q ip daddr 198.18.0.2 tcp dport 9192 counter drop\n", p.Interface)
		}
		rules.WriteString(" }\n}\n")
		(relayUplink{relay: f.robot}).nft(t, rules.String())
	default:
		t.Fatal("unsupported comparison fault")
	}
}

func uplinkFaultEvidence(t *testing.T, f *uplinkFixture, fault string) map[string]string {
	if fault == "link-down" {
		return map[string]string{"robot": netOutput(t, f.robot, "ip", "-j", "link", "show", "wan0")}
	}
	namespaces := map[string]string{"r0": f.relays[0]}
	if fault == "last-endpoint-only" {
		namespaces["r1"] = f.relays[1]
	}
	if fault == "app1-last-path" {
		namespaces = map[string]string{"robot": f.robot}
	}
	out := map[string]string{}
	for role, ns := range namespaces {
		out[role] = netOutput(t, ns, "nft", "-j", "list", "table", "inet", "comparison_fault")
	}
	return out
}
