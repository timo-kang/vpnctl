// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"net/netip"
	"strings"
)

// Source rules follow every candidate transport mark and precede main. Hash
// collisions are rejected by inventory checks, never treated as reservations.
func probePriority(e Entry) uint32 { return 28000 + (e.Candidate.Pin.RulePriority-20000)%4000 }
func probeRuleMatches(o object, e Entry) bool {
	if !e.ProbeRouting {
		return false
	}
	source := strings.TrimSuffix(e.Candidate.InnerAddress, "/32")
	return n(o, "priority") == probePriority(e) && (str(o, "src") == source || str(o, "src") == e.Candidate.InnerAddress) && n(o, "table") == e.Candidate.Pin.Table && n(o, "protocol") == 186 && only(o, "priority", "src", "table", "protocol")
}
func probeRouteMatches(o object, e Entry) bool {
	if !e.ProbeRouting {
		return false
	}
	if n(o, "table") != e.Candidate.Pin.Table || n(o, "protocol") != 186 || n(o, "metric") != e.Metric || str(o, "dev") != e.Candidate.Pin.WGInterface || str(o, "prefsrc") != strings.TrimSuffix(e.Candidate.InnerAddress, "/32") || str(o, "type") != "" && str(o, "type") != "unicast" && str(o, "type") != "1" || !only(o, "type", "dst", "table", "protocol", "metric", "scope", "flags", "dev", "prefsrc") {
		return false
	}
	for _, p := range prefixes(e) {
		if str(o, "dst") == p || str(o, "dst") == strings.TrimSuffix(p, "/32") {
			return true
		}
	}
	return false
}
func probeRouteArgs(e Entry, verb, prefix string) []string {
	return []string{"-4", "route", verb, prefix, "dev", e.Candidate.Pin.WGInterface, "src", strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "table", decimal(e.Candidate.Pin.Table), "proto", protocol, "metric", decimal(e.Metric)}
}
func probeRuleArgs(e Entry, verb string) []string {
	return []string{"-4", "rule", verb, "priority", decimal(probePriority(e)), "from", e.Candidate.InnerAddress, "lookup", decimal(e.Candidate.Pin.Table), "protocol", protocol}
}

func probeSourceMayMatch(o object, e Entry) bool {
	if inverted, _ := o["not"].(bool); inverted {
		return true
	}
	source := str(o, "src")
	if source == "" || source == "all" {
		return true
	}
	if !strings.Contains(source, "/") {
		source += "/32"
	}
	p, err := netip.ParsePrefix(source)
	if err != nil {
		return true
	}
	inner, err := netip.ParsePrefix(e.Candidate.InnerAddress)
	return err != nil || p.Contains(inner.Addr())
}
