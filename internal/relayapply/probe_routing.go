// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"fmt"
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
	keys := []string{"priority", "src", "table", "protocol"}
	if e.ProbeScope == 1 {
		if str(o, "oif") != e.Candidate.Pin.WGInterface {
			return false
		}
		keys = append(keys, "oif")
		if detached, ok := o["oif_detached"]; ok {
			if e.Phase != "releasing" || detached != nil {
				return false
			}
			keys = append(keys, "oif_detached")
		}
	}
	return n(o, "priority") == probePriority(e) && (str(o, "src") == source || str(o, "src") == e.Candidate.InnerAddress) && n(o, "table") == e.Candidate.Pin.Table && n(o, "protocol") == 186 && only(o, keys...)
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
	args := []string{"-4", "rule", verb, "priority", decimal(probePriority(e)), "from", e.Candidate.InnerAddress, "lookup", decimal(e.Candidate.Pin.Table), "protocol", protocol}
	if e.ProbeScope == 1 {
		args = append(args, "oif", e.Candidate.Pin.WGInterface)
	}
	return args
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

// Device-bound probe rules are intentionally invisible to unbound flows and
// Linux's initial reverse-path lookup. Require a deployment-provisioned setting;
// never change namespace-wide settings or another manager's interfaces here.
func (k kernel) checkProbeEnvironment(ctx context.Context, e Entry, fresh bool) error {
	if e.ProbeScope != 1 {
		return nil
	}
	iface := e.Candidate.Pin.WGInterface
	if fresh {
		iface = "default"
	}
	for _, name := range []string{"all", iface} {
		path := "/proc/sys/net/ipv4/conf/" + name + "/rp_filter"
		value, err := k.run(ctx, "", "cat", path)
		if err != nil || strings.TrimSpace(string(value)) != "0" {
			return fmt.Errorf("application candidates require deployment rp_filter=0 at %s: %w", path, ErrConflict)
		}
	}
	return nil
}
