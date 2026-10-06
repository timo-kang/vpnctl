// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

type targetKernel struct{ kernel }

func guardRouteMatches(o object, e TargetGuard) bool {
	return n(o, "table") == e.Table && n(o, "metric") == e.Metric && n(o, "protocol") == 186 && (str(o, "type") == "unreachable" || str(o, "type") == "7") && str(o, "dst") == "default" && only(o, "type", "dst", "table", "protocol", "metric", "scope", "flags")
}
func guardRulePrefix(o object, e TargetGuard) string {
	if n(o, "priority") != e.Priority || n(o, "table") != e.Table || n(o, "protocol") != 186 || str(o, "src") != "all" || str(o, "iif") != "lo" || !only(o, "priority", "src", "dst", "iif", "fwmark", "fwmask", "table", "protocol") {
		return ""
	}
	mark, ok := num(o["fwmark"])
	if !ok || mark != 0 {
		return ""
	}
	if v, exists := o["fwmask"]; exists {
		mask, ok := num(v)
		if !ok || mask != ^uint32(0) {
			return ""
		}
	}
	for _, p := range e.Prefixes {
		if str(o, "dst") == p || str(o, "dst") == strings.TrimSuffix(p, "/32") {
			return p
		}
	}
	return ""
}
func guardRouteArgs(e TargetGuard, verb string) []string {
	return []string{"-4", "route", verb, "unreachable", "default", "table", decimal(e.Table), "proto", protocol, "metric", decimal(e.Metric)}
}
func guardRuleArgs(e TargetGuard, verb, prefix string) []string {
	return []string{"-4", "rule", verb, "priority", decimal(e.Priority), "from", "all", "to", prefix, "iif", "lo", "fwmark", "0/0xffffffff", "lookup", decimal(e.Table), "protocol", protocol}
}
func routePrefix(raw string) (netip.Prefix, error) {
	if raw == "default" || raw == "all" || raw == "" {
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	if !strings.Contains(raw, "/") {
		raw += "/32"
	}
	return netip.ParsePrefix(raw)
}
func targetDestinationOverlaps(o object, e TargetGuard) bool {
	if inverted, _ := o["not"].(bool); inverted {
		return true
	}
	p, err := routePrefix(str(o, "dst"))
	if err != nil {
		return true
	}
	for _, s := range e.Prefixes {
		q, err := netip.ParsePrefix(s)
		if err != nil || p.Overlaps(q) {
			return true
		}
	}
	return false
}
func targetGuardOwnership(s snapshot, e TargetGuard, fresh bool) (bool, map[string]bool, error) {
	route := false
	apps := map[string]bool{}
	rules := map[string]bool{}
	for _, o := range s.routes {
		if n(o, "table") != e.Table {
			continue
		}
		if fresh {
			return false, nil, ErrConflict
		}
		if guardRouteMatches(o, e) && !route {
			route = true
			continue
		}
		prefix := applicationRoutePrefix(o, e, e.Active)
		if prefix == "" {
			prefix = applicationRoutePrefix(o, e, e.Pending)
		}
		if prefix == "" || apps[prefix] {
			return false, nil, ErrConflict
		}
		apps[prefix] = true
	}
	for _, o := range s.rules {
		if n(o, "table") != e.Table && n(o, "priority") != e.Priority {
			continue
		}
		prefix := guardRulePrefix(o, e)
		if fresh || prefix == "" || rules[prefix] {
			return false, nil, ErrConflict
		}
		rules[prefix] = true
	}
	return route, rules, nil
}
func targetGuardConflicts(s snapshot, e TargetGuard, entries []Entry, fresh bool) (bool, error) {
	route, rules, err := targetGuardOwnership(s, e, fresh)
	if err != nil {
		return false, err
	}
	for _, o := range s.routes {
		if n(o, "table") == e.Table {
			continue
		}
		// The machine's default routes remain intact, but a more specific foreign
		// destination (including a local address) must not be silently captured.
		if str(o, "dst") == "default" {
			continue
		}
		if !targetDestinationOverlaps(o, e) {
			continue
		}
		owned := false
		for _, entry := range entries {
			owned = owned || candidateProbeOwned(entry, e) && probeRouteMatches(o, entry)
		}
		if !owned {
			return false, ErrConflict
		}
	}
	for _, o := range s.rules {
		if guardRulePrefix(o, e) != "" && !fresh {
			continue
		}
		local := n(o, "priority") == 0 && n(o, "table") == 255 && str(o, "src") == "all" && only(o, "priority", "src", "table", "protocol")
		if local || n(o, "priority") >= e.Priority {
			continue
		}
		if !markMatch(o, 0) || !targetDestinationOverlaps(o, e) {
			continue
		}
		// Explicit-source candidate probes intentionally bypass app quarantine.
		// No arbitrary source-, UID-, interface- or port-specific rule is adopted.
		probe := false
		for _, entry := range entries {
			probe = probe || candidateProbeOwned(entry, e) && (e.ApplicationVersion == 0 || entry.ProbeScope == 1) && probeRuleMatches(o, entry)
		}
		if !probe {
			return false, ErrConflict
		}
	}
	return route && len(rules) == len(e.Prefixes), nil
}

// Device-bound probe rules remain isolated from ordinary applications while an
// owned candidate is being prepared/removed. Their presence must not quarantine
// an independent target. This exemption grants no candidate readiness or lease.
func candidateProbeOwned(entry Entry, guard TargetGuard) bool {
	return entry.Phase == "prepared" || guard.ApplicationVersion == 1 && entry.ProbeScope == 1 && entry.ProbeRouting && entry.LeaseVersion == 3
}
func (k targetKernel) Check(ctx context.Context, e TargetGuard, entries []Entry, fresh bool) (bool, error) {
	s, err := k.snapshot(ctx)
	if err != nil {
		return false, err
	}
	return targetGuardConflicts(s, e, entries, fresh)
}
func (k targetKernel) Ensure(ctx context.Context, e TargetGuard, entries []Entry) error {
	// Every mutation rereads ownership; ip add is exclusive. Never replace or
	// flush a table that an external manager may have changed between calls.
	for _, prefix := range append([]string{""}, e.Prefixes...) {
		s, err := k.snapshot(ctx)
		if err != nil {
			return err
		}
		if _, err = targetGuardConflicts(s, e, entries, false); err != nil {
			return err
		}
		route, rules, err := targetGuardOwnership(s, e, false)
		if err != nil {
			return err
		}
		if prefix == "" {
			if route {
				continue
			}
			if len(rules) != 0 {
				return errors.New("target guard route disappeared beneath installed rules")
			}
			if _, err = k.run(ctx, "", "ip", guardRouteArgs(e, "add")...); err != nil {
				return err
			}
		} else {
			if !route {
				return errors.New("target guard route missing")
			}
			if rules[prefix] {
				continue
			}
			if _, err = k.run(ctx, "", "ip", guardRuleArgs(e, "add", prefix)...); err != nil {
				return err
			}
		}
	}
	return nil
}
func (k targetKernel) Remove(ctx context.Context, e TargetGuard) error {
	if e.Active != nil || e.Pending != nil {
		if err := k.SetRoutes(ctx, e, nil, nil); err != nil {
			return err
		}
	}
	for _, prefix := range append(append([]string{}, e.Prefixes...), "") {
		s, err := k.snapshot(ctx)
		if err != nil {
			return err
		}
		route, rules, err := targetGuardOwnership(s, e, false)
		if err != nil {
			return err
		}
		if prefix != "" {
			if !rules[prefix] {
				continue
			}
			if _, err = k.run(ctx, "", "ip", guardRuleArgs(e, "del", prefix)...); err != nil {
				return err
			}
		} else if route {
			if len(rules) != 0 {
				return ErrConflict
			}
			if _, err = k.run(ctx, "", "ip", guardRouteArgs(e, "del")...); err != nil {
				return err
			}
		}
	}
	s, err := k.snapshot(ctx)
	if err != nil {
		return err
	}
	route, rules, err := targetGuardOwnership(s, e, false)
	if err != nil {
		return err
	}
	if route || len(rules) != 0 {
		return ErrRecovery
	}
	return nil
}
