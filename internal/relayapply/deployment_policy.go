// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"vpnctl/internal/relaycatalog"
)

// Group by target, rather than expanding every source/prefix combination.
// At catalog capacity this has at most 32 grants, 8192 source memberships and
// 256 target prefixes. The probe port is not an application authorization ACL.
func deploymentGrants(v *relaycatalog.DeploymentView, endpoint string) []DeploymentGrant {
	paths := map[string]relaycatalog.Path{}
	for _, p := range v.Spec.Paths {
		if p.EndpointID == endpoint {
			paths[p.ID] = p
		}
	}
	grants := []DeploymentGrant{}
	for _, target := range v.Spec.Targets {
		g := DeploymentGrant{Target: target.ID, Prefixes: slices.Clone(target.Prefixes)}
		for _, b := range v.Bindings {
			if p, ok := paths[b.PathID]; ok && slices.Contains(p.TargetIDs, target.ID) {
				g.Sources = append(g.Sources, b.InnerAddress)
			}
		}
		if len(g.Sources) != 0 {
			slices.Sort(g.Sources)
			slices.Sort(g.Prefixes)
			grants = append(grants, g)
		}
	}
	slices.SortFunc(grants, func(a, b DeploymentGrant) int { return strings.Compare(a.Target, b.Target) })
	return grants
}

func validateDeploymentGrants(e DeploymentEntry) error {
	if e.PolicyVersion == 0 && len(e.Grants) == 0 {
		return nil // Legacy journal: quiesce, never silently adopt.
	}
	if e.PolicyVersion != 1 || len(e.Grants) > relaycatalog.MaxTargets || len(e.Peers) != 0 && len(e.Grants) == 0 {
		return errors.New("invalid relay forwarding policy version or grants")
	}
	sources := map[string]bool{}
	for _, p := range e.Peers {
		sources[p.Address] = true
	}
	covered := map[string]bool{}
	prefixes := []netip.Prefix{}
	last := ""
	for _, g := range e.Grants {
		if g.Target <= last || len(g.Target) > 64 || len(g.Sources) == 0 || len(g.Sources) > len(e.Peers) || len(g.Prefixes) == 0 || len(g.Prefixes) > 8 || !slices.IsSorted(g.Sources) || !slices.IsSorted(g.Prefixes) {
			return errors.New("invalid relay forwarding grant")
		}
		last = g.Target
		for i, s := range g.Sources {
			if !sources[s] || i > 0 && s == g.Sources[i-1] {
				return errors.New("invalid relay forwarding source")
			}
			covered[s] = true
		}
		for _, raw := range g.Prefixes {
			p, err := netip.ParsePrefix(raw)
			if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != raw || !p.Addr().IsGlobalUnicast() {
				return errors.New("invalid relay forwarding target prefix")
			}
			for _, old := range prefixes {
				if old.Overlaps(p) {
					return errors.New("overlapping relay forwarding targets")
				}
			}
			for source := range sources {
				ip, err := netip.ParsePrefix(source)
				if err != nil || p.Contains(ip.Addr()) {
					return errors.New("relay forwarding target overlaps peer")
				}
			}
			prefixes = append(prefixes, p)
		}
	}
	if len(covered) != len(sources) {
		return errors.New("relay peer has no forwarding grant")
	}
	return nil
}

func policyTable(e DeploymentEntry) string { return "vf" + e.Interface[2:] }

func policyAddress(raw string) any {
	p := netip.MustParsePrefix(raw)
	if p.Bits() == 32 {
		return p.Addr().String()
	}
	return object{"prefix": object{"addr": p.Addr().String(), "len": p.Bits()}}
}

// These chains only restrict the owned inner interface. Return continues into
// deployment-managed firewall chains: it cannot override their drop verdicts.
// NAT, physical interfaces, DNS and the default route remain deployment-owned.
func policyExpected(e DeploymentEntry) []object {
	table := policyTable(e)
	rows := []object{{"table": object{"family": "inet", "name": table, "comment": e.Alias}}}
	for i, g := range e.Grants {
		for _, part := range []struct {
			name   string
			values []string
		}{{"s", g.Sources}, {"t", g.Prefixes}} {
			elems := []any{}
			for _, value := range part.values {
				elems = append(elems, policyAddress(value))
			}
			set := object{"family": "inet", "table": table, "name": fmt.Sprintf("%s%d", part.name, i), "type": "ipv4_addr", "elem": elems, "comment": e.Alias}
			if part.name == "t" {
				set["flags"] = []string{"interval"}
			}
			rows = append(rows, object{"set": set})
		}
	}
	for _, hook := range []string{"input", "forward", "output"} {
		rows = append(rows, object{"chain": object{"family": "inet", "table": table, "name": hook, "type": "filter", "hook": hook, "prio": -5, "policy": "accept"}})
	}
	meta := func(key string) object { return object{"meta": object{"key": key}} }
	ip := func(key string) object { return object{"payload": object{"protocol": "ip", "field": key}} }
	match := func(left, right any) object { return object{"match": object{"op": "==", "left": left, "right": right}} }
	rule := func(chain string, expressions ...any) {
		rows = append(rows, object{"rule": object{"family": "inet", "table": table, "chain": chain, "comment": e.Alias, "expr": expressions}})
	}
	rule("input", match(meta("iif"), e.LinkIndex), object{"drop": nil})
	for i := range e.Grants {
		rule("forward", match(meta("iif"), e.LinkIndex), match(ip("saddr"), fmt.Sprintf("@s%d", i)), match(ip("daddr"), fmt.Sprintf("@t%d", i)), object{"return": nil})
		rule("forward", match(meta("oif"), e.LinkIndex), match(ip("daddr"), fmt.Sprintf("@s%d", i)), match(ip("saddr"), fmt.Sprintf("@t%d", i)), object{"match": object{"op": "in", "left": object{"ct": object{"key": "state"}}, "right": 2}}, match(object{"ct": object{"key": "direction"}}, 1), object{"return": nil})
		rule("forward", policyICMPExpressions(e, i)...)
	}
	rule("forward", match(meta("iif"), e.LinkIndex), object{"drop": nil})
	rule("forward", match(meta("oif"), e.LinkIndex), object{"drop": nil})
	for i := range e.Grants {
		rule("output", policyICMPExpressions(e, i)...)
	}
	rule("output", match(meta("oif"), e.LinkIndex), object{"drop": nil})
	return rows
}

// ICMP errors may come from an intermediate router or from this relay. Verify
// the conntrack original tuple and reply direction, not the error's outer source.
// This preserves PMTU/unreachable feedback without granting arbitrary related
// data connections or inbound application traffic.
func policyICMPExpressions(e DeploymentEntry, i int) []any {
	match := func(left, right any) object { return object{"match": object{"op": "==", "left": left, "right": right}} }
	return []any{
		match(object{"meta": object{"key": "oif"}}, e.LinkIndex),
		match(object{"payload": object{"protocol": "ip", "field": "daddr"}}, fmt.Sprintf("@s%d", i)),
		match(object{"payload": object{"protocol": "ip", "field": "protocol"}}, 1),
		match(object{"payload": object{"protocol": "icmp", "field": "type"}}, object{"set": []int{3, 11, 12}}),
		object{"match": object{"op": "in", "left": object{"ct": object{"key": "state"}}, "right": 4}},
		match(object{"ct": object{"key": "direction"}}, 1),
		match(object{"ct": object{"key": "ip saddr", "dir": "original"}}, fmt.Sprintf("@s%d", i)),
		match(object{"ct": object{"key": "ip daddr", "dir": "original"}}, fmt.Sprintf("@t%d", i)),
		object{"return": nil},
	}
}

// Object ordering is not an nft API guarantee. Rule order within each chain is
// significant; set element order is not. Reject all unexpected properties.
func canonicalPolicy(rows []object, e DeploymentEntry) (string, error) {
	objects := map[string]any{}
	rules := map[string][]any{}
	for _, row := range rows {
		if len(row) != 1 {
			return "", ErrConflict
		}
		for kind, raw := range row {
			if kind == "metainfo" {
				continue
			}
			x, ok := raw.(map[string]any)
			if !ok {
				return "", ErrConflict
			}
			delete(x, "handle")
			if kind == "table" {
				if value, ok := x["comment"]; ok && value != e.Alias {
					return "", ErrConflict
				}
				delete(x, "comment")
			}
			if kind == "rule" {
				chain, ok := x["chain"].(string)
				if !ok {
					return "", ErrConflict
				}
				if expressions, ok := x["expr"].([]any); ok {
					for _, raw := range expressions {
						expr, _ := raw.(map[string]any)
						m, _ := expr["match"].(map[string]any)
						left, _ := m["left"].(map[string]any)
						meta, _ := left["meta"].(map[string]any)
						if (meta["key"] == "iif" || meta["key"] == "oif") && leaseIndex(m["right"], e) {
							m["right"] = float64(e.LinkIndex)
						}
					}
				}
				rules[chain] = append(rules[chain], x)
				continue
			}
			if kind != "table" && kind != "set" && kind != "chain" {
				return "", ErrConflict
			}
			name, ok := x["name"].(string)
			if !ok || objects[kind+":"+name] != nil {
				return "", ErrConflict
			}
			if kind == "set" {
				elements, ok := x["elem"].([]any)
				if !ok {
					return "", ErrConflict
				}
				slices.SortFunc(elements, func(a, b any) int { return strings.Compare(deploymentHash(a), deploymentHash(b)) })
			}
			objects[kind+":"+name] = x
		}
	}
	return deploymentHash([]any{objects, rules}), nil
}

func validatePolicy(rows []object, e DeploymentEntry) error {
	// Normalize our typed construction through the same JSON data model.
	wire, _ := json.Marshal(policyExpected(e))
	var expected []object
	if json.Unmarshal(wire, &expected) != nil {
		return ErrConflict
	}
	want, err := canonicalPolicy(expected, e)
	got, readErr := canonicalPolicy(rows, e)
	if err != nil || readErr != nil || want != got {
		return ErrConflict
	}
	return nil
}

func (k deploymentKernel) policyRead(ctx context.Context, e DeploymentEntry) (bool, error) {
	rows, err := k.nftRows(ctx, "list", "tables")
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if table, ok := row["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == policyTable(e) {
			rows, err = k.nftRows(ctx, "list", "table", "inet", policyTable(e))
			if err == nil {
				err = validatePolicy(rows, e)
			}
			return true, err
		}
	}
	return false, nil
}

func (k deploymentKernel) policyCreate(ctx context.Context, e DeploymentEntry) error {
	if e.PolicyVersion == 0 {
		return nil
	}
	if exists, err := k.policyRead(ctx, e); err != nil {
		return err
	} else if exists {
		return ErrConflict
	}
	_, err := k.run(ctx, policyScript(e), "nft", "-f", "/dev/stdin")
	return err
}

func (k deploymentKernel) policyRemove(ctx context.Context, e DeploymentEntry) error {
	if e.PolicyVersion == 0 {
		return nil
	}
	exists, err := k.policyRead(ctx, e)
	if err != nil || !exists {
		return err
	}
	_, err = k.run(ctx, "", "nft", "delete", "table", "inet", policyTable(e))
	return err
}

// Use the text frontend: nft 1.0.6 JSON input silently discards set comments.
func policyScript(e DeploymentEntry) string {
	table := policyTable(e)
	var b strings.Builder
	fmt.Fprintf(&b, "create table inet %s { comment %q; }\n", table, e.Alias)
	for i, g := range e.Grants {
		sources := make([]string, len(g.Sources))
		for j, source := range g.Sources {
			sources[j] = strings.TrimSuffix(source, "/32")
		}
		fmt.Fprintf(&b, "add set inet %s s%d { type ipv4_addr; comment %q; elements = { %s }; }\n", table, i, e.Alias, strings.Join(sources, ", "))
		fmt.Fprintf(&b, "add set inet %s t%d { type ipv4_addr; flags interval; comment %q; elements = { %s }; }\n", table, i, e.Alias, strings.Join(g.Prefixes, ", "))
	}
	for _, hook := range []string{"input", "forward", "output"} {
		fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority -5; policy accept; }\n", table, hook, hook)
	}
	fmt.Fprintf(&b, "add rule inet %s input meta iif %d drop comment %q\n", table, e.LinkIndex, e.Alias)
	for i := range e.Grants {
		fmt.Fprintf(&b, "add rule inet %s forward meta iif %d ip saddr @s%d ip daddr @t%d return comment %q\n", table, e.LinkIndex, i, i, e.Alias)
		fmt.Fprintf(&b, "add rule inet %s forward meta oif %d ip daddr @s%d ip saddr @t%d ct state established ct direction reply return comment %q\n", table, e.LinkIndex, i, i, e.Alias)
		b.WriteString(policyICMPRule(e, i, "forward"))
	}
	fmt.Fprintf(&b, "add rule inet %s forward meta iif %d drop comment %q\n", table, e.LinkIndex, e.Alias)
	fmt.Fprintf(&b, "add rule inet %s forward meta oif %d drop comment %q\n", table, e.LinkIndex, e.Alias)
	for i := range e.Grants {
		b.WriteString(policyICMPRule(e, i, "output"))
	}
	fmt.Fprintf(&b, "add rule inet %s output meta oif %d drop comment %q\n", table, e.LinkIndex, e.Alias)
	return b.String()
}

func policyICMPRule(e DeploymentEntry, i int, hook string) string {
	return fmt.Sprintf("add rule inet %s %s meta oif %d ip daddr @s%d ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } ct state related ct direction reply ct original ip saddr @s%d ct original ip daddr @t%d return comment %q\n", policyTable(e), hook, e.LinkIndex, i, i, i, e.Alias)
}
