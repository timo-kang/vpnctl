// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

func Build(ctx context.Context, node, controller string, cache relaycache.Report, underlays []Underlay, collector Collector) (Plan, error) {
	now := time.Now().UTC()
	out := Plan{SchemaVersion: 1, NodeID: node, ControllerID: cache.ControllerID, Generation: cache.ObservedGeneration, ObservedAt: now, ValidUntil: now, CacheValidity: cache.Validity, State: "blocked", UplinkHealth: "unknown", Inventory: []Inventory{}, Paths: []Candidate{}}
	if e := ValidateUnderlays(underlays); e != nil {
		return out, e
	}
	if node == "" || cache.NodeID != node || controller != "" && controller != cache.ControllerID {
		out.Reason = "cache_identity_mismatch"
		return out, nil
	}
	v := cache.Catalog
	if v == nil {
		out.Reason = "cache_" + cache.Validity
		return out, nil
	}
	if len(v.Spec.Paths) > relaycatalog.MaxPathsPerNode || len(cache.Paths) > relaycatalog.MaxPathsPerNode || v.Validate(node, v.IssuedAt) != nil || v.ControllerID != cache.ControllerID || v.Generation != cache.ObservedGeneration {
		out.Reason = "catalog_invalid"
		return out, nil
	}
	statuses := map[string]relaycache.PathStatus{}
	for _, s := range cache.Paths {
		if _, ok := statuses[s.PathID]; ok {
			out.Reason = "cache_paths_invalid"
			return out, nil
		}
		statuses[s.PathID] = s
	}
	relays, targets, bindings := map[string]relaycatalog.Relay{}, map[string]relaycatalog.Target{}, map[string]relaycatalog.Binding{}
	for _, r := range v.Spec.Relays {
		relays[r.ID] = r
	}
	for _, t := range v.Spec.Targets {
		targets[t.ID] = t
	}
	for _, b := range v.Bindings {
		bindings[b.PathID] = b
	}
	global := ""
	switch {
	case cache.Validity != "valid":
		global = "cache_" + cache.Validity
	case cache.BlockedReason != "":
		global = "cache_" + cache.BlockedReason
	case cache.Refresh.Result == "in_progress":
		global = "cache_refresh_in_progress"
	case v.Validate(node, now) != nil:
		global = "cache_expired_or_clock_skew"
	}
	for _, p := range v.Spec.Paths {
		r := relays[p.RelayID]
		ep := ""
		for _, e := range r.Endpoints {
			if e.ID == p.EndpointID {
				ep = e.Address
			}
		}
		candidate := Candidate{PathID: p.ID, RelayID: p.RelayID, UnderlayID: p.UnderlayID, Endpoint: ep, RelayPublicKey: r.PublicKey, RelayKeyGeneration: r.KeyGeneration, Priority: p.Priority, Cost: p.Cost, State: "excluded", Targets: []relaycatalog.Target{}}
		for _, id := range p.TargetIDs {
			candidate.Targets = append(candidate.Targets, targets[id])
		}
		s, found := statuses[p.ID]
		b, bound := bindings[p.ID]
		switch {
		case global != "":
			candidate.Reason = global
		case p.Disabled:
			candidate.Reason = "disabled"
		case p.Drain:
			candidate.Reason = "draining"
		case !found || s.State != "bound" || !bound || b.PublicKey != s.PublicKey || b.InnerAddress != s.InnerAddress:
			candidate.Reason = "binding_unavailable"
		case !cache.UsableCache:
			candidate.Reason = "cache_unusable"
		default:
			candidate.State = "pending"
			candidate.PublicKey, candidate.InnerAddress = b.PublicKey, b.InnerAddress
		}
		out.Paths = append(out.Paths, candidate)
	}
	if global != "" {
		out.Reason = global
		return out, nil
	}
	if collector == nil {
		collector = LinuxCollector{}
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	// Serial collection bounds both process count (one at a time) and goroutines.
	// Only approved, bound, enabled paths can trigger endpoint route lookups.
	for _, u := range underlays {
		endpoints := []string{}
		for _, p := range out.Paths {
			if p.State == "pending" && p.UnderlayID == u.ID && !slices.Contains(endpoints, p.Endpoint) {
				endpoints = append(endpoints, p.Endpoint)
			}
		}
		inv := Inventory{Underlay: u, Check: unknown("no_approved_path"), Addresses: []string{}, Routes: []Route{}, DNS: unknown("not_collected"), Modem: unknown("not_collected")}
		if len(endpoints) > 0 {
			if ctx.Err() != nil {
				inv.Check = unknown("collection_deadline")
			} else {
				inv = collector.Collect(ctx, u, endpoints)
			}
		}
		out.Inventory = append(out.Inventory, inv)
	}
	now = time.Now().UTC()
	out.ObservedAt = now
	out.ValidUntil = now.Add(MaxAge)
	if v.ExpiresAt.Before(out.ValidUntil) {
		out.ValidUntil = v.ExpiresAt
	}
	eligible, uncertain, unavailable, unprepared := 0, 0, 0, 0
	for i := range out.Paths {
		p := &out.Paths[i]
		if p.State != "pending" {
			if p.Reason != "disabled" && p.Reason != "draining" {
				unprepared++
			}
			continue
		}
		p.State = "excluded"
		if ctx.Err() != nil || !now.Before(v.ExpiresAt) {
			p.Reason = "plan_expired_or_deadline"
			uncertain++
			continue
		}
		var inv *Inventory
		for j, u := range underlays {
			if u.ID == p.UnderlayID {
				inv = &out.Inventory[j]
				break
			}
		}
		if inv == nil {
			p.Reason = "underlay_unmapped"
			uncertain++
			continue
		}
		if inv.ID != p.UnderlayID || inv.Underlay != underlays[indexUnderlay(underlays, p.UnderlayID)] || inv.ObservedAt.IsZero() || inv.ObservedAt.After(now) || now.Sub(inv.ObservedAt) > MaxAge || len(inv.Addresses) > MaxAddresses || len(inv.Routes) > relaycatalog.MaxPathsPerNode {
			p.Reason = "inventory_invalid_or_stale"
			uncertain++
			continue
		}
		expires := inv.ObservedAt.Add(MaxAge)
		if expires.Before(out.ValidUntil) {
			out.ValidUntil = expires
		}
		if inv.State == "down" {
			p.Reason = inv.Reason
			unavailable++
			continue
		}
		if inv.State != "up" {
			p.Reason = inv.Reason
			if p.Reason == "" {
				p.Reason = "inventory_unknown"
			}
			uncertain++
			continue
		}
		if inv.Present == nil || !*inv.Present || inv.AdminUp == nil || !*inv.AdminUp || inv.Carrier == nil || !*inv.Carrier || inv.IfIndex <= 0 {
			p.Reason = "inventory_inconsistent"
			uncertain++
			continue
		}
		var route *Route
		for j := range inv.Routes {
			if inv.Routes[j].Endpoint == p.Endpoint {
				if route != nil {
					route = nil
					break
				}
				route = &inv.Routes[j]
			}
		}
		if route == nil {
			p.Reason = "route_missing_or_ambiguous"
			uncertain++
			continue
		}
		if route.State == "down" {
			p.Reason = route.Reason
			unavailable++
			continue
		}
		if route.State != "up" || !usableIPv4(route.Source) || !slices.Contains(inv.Addresses, route.Source) || inv.SourceIPv4 != "" && route.Source != inv.SourceIPv4 || route.Gateway != "" && !usableIPv4(route.Gateway) {
			p.Reason = "route_unknown_or_invalid"
			uncertain++
			continue
		}
		if inv.SourceIPv4 == "" && len(inv.Addresses) != 1 {
			p.Reason = "source_ambiguous"
			uncertain++
			continue
		}
		p.State = "eligible"
		p.Pin = pinProposal(out.ControllerID, node, *p, *inv, *route, i)
		eligible++
	}
	// Proposed resources may collide; fail closed before handing anything off.
	for i := range out.Paths {
		for j := 0; j < i; j++ {
			a, b := out.Paths[i].Pin, out.Paths[j].Pin
			if a != nil && b != nil && (a.WGInterface == b.WGInterface || a.FWMark == b.FWMark || a.Table == b.Table || a.RulePriority == b.RulePriority) {
				out.Reason = "proposed_resource_collision"
				for k := range out.Paths {
					if out.Paths[k].Pin != nil {
						out.Paths[k].State = "excluded"
						out.Paths[k].Reason = out.Reason
						out.Paths[k].Pin = nil
					}
				}
				return out, nil
			}
		}
	}
	switch {
	case eligible > 0:
		out.State = "eligible"
	case uncertain > 0:
		out.State = "unknown"
		out.Reason = "candidate_inventory_incomplete"
	case unprepared > 0:
		out.Reason = "candidate_preparation_incomplete"
	case unavailable > 0:
		out.State = "no_uplink"
		out.Reason = "approved_underlays_unavailable"
	default:
		out.Reason = "no_prepared_candidates"
	}
	return out, nil
}
func indexUnderlay(v []Underlay, id string) int {
	for i, u := range v {
		if u.ID == id {
			return i
		}
	}
	return -1
}
func pinProposal(controller, node string, p Candidate, inv Inventory, r Route, slot int) *PinInput {
	h := sha256.Sum256([]byte(controller + "\x00" + node + "\x00" + p.PathID + "\x00" + p.PublicKey))
	scope := sha256.Sum256([]byte(controller + "\x00" + node))
	ap, _ := netip.ParseAddrPort(p.Endpoint)
	return &PinInput{Owner: hex.EncodeToString(h[:]), WGInterface: "vr" + hex.EncodeToString(h[:6]), FWMark: 0x76000000 | binary.BigEndian.Uint32(scope[8:12])&0xfffff8 | uint32(slot), Table: 100000 + 8*uint32(binary.BigEndian.Uint16(scope[12:14])) + uint32(slot), RulePriority: 20000 + 8*(uint32(binary.BigEndian.Uint16(scope[14:16]))%1000) + uint32(slot), EndpointPrefix: fmt.Sprintf("%s/32", ap.Addr()), Interface: inv.Interface, IfIndex: inv.IfIndex, Source: r.Source, Gateway: r.Gateway, TerminalUnreachable: true, RequiresOwnershipCheck: true}
}
