// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func validText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validatePublicKey(s string) error {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s || PublicKeyID(s) != s {
		return invalid("public key must be canonical base64 X25519")
	}
	pub, e := ecdh.X25519().NewPublicKey(b)
	if e != nil {
		return invalid("invalid X25519 public key")
	}
	var seed [32]byte
	seed[0] = 1
	private, _ := ecdh.X25519().NewPrivateKey(seed[:])
	if _, e = private.ECDH(pub); e != nil {
		return invalid("low-order X25519 public key")
	}
	return nil
}

// PublicKeyID identifies equivalent X25519 u-coordinate encodings in legacy
// registrations. New catalog keys must already use this canonical encoding.
func PublicKeyID(s string) string {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return s
	}
	b[31] &= 127
	// p = 2^255 - 19; the masked value can exceed p by at most 18.
	above := b[0] >= 237
	for i := 1; i < 31; i++ {
		above = above && b[i] == 255
	}
	above = above && b[31] == 127
	if above {
		low := b[0] - 237
		clear(b)
		b[0] = low
	}
	return base64.StdEncoding.EncodeToString(b)
}

var forbiddenIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/3"),
}

func unicastIPv4(a netip.Addr) bool {
	if !a.Is4() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range forbiddenIPv4 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
func prefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != s || p.Bits() == 0 || !unicastIPv4(p.Addr()) || !unicastIPv4(last(p)) {
		return netip.Prefix{}, invalid("noncanonical/non-unicast IPv4 prefix %q", s)
	}
	for _, blocked := range forbiddenIPv4 {
		if p.Overlaps(blocked) {
			return netip.Prefix{}, invalid("prefix includes non-unicast addresses")
		}
	}
	return p, nil
}
func last(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= uint32((uint64(1) << uint(32-p.Bits())) - 1)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
func host(s string) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || !unicastIPv4(a) || a.String() != s {
		return netip.Addr{}, invalid("noncanonical/non-unicast IPv4 address %q", s)
	}
	return a, nil
}
func ValidateSpec(s Spec, env Environment) error {
	if s.SchemaVersion != SchemaVersion {
		return invalid("unsupported schema_version %d", s.SchemaVersion)
	}
	pool, e := prefix(s.PoolCIDR)
	if e != nil {
		return e
	}
	if pool.Bits() < 16 || pool.Bits() > 30 {
		return invalid("pool must be /16../30")
	}
	var legacy netip.Prefix
	if env.VPNCIDR != "" {
		legacy, e = prefix(env.VPNCIDR)
		if e != nil {
			return e
		}
		if pool.Overlaps(legacy) {
			return invalid("path pool overlaps legacy VPN CIDR")
		}
	}
	if len(s.ReservedIPs) > 64 || len(s.Relays) > MaxRelays || len(s.Targets) > MaxTargets || len(s.Paths) > MaxNodes*MaxPathsPerNode {
		return fmt.Errorf("%w: descriptor limit", ErrCapacity)
	}
	reserved := map[string]bool{}
	for _, v := range s.ReservedIPs {
		a, e := host(v)
		if e != nil {
			return e
		}
		if !pool.Contains(a) || a == pool.Addr() || a == last(pool) || reserved[v] {
			return invalid("invalid/duplicate pool reservation %q", v)
		}
		reserved[v] = true
	}
	relays := map[string]Relay{}
	keys := map[string]bool{}
	endpoints := map[string]bool{}
	for _, r := range s.Relays {
		if !validID(r.ID) || !validText(r.Site, 128) || r.KeyGeneration == 0 || len(r.Endpoints) == 0 || len(r.Endpoints) > 8 {
			return invalid("invalid relay %q", r.ID)
		}
		if _, ok := relays[r.ID]; ok {
			return invalid("duplicate relay %q", r.ID)
		}
		if e := ValidatePublicKey(r.PublicKey); e != nil {
			return e
		}
		if keys[r.PublicKey] || env.ReservedKeys[r.PublicKey] {
			return invalid("relay key is already reserved")
		}
		keys[r.PublicKey] = true
		ids := map[string]bool{}
		for _, ep := range r.Endpoints {
			ap, e := netip.ParseAddrPort(ep.Address)
			if !validID(ep.ID) || ids[ep.ID] || e != nil || !unicastIPv4(ap.Addr()) || ap.Port() == 0 || ap.String() != ep.Address {
				return invalid("invalid/duplicate relay endpoint")
			}
			if pool.Contains(ap.Addr()) || legacy.IsValid() && legacy.Contains(ap.Addr()) {
				return invalid("relay endpoint is inside a VPN pool")
			}
			if endpoints[ep.Address] {
				return invalid("endpoint belongs to multiple relays")
			}
			endpoints[ep.Address] = true
			ids[ep.ID] = true
		}
		relays[r.ID] = r
	}
	targets := map[string]Target{}
	allPrefixes := []netip.Prefix{}
	for _, t := range s.Targets {
		if !validID(t.ID) || t.Protocol != "tcp" || t.Port == 0 || len(t.Prefixes) == 0 || len(t.Prefixes) > 8 {
			return invalid("invalid target %q (v1 supports tcp)", t.ID)
		}
		if _, ok := targets[t.ID]; ok {
			return invalid("duplicate target")
		}
		probe, e := host(t.ProbeAddress)
		if e != nil {
			return e
		}
		contained := false
		for _, v := range t.Prefixes {
			p, e := prefix(v)
			if e != nil {
				return e
			}
			if p.Overlaps(pool) || legacy.IsValid() && p.Overlaps(legacy) {
				return invalid("target overlaps a VPN pool")
			}
			for _, old := range allPrefixes {
				if old.Overlaps(p) {
					return invalid("target prefixes overlap")
				}
			}
			for ep := range endpoints {
				ap, _ := netip.ParseAddrPort(ep)
				if p.Contains(ap.Addr()) {
					return invalid("target includes relay endpoint")
				}
			}
			allPrefixes = append(allPrefixes, p)
			contained = contained || p.Contains(probe)
		}
		if !contained {
			return invalid("target probe address is outside allowed prefixes")
		}
		targets[t.ID] = t
	}
	paths := map[string]bool{}
	counts := map[string]int{}
	underlays := map[string]map[string]bool{}
	tuples := map[string]bool{}
	for _, p := range s.Paths {
		if !validID(p.ID) || !validID(p.UnderlayID) || p.NodeID == "" || !env.Nodes[p.NodeID] || p.Priority < 0 || p.Priority > 65535 || p.Cost < 0 || p.Cost > 65535 {
			return invalid("invalid path/node %q", p.ID)
		}
		if paths[p.ID] {
			return invalid("duplicate path ID")
		}
		paths[p.ID] = true
		counts[p.NodeID]++
		if counts[p.NodeID] > MaxPathsPerNode || len(counts) > MaxNodes {
			return fmt.Errorf("%w: node/path limit", ErrCapacity)
		}
		if underlays[p.NodeID] == nil {
			underlays[p.NodeID] = map[string]bool{}
		}
		underlays[p.NodeID][p.UnderlayID] = true
		if len(underlays[p.NodeID]) > 4 {
			return fmt.Errorf("%w: underlay limit", ErrCapacity)
		}
		r, ok := relays[p.RelayID]
		if !ok {
			return invalid("path references unknown relay")
		}
		found := false
		for _, ep := range r.Endpoints {
			found = found || ep.ID == p.EndpointID
		}
		if !found {
			return invalid("path references unknown endpoint")
		}
		// A candidate denotes one relay/underlay pair; target subsets belong to it.
		tuple := p.NodeID + "\x00" + p.RelayID + "\x00" + p.UnderlayID
		if tuples[tuple] {
			return invalid("duplicate relay/underlay candidate")
		}
		tuples[tuple] = true
		if len(p.TargetIDs) == 0 || len(p.TargetIDs) > 8 {
			return invalid("path requires 1..8 targets")
		}
		used := map[string]bool{}
		for _, id := range p.TargetIDs {
			if _, ok := targets[id]; !ok || used[id] {
				return invalid("invalid/duplicate path target")
			}
			used[id] = true
		}
	}
	return nil
}
func validateEnvelope(id string, generation uint64, issued, expires time.Time) error {
	b, e := hex.DecodeString(id)
	if e != nil || len(b) != 16 || hex.EncodeToString(b) != id || generation == 0 || generation == ^uint64(0) {
		return invalid("invalid controller identity/generation")
	}
	lifetime := expires.Sub(issued)
	if issued.IsZero() || lifetime < time.Minute || lifetime > 24*time.Hour {
		return invalid("invalid catalog validity window")
	}
	return nil
}
func (s *State) Validate(env Environment) error {
	if s == nil {
		return nil
	}
	if e := validateEnvelope(s.ControllerID, s.Generation, s.IssuedAt, s.ExpiresAt); e != nil {
		return e
	}
	if e := ValidateSpec(s.Spec, env); e != nil {
		return e
	}
	if e := s.validateRecipients(env); e != nil {
		return e
	}
	if len(s.RetiredPathIDs)+len(s.Spec.Paths) > MaxPathIDs || len(s.RetiredRelayIDs)+len(s.Spec.Relays) > MaxRelayIDs || len(s.Bindings) > MaxPathIDs {
		return fmt.Errorf("%w: lifetime ledger limit", ErrCapacity)
	}
	retired := map[string]bool{}
	for _, id := range s.RetiredPathIDs {
		if !validID(id) || retired[id] {
			return invalid("invalid retired path ledger")
		}
		retired[id] = true
	}
	paths := map[string]Path{}
	for _, p := range s.Spec.Paths {
		if retired[p.ID] {
			return invalid("retired path reused")
		}
		paths[p.ID] = p
	}
	relays := map[string]bool{}
	for _, id := range s.RetiredRelayIDs {
		if !validID(id) || relays[id] {
			return invalid("invalid retired relay ledger")
		}
		relays[id] = true
	}
	keys := map[string]bool{}
	if len(s.ReservedRelayKeys) > MaxRelayKeys {
		return fmt.Errorf("%w: relay key ledger", ErrCapacity)
	}
	for _, k := range s.ReservedRelayKeys {
		if e := ValidatePublicKey(k); e != nil {
			return e
		}
		if keys[k] || env.ReservedKeys[k] {
			return invalid("duplicate/reserved relay key ledger")
		}
		keys[k] = true
	}
	for _, r := range s.Spec.Relays {
		if relays[r.ID] {
			return invalid("retired relay reused")
		}
		if !slices.Contains(s.ReservedRelayKeys, r.PublicKey) {
			return invalid("relay key ledger missing active key")
		}
	}
	pool, _ := prefix(s.Spec.PoolCIDR)
	ips := map[string]bool{}
	bindings := map[string]bool{}
	for _, v := range s.Spec.ReservedIPs {
		ips[v+"/32"] = true
	}
	for _, b := range s.Bindings {
		if !validID(b.PathID) || b.NodeID == "" || !validText(b.NodeID, 256) || b.CreatedAt.IsZero() || bindings[b.PathID] {
			return invalid("invalid binding identity")
		}
		if e := ValidatePublicKey(b.PublicKey); e != nil {
			return e
		}
		if keys[b.PublicKey] || env.ReservedKeys[b.PublicKey] {
			return invalid("binding key is already reserved")
		}
		keys[b.PublicKey] = true
		p, e := netip.ParsePrefix(b.InnerAddress)
		if e != nil || !p.Addr().Is4() || p.Bits() != 32 || p.String() != b.InnerAddress || !pool.Contains(p.Addr()) || p.Addr() == pool.Addr() || p.Addr() == last(pool) || ips[b.InnerAddress] {
			return invalid("invalid/duplicate binding lease")
		}
		ips[b.InnerAddress] = true
		bindings[b.PathID] = true
		digest, e := hex.DecodeString(b.DefinitionHash)
		if e != nil || len(digest) != 32 || strings.ToLower(b.DefinitionHash) != b.DefinitionHash {
			return invalid("invalid binding definition hash")
		}
		if b.RetiredAt.IsZero() {
			p, ok := paths[b.PathID]
			if !ok || p.NodeID != b.NodeID || definitionHash(s.Spec, p) != b.DefinitionHash {
				return invalid("binding does not match its approved path")
			}
		} else if !retired[b.PathID] || b.RetiredAt.Before(b.CreatedAt) {
			return invalid("invalid retired binding")
		}
	}
	return nil
}
func (v View) Validate(nodeID string, now time.Time) error {
	if v.NodeID != nodeID || nodeID == "" {
		return invalid("catalog node identity mismatch")
	}
	for _, p := range v.Spec.Paths {
		if p.NodeID != nodeID {
			return invalid("foreign path in node view")
		}
	}
	for _, b := range v.Bindings {
		if b.NodeID != nodeID || !b.RetiredAt.IsZero() {
			return invalid("foreign/retired binding in node view")
		}
	}
	state := State{ControllerID: v.ControllerID, Generation: v.Generation, IssuedAt: v.IssuedAt, ExpiresAt: v.ExpiresAt, Spec: v.Spec, Bindings: v.Bindings}
	for _, r := range v.Spec.Relays {
		state.ReservedRelayKeys = append(state.ReservedRelayKeys, r.PublicKey)
	}
	if e := state.Validate(Environment{Nodes: map[string]bool{nodeID: true}}); e != nil {
		return e
	}
	if v.IssuedAt.After(now.Add(30 * time.Second)) {
		return invalid("catalog issued in the future")
	}
	if !now.Before(v.ExpiresAt) {
		return ErrExpired
	}
	return nil
}
