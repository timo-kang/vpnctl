// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func testKey(label string) string {
	seed := sha256.Sum256([]byte(label))
	k, _ := ecdh.X25519().NewPrivateKey(seed[:])
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func testSpec() Spec {
	return Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/29", ReservedIPs: []string{"10.78.0.1"}, Relays: []Relay{
		{ID: "ra", PublicKey: testKey("ra"), KeyGeneration: 1, Endpoints: []Endpoint{{ID: "e", Address: "192.0.2.11:51820"}}},
		{ID: "rb", PublicKey: testKey("rb"), KeyGeneration: 1, Endpoints: []Endpoint{{ID: "e", Address: "198.51.100.12:51820"}}},
	}, Targets: []Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Protocol: "tcp", Port: 443}}, Paths: []Path{
		{ID: "a-primary", NodeID: "a", RelayID: "ra", EndpointID: "e", UnderlayID: "wifi", TargetIDs: []string{"app"}},
		{ID: "a-backup", NodeID: "a", RelayID: "rb", EndpointID: "e", UnderlayID: "lan", TargetIDs: []string{"app"}},
		{ID: "b-primary", NodeID: "b", RelayID: "ra", EndpointID: "e", UnderlayID: "wifi", TargetIDs: []string{"app"}},
	}}
}
func testEnv() Environment {
	return Environment{VPNCIDR: "10.7.0.0/24", Nodes: map[string]bool{"a": true, "b": true}, ReservedKeys: map[string]bool{testKey("legacy"): true}}
}
func newCatalog(t *testing.T) (*State, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	s, e := Apply(nil, Update{TTLSeconds: 3600, Spec: testSpec()}, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	return s, now
}
func bindRequest(s *State, node, path, key string) BindRequest {
	return BindRequest{SchemaVersion: 1, ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, NodeID: node, PathID: path, PublicKey: testKey(key)}
}
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestBindingOwnershipCASAndIsolation(t *testing.T) {
	s, now := newCatalog(t)
	original := encode(s)
	req := bindRequest(s, "a", "a-primary", "path-a")
	bound, e := Bind(s, req, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	if encode(s) != original || len(s.Bindings) != 0 || len(bound.Bindings) != 1 || bound.Generation != 2 {
		t.Fatal("mutation escaped snapshot")
	}
	again, e := Bind(bound, req, testEnv(), now.Add(time.Second))
	if e != nil || again != bound {
		t.Fatal("retry allocated or advanced", e)
	}
	other := bindRequest(bound, "a", "a-primary", "different")
	if _, e = Bind(bound, other, testEnv(), now); !errors.Is(e, ErrConflict) {
		t.Fatal("key overwrite", e)
	}
	thief := bindRequest(bound, "b", "b-primary", "path-a")
	if _, e = Bind(bound, thief, testEnv(), now); !errors.Is(e, ErrConflict) {
		t.Fatal("key theft", e)
	}
	wrong := bindRequest(bound, "b", "a-primary", "another")
	if _, e = Bind(bound, wrong, testEnv(), now); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign path", e)
	}
	stale := bindRequest(bound, "a", "a-backup", "backup")
	stale.ExpectedGeneration = 1
	if _, e = Bind(bound, stale, testEnv(), now); !errors.Is(e, ErrConflict) {
		t.Fatal("stale new binding", e)
	}
	stale.ExpectedGeneration = bound.Generation
	both, e := Bind(bound, stale, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	if both.Bindings[0].InnerAddress == both.Bindings[1].InnerAddress {
		t.Fatal("duplicate lease")
	}
	for _, b := range both.Bindings {
		p, _ := netip.ParsePrefix(b.InnerAddress)
		if p.Addr().String() == "10.78.0.1" {
			t.Fatal("reserved address allocated")
		}
	}
	v := both.NodeView("a")
	if e = v.Validate("a", now); e != nil {
		t.Fatal(e)
	}
	if len(v.Spec.Paths) != 2 || len(v.Bindings) != 2 {
		t.Fatal("wrong node view")
	}
	v.Spec.Paths[0].TargetIDs[0] = "mutated"
	if encode(both) == encode(v) || both.Spec.Paths[0].TargetIDs[0] == "mutated" {
		t.Fatal("view aliases stored slices")
	}
	before := encode(both)
	_, e = Apply(both, Update{ControllerID: both.ControllerID, ExpectedGeneration: 1, TTLSeconds: 3600, Spec: testSpec()}, testEnv(), now)
	if !errors.Is(e, ErrConflict) || encode(both) != before {
		t.Fatal("stale admin changed state", e)
	}
}
func TestCatalogRetirementNeverReusesKeyIPOrIdentity(t *testing.T) {
	s, now := newCatalog(t)
	req := bindRequest(s, "a", "a-primary", "first")
	s, e := Bind(s, req, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	lease := s.Bindings[0].InnerAddress
	update := func(spec Spec) (*State, error) {
		return Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now.Add(time.Second))
	}
	spec := cloneSpec(s.Spec)
	spec.Paths = slices.DeleteFunc(spec.Paths, func(p Path) bool { return p.ID == "a-primary" })
	if _, e = update(spec); !errors.Is(e, ErrConflict) {
		t.Fatal("removed enabled binding", e)
	}
	spec = cloneSpec(s.Spec)
	for i, p := range spec.Paths {
		if p.ID == "a-primary" {
			spec.Paths[i].Disabled = true
		}
	}
	s, e = update(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec = cloneSpec(s.Spec)
	spec.Paths = slices.DeleteFunc(spec.Paths, func(p Path) bool { return p.ID == "a-primary" })
	s, e = update(spec)
	if e != nil {
		t.Fatal(e)
	}
	if s.Bindings[0].RetiredAt.IsZero() {
		t.Fatal("lost retirement")
	}
	reuse := bindRequest(s, "b", "b-primary", "first")
	if _, e = Bind(s, reuse, testEnv(), now.Add(2*time.Second)); !errors.Is(e, ErrConflict) {
		t.Fatal("retired key reused", e)
	}
	spec = cloneSpec(s.Spec)
	spec.Paths = append(spec.Paths, Path{ID: "a-primary", NodeID: "b", RelayID: "rb", EndpointID: "e", UnderlayID: "lan", TargetIDs: []string{"app"}})
	if _, e = update(spec); e == nil {
		t.Fatal("retired ID reused")
	}
	s, e = Bind(s, bindRequest(s, "b", "b-primary", "bkey"), testEnv(), now.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	for _, b := range s.Bindings {
		if b.RetiredAt.IsZero() && b.InnerAddress == lease {
			t.Fatal("retired lease reused")
		}
	}
	prior := encode(s)
	n, e := RemoveNode(s, "b", now.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	env := testEnv()
	delete(env.Nodes, "b")
	if e = n.Validate(env); e != nil {
		t.Fatal(e)
	}
	if encode(s) != prior || len(n.NodeView("b").Spec.Paths) != 0 || len(n.NodeView("b").Bindings) != 0 {
		t.Fatal("removal snapshot mismatch")
	}
}
func TestCatalogLeaseExhaustionAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	spec := testSpec()
	spec.PoolCIDR = "10.78.0.0/30"
	spec.ReservedIPs = []string{"10.78.0.1"}
	s, e := Apply(nil, Update{Spec: spec, TTLSeconds: 60}, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	req := bindRequest(s, "a", "a-primary", "one")
	s, e = Bind(s, req, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	if s.Bindings[0].InnerAddress != "10.78.0.2/32" {
		t.Fatal(s.Bindings)
	}
	if _, e = Bind(s, bindRequest(s, "a", "a-backup", "two"), testEnv(), now); !errors.Is(e, ErrCapacity) {
		t.Fatal("pool exhausted", e)
	}
	if _, e = Bind(s, req, testEnv(), s.ExpiresAt); !errors.Is(e, ErrExpired) {
		t.Fatal("expired binding retry", e)
	}
	if e = s.NodeView("a").Validate("a", s.ExpiresAt); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
}
func TestBoundIdentityAndRelayKeyHistory(t *testing.T) {
	s, now := newCatalog(t)
	s, e := Bind(s, bindRequest(s, "a", "a-primary", "path"), testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Spec){
		func(p *Spec) { p.Relays[0].PublicKey = testKey("newra"); p.Relays[0].KeyGeneration++ },
		func(p *Spec) { p.Relays[0].Endpoints[0].Address = "192.0.2.13:51820" },
		func(p *Spec) { p.Targets[0].Port = 8443 },
	} {
		spec := cloneSpec(s.Spec)
		change(&spec)
		if _, e = Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now); !errors.Is(e, ErrConflict) {
			t.Fatal("bound identity changed", e)
		}
	}
	spec := cloneSpec(s.Spec)
	spec.Relays[1].PublicKey = testKey("newrb")
	spec.Relays[1].KeyGeneration++
	s, e = Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	r := bindRequest(s, "b", "b-primary", "rb")
	if _, e = Bind(s, r, testEnv(), now); !errors.Is(e, ErrConflict) {
		t.Fatal("retired relay key became node key", e)
	}
	spec = cloneSpec(s.Spec)
	spec.Relays[1].PublicKey = testKey("rb")
	spec.Relays[1].KeyGeneration++
	if _, e = Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now); !errors.Is(e, ErrConflict) {
		t.Fatal("old relay key resurrected", e)
	}
}
func TestInvalidCatalogDefinitions(t *testing.T) {
	cases := map[string]func(*Spec){
		"schema":               func(s *Spec) { s.SchemaVersion = 2 },
		"pool_overlap":         func(s *Spec) { s.PoolCIDR = "10.7.0.0/24" },
		"pool_host_bits":       func(s *Spec) { s.PoolCIDR = "10.78.0.1/24" },
		"pool_unbounded":       func(s *Spec) { s.PoolCIDR = "10.0.0.0/8" },
		"key":                  func(s *Spec) { s.Relays[0].PublicKey = "bad" },
		"key_zero":             func(s *Spec) { s.Relays[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"legacy_key":           func(s *Spec) { s.Relays[0].PublicKey = testKey("legacy") },
		"relay_key_duplicate":  func(s *Spec) { s.Relays[1].PublicKey = s.Relays[0].PublicKey },
		"endpoint_dns":         func(s *Spec) { s.Relays[0].Endpoints[0].Address = "example.com:51820" },
		"endpoint_pool":        func(s *Spec) { s.Relays[0].Endpoints[0].Address = "10.78.0.4:51820" },
		"endpoint_ipv6":        func(s *Spec) { s.Relays[0].Endpoints[0].Address = "[::1]:51820" },
		"endpoint_zero_port":   func(s *Spec) { s.Relays[0].Endpoints[0].Address = "192.0.2.11:0" },
		"unknown_node":         func(s *Spec) { s.Paths[0].NodeID = "not-registered" },
		"duplicate_path":       func(s *Spec) { s.Paths = append(s.Paths, s.Paths[0]) },
		"duplicate_pair":       func(s *Spec) { p := s.Paths[0]; p.ID = "other"; s.Paths = append(s.Paths, p) },
		"unknown_endpoint":     func(s *Spec) { s.Paths[0].EndpointID = "unknown" },
		"unknown_target":       func(s *Spec) { s.Paths[0].TargetIDs = []string{"unknown"} },
		"target_probe_outside": func(s *Spec) { s.Targets[0].ProbeAddress = "198.18.0.3" },
		"target_default":       func(s *Spec) { s.Targets[0].Prefixes = []string{"0.0.0.0/0"} },
		"target_pool":          func(s *Spec) { s.Targets[0].Prefixes = []string{"10.78.0.0/24"} },
		"target_overlap": func(s *Spec) {
			s.Targets = append(s.Targets, Target{ID: "overlap", Prefixes: []string{"198.18.0.0/24"}, ProbeAddress: "198.18.0.2", Protocol: "tcp", Port: 443})
		},
		"target_endpoint": func(s *Spec) {
			s.Targets[0].Prefixes = []string{"192.0.2.11/32"}
			s.Targets[0].ProbeAddress = "192.0.2.11"
		},
		"reserved_duplicate": func(s *Spec) { s.ReservedIPs = append(s.ReservedIPs, s.ReservedIPs[0]) },
		"reserved_network":   func(s *Spec) { s.ReservedIPs = []string{"10.78.0.0"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := testSpec()
			change(&s)
			if _, e := Apply(nil, Update{Spec: s, TTLSeconds: 3600}, testEnv(), time.Now()); e == nil {
				t.Fatal("bad definition accepted")
			}
		})
	}
}
func TestTamperedPersistenceAndViews(t *testing.T) {
	s, now := newCatalog(t)
	s, e := Bind(s, bindRequest(s, "a", "a-primary", "a-key"), testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*State){
		"hash":                   func(s *State) { s.Bindings[0].DefinitionHash = "bad" },
		"lease":                  func(s *State) { s.Bindings[0].InnerAddress = "10.78.0.1/32" },
		"owner":                  func(s *State) { s.Bindings[0].NodeID = "b" },
		"missing_key_ledger":     func(s *State) { s.ReservedRelayKeys = nil },
		"active_retired":         func(s *State) { s.RetiredPathIDs = []string{s.Bindings[0].PathID} },
		"invalid_validity":       func(s *State) { s.ExpiresAt = s.IssuedAt },
		"unsupported_generation": func(s *State) { s.Generation = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			n := clone(s)
			change(n)
			if e = n.Validate(testEnv()); e == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
	v := s.NodeView("a")
	if e = v.Validate("b", now); e == nil {
		t.Fatal("foreign identity accepted")
	}
	v = s.NodeView("a")
	v.Spec.Paths[0].NodeID = "b"
	if e = v.Validate("a", now); e == nil {
		t.Fatal("foreign path accepted")
	}
}

func TestPublicKeyAliasesAndNonUnicastRanges(t *testing.T) {
	key := testKey("aliased")
	raw, _ := base64.StdEncoding.DecodeString(key)
	raw[31] |= 128
	alias := base64.StdEncoding.EncodeToString(raw)
	if ValidatePublicKey(alias) == nil || PublicKeyID(alias) != key {
		t.Fatal("X25519 high-bit alias accepted as a distinct key")
	}
	// The noncanonical field element p+9 is equivalent to basepoint 9.
	raw = make([]byte, 32)
	for i := range raw {
		raw[i] = 255
	}
	raw[0], raw[31] = 246, 127
	alias = base64.StdEncoding.EncodeToString(raw)
	base := make([]byte, 32)
	base[0] = 9
	if ValidatePublicKey(alias) == nil || PublicKeyID(alias) != base64.StdEncoding.EncodeToString(base) {
		t.Fatal("field reduction alias accepted")
	}
	s, now := newCatalog(t)
	s, e := Bind(s, bindRequest(s, "a", "a-primary", "aliased"), testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = base64.StdEncoding.DecodeString(key)
	raw[31] |= 128
	if !s.KeyReserved(base64.StdEncoding.EncodeToString(raw)) {
		t.Fatal("legacy alias bypassed reservation")
	}
	for _, cidr := range []string{"128.0.0.0/2", "0.1.0.0/16", "240.0.0.0/24", "169.254.1.0/24"} {
		if _, e := prefix(cidr); e == nil {
			t.Fatal("non-unicast range", cidr)
		}
	}
}

func TestDrainLifetimeLimitsAndBackwardsClock(t *testing.T) {
	s, now := newCatalog(t)
	for _, disabled := range []bool{false, true} {
		spec := cloneSpec(s.Spec)
		for i := range spec.Paths {
			spec.Paths[i].Drain = !disabled
			spec.Paths[i].Disabled = disabled
		}
		blocked, e := Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Bind(blocked, bindRequest(blocked, "a", "a-primary", "blocked"), testEnv(), now); !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	bound, e := Bind(s, bindRequest(s, "a", "a-primary", "clock"), testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	removed, e := RemoveNode(bound, "a", now.Add(-time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if e = removed.Validate(testEnv()); e != nil {
		t.Fatal("clock step corrupted persisted ledger", e)
	}
	if !removed.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("removal extended validity")
	}
	n := clone(s)
	n.Generation = ^uint64(0) - 1
	if _, e = Bind(n, bindRequest(n, "a", "a-primary", "full"), testEnv(), now); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	n = clone(s)
	for i := 0; i < MaxPathIDs; i++ {
		n.RetiredPathIDs = append(n.RetiredPathIDs, fmt.Sprintf("retired-%d", i))
	}
	if e = n.Validate(testEnv()); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
}
