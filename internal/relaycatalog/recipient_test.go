// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func setRecipient(t *testing.T, s *State, relay, principal string) *State {
	t.Helper()
	n, e := SetRecipient(s, RecipientUpdate{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, RelayID: relay, PrincipalID: principal}, testEnv())
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestRecipientCASRemovalAndIsolation(t *testing.T) {
	s, now := newCatalog(t)
	before := encode(s)
	if _, ok := s.DeploymentFor("ra", "ra"); ok {
		t.Fatal("relay name granted authority")
	}
	g := setRecipient(t, s, "ra", "a")
	if encode(s) != before || g.Generation != s.Generation+1 || g.ExpiresAt != s.ExpiresAt {
		t.Fatal("grant mutated old approval or deadline")
	}
	if same := setRecipient(t, g, "ra", "a"); same != g {
		t.Fatal("idempotent grant changed generation")
	}
	for _, req := range []RecipientUpdate{
		{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, RelayID: "ra", PrincipalID: "a"},
		{ControllerID: "other", ExpectedGeneration: g.Generation, RelayID: "ra", PrincipalID: "a"},
		{ControllerID: g.ControllerID, ExpectedGeneration: g.Generation, RelayID: "missing", PrincipalID: "a"},
		{ControllerID: g.ControllerID, ExpectedGeneration: g.Generation, RelayID: "ra", PrincipalID: "missing"},
	} {
		if _, e := SetRecipient(g, req, testEnv()); e == nil {
			t.Fatal("bad grant accepted", req)
		}
	}
	if _, ok := g.DeploymentFor("b", "ra"); ok {
		t.Fatal("other principal authorized")
	}
	if _, ok := g.DeploymentFor("a", "rb"); ok {
		t.Fatal("other relay authorized")
	}
	// Principal b owns a grant even after its own robot paths are gone.
	g, _ = RemoveNode(g, "b", now)
	g = setRecipient(t, g, "rb", "b")
	removed, e := RemoveNode(g, "b", now.Add(-time.Hour))
	if e != nil || removed.Generation != g.Generation+1 || len(removed.Recipients) != 1 || removed.RecipientSchema != 1 {
		t.Fatal("grant-only removal failed", e)
	}
	if _, ok := removed.DeploymentFor("b", "rb"); ok {
		t.Fatal("same-name re-enrollment inherited grant")
	}
	withdrawn := setRecipient(t, removed, "ra", "")
	if len(withdrawn.Recipients) != 0 || withdrawn.RecipientSchema != 1 {
		t.Fatal("withdrawal lost sticky schema")
	}
	// Removing the relay itself also drops its recipient in the approval commit.
	empty, _ := Apply(nil, Update{Spec: Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24", Relays: testSpec().Relays}, TTLSeconds: 60}, testEnv(), now)
	empty = setRecipient(t, empty, "ra", "a")
	spec := cloneSpec(empty.Spec)
	spec.Relays = spec.Relays[1:]
	next, e := Apply(empty, Update{ControllerID: empty.ControllerID, ExpectedGeneration: empty.Generation, TTLSeconds: 60, Spec: spec}, testEnv(), now)
	if e != nil || len(next.Recipients) != 0 || next.RecipientSchema != 1 {
		t.Fatal("removed relay retained grant", e)
	}
}

func TestRecipientRejectsBrokenLedgerAndPendingPrincipal(t *testing.T) {
	s, _ := newCatalog(t)
	env := testEnv()
	env.Nodes["pending"] = false
	if _, e := SetRecipient(s, RecipientUpdate{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, RelayID: "ra", PrincipalID: "pending"}, env); !errors.Is(e, ErrInvalid) {
		t.Fatal("pending identity granted access", e)
	}
	s = setRecipient(t, s, "ra", "a")
	for name, change := range map[string]func(*State){
		"missing_schema":    func(s *State) { s.RecipientSchema = 0 },
		"new_schema":        func(s *State) { s.RecipientSchema = 2 },
		"duplicate":         func(s *State) { s.Recipients = append(s.Recipients, s.Recipients[0]) },
		"unknown_relay":     func(s *State) { s.Recipients[0].RelayID = "unknown" },
		"unknown_principal": func(s *State) { s.Recipients[0].PrincipalID = "unknown" },
		"empty_principal":   func(s *State) { s.Recipients[0].PrincipalID = "" },
		"overflow":          func(s *State) { s.Recipients = make([]RecipientGrant, MaxRelays+1) },
	} {
		t.Run(name, func(t *testing.T) {
			n := clone(s)
			change(n)
			if e := n.Validate(env); e == nil {
				t.Fatal("invalid grant ledger accepted")
			}
		})
	}
	n := clone(s)
	n.Generation = ^uint64(0) - 1
	if _, e := SetRecipient(n, RecipientUpdate{ControllerID: n.ControllerID, ExpectedGeneration: n.Generation, RelayID: "ra", PrincipalID: ""}, env); !errors.Is(e, ErrCapacity) {
		t.Fatal("generation wrapped", e)
	}
}

func TestDeploymentBoundEnabledProjectionAndValidation(t *testing.T) {
	s, now := newCatalog(t)
	for _, p := range s.Spec.Paths {
		var e error
		s, e = Bind(s, bindRequest(s, p.NodeID, p.ID, "binding-"+p.ID), testEnv(), now)
		if e != nil {
			t.Fatal(e)
		}
	}
	s = setRecipient(t, s, "ra", "a")
	v, ok := s.DeploymentFor("a", "ra")
	if !ok || len(v.Bindings) != 2 || len(v.Spec.Relays) != 1 || len(v.Spec.Paths) != 2 || len(v.Spec.ReservedIPs) != 0 {
		t.Fatal("wrong relay projection")
	}
	if e := v.Validate("a", "ra", now); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(v)
	for _, forbidden := range []string{"recipients", "retired_path", testKey("rb"), testKey("binding-a-backup")} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("foreign metadata in view", forbidden)
		}
	}
	// Mutating a returned view must not alter immutable published state.
	v.Spec.Paths[0].TargetIDs[0] = "changed"
	v.Spec.Relays[0].Endpoints[0].Address = "changed"
	v.Spec.Targets[0].Prefixes[0] = "changed"
	if e := s.Validate(testEnv()); e != nil {
		t.Fatal("projection aliases state", e)
	}
	v, _ = s.DeploymentFor("a", "ra")
	for name, change := range map[string]func(*DeploymentView){
		"schema":            func(v *DeploymentView) { v.SchemaVersion = 2 },
		"principal":         func(v *DeploymentView) { v.PrincipalID = "b" },
		"relay":             func(v *DeploymentView) { v.RelayID = "rb" },
		"foreign_relay":     func(v *DeploymentView) { v.Spec.Relays = append(v.Spec.Relays, testSpec().Relays[1]) },
		"unbound":           func(v *DeploymentView) { v.Bindings = v.Bindings[:1] },
		"duplicate_binding": func(v *DeploymentView) { v.Bindings[1] = v.Bindings[0] },
		"disabled":          func(v *DeploymentView) { v.Spec.Paths[0].Disabled = true },
		"retired":           func(v *DeploymentView) { v.Bindings[0].RetiredAt = now },
		"lease":             func(v *DeploymentView) { v.Bindings[0].InnerAddress = "10.78.0.0/24" },
		"hash":              func(v *DeploymentView) { v.Bindings[0].DefinitionHash = strings.Repeat("f", 64) },
		"foreign_target":    func(v *DeploymentView) { v.Spec.Targets = append(v.Spec.Targets, v.Spec.Targets[0]) },
		"reservation":       func(v *DeploymentView) { v.Spec.ReservedIPs = []string{"10.78.0.1"} },
		"future":            func(v *DeploymentView) { v.IssuedAt = now.Add(time.Minute); v.ExpiresAt = v.IssuedAt.Add(time.Hour) },
		"expiry":            func(v *DeploymentView) { v.IssuedAt = now.Add(-time.Hour); v.ExpiresAt = now },
	} {
		t.Run(name, func(t *testing.T) {
			copy, _ := s.DeploymentFor("a", "ra")
			change(&copy)
			if e := copy.Validate("a", "ra", now); e == nil {
				t.Fatal("invalid deployment accepted")
			}
		})
	}
	// Drain retains peers. Disabled paths are absent even though bindings remain
	// reserved in the controller ledger and node views.
	spec := cloneSpec(s.Spec)
	for i := range spec.Paths {
		if spec.Paths[i].RelayID == "ra" {
			spec.Paths[i].Drain = true
		}
	}
	s, e := Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	v, _ = s.DeploymentFor("a", "ra")
	if len(v.Bindings) != 2 || !v.Spec.Paths[0].Drain {
		t.Fatal("drain dropped existing binding")
	}
	spec = cloneSpec(s.Spec)
	for i := range spec.Paths {
		spec.Paths[i].Disabled = true
	}
	s, e = Apply(s, Update{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, TTLSeconds: 3600, Spec: spec}, testEnv(), now)
	if e != nil {
		t.Fatal(e)
	}
	v, _ = s.DeploymentFor("a", "ra")
	if len(v.Bindings) != 0 || len(v.Spec.Paths) != 0 || len(v.Spec.Targets) != 0 || v.Validate("a", "ra", now) != nil {
		t.Fatal("disabled peers not removed from deployment")
	}
	if len(s.Bindings) != 3 || !slices.ContainsFunc(s.NodeView("a").Spec.Paths, func(p Path) bool { return p.Disabled }) {
		t.Fatal("deployment changed node ledger")
	}
	if !errors.Is(v.Validate("a", "ra", s.ExpiresAt), ErrExpired) {
		t.Fatal("expired empty deployment accepted")
	}
}
