// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import (
	"fmt"
	"slices"
	"time"
)

func (s *State) validateRecipients(env Environment) error {
	if s.RecipientSchema != 0 && s.RecipientSchema != 1 || s.RecipientSchema == 0 && len(s.Recipients) != 0 {
		return invalid("unsupported recipient schema")
	}
	if len(s.Recipients) > MaxRelays {
		return fmt.Errorf("%w: relay recipient limit", ErrCapacity)
	}
	seen := map[string]bool{}
	for _, g := range s.Recipients {
		if !slices.ContainsFunc(s.Spec.Relays, func(r Relay) bool { return r.ID == g.RelayID }) || seen[g.RelayID] || g.PrincipalID == "" || !env.Nodes[g.PrincipalID] {
			return invalid("recipient must reference a distinct active relay and registered principal")
		}
		seen[g.RelayID] = true
	}
	return nil
}

// SetRecipient uses the same catalog CAS as approval and binding changes. It
// does not renew the approval deadline. Even an idempotent request requires
// current CAS: after a lost response, read admin status before retrying.
func SetRecipient(old *State, req RecipientUpdate, env Environment) (*State, error) {
	if old == nil {
		return nil, ErrNotFound
	}
	if req.ControllerID != old.ControllerID || req.ExpectedGeneration != old.Generation {
		return nil, fmt.Errorf("%w: controller identity or generation changed; read status", ErrConflict)
	}
	if !slices.ContainsFunc(old.Spec.Relays, func(r Relay) bool { return r.ID == req.RelayID }) {
		return nil, ErrNotFound
	}
	if req.PrincipalID != "" && !env.Nodes[req.PrincipalID] {
		return nil, invalid("recipient principal must be registered and enrollment complete")
	}
	previous := ""
	for _, g := range old.Recipients {
		if g.RelayID == req.RelayID {
			previous = g.PrincipalID
		}
	}
	if previous == req.PrincipalID {
		return old, nil
	}
	n := clone(old)
	n.RecipientSchema = 1
	n.Recipients = slices.DeleteFunc(n.Recipients, func(g RecipientGrant) bool { return g.RelayID == req.RelayID })
	if req.PrincipalID != "" {
		n.Recipients = append(n.Recipients, RecipientGrant{RelayID: req.RelayID, PrincipalID: req.PrincipalID})
	}
	slices.SortFunc(n.Recipients, func(a, b RecipientGrant) int { return compare(a.RelayID, b.RelayID) })
	if e := nextGeneration(n); e != nil {
		return nil, e
	}
	return n, n.Validate(env)
}

// DeploymentFor checks the grant before exposing any catalog metadata. Callers
// must authenticate principal independently; the request supplies only relayID.
func (s *State) DeploymentFor(principal, relayID string) (DeploymentView, bool) {
	if s == nil || !slices.ContainsFunc(s.Recipients, func(g RecipientGrant) bool {
		return g.RelayID == relayID && g.PrincipalID == principal
	}) {
		return DeploymentView{}, false
	}
	v := DeploymentView{SchemaVersion: 1, ControllerID: s.ControllerID, Generation: s.Generation, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt,
		PrincipalID: principal, RelayID: relayID, Spec: Spec{SchemaVersion: SchemaVersion, PoolCIDR: s.Spec.PoolCIDR}}
	bound := map[string]Binding{}
	for _, b := range s.Bindings {
		if b.RetiredAt.IsZero() {
			bound[b.PathID] = b
		}
	}
	usedTargets := map[string]bool{}
	for _, p := range s.Spec.Paths {
		b, ok := bound[p.ID]
		if p.RelayID != relayID || p.Disabled || !ok {
			continue
		}
		v.Spec.Paths = append(v.Spec.Paths, p)
		v.Bindings = append(v.Bindings, b)
		for _, id := range p.TargetIDs {
			usedTargets[id] = true
		}
	}
	for _, r := range s.Spec.Relays {
		if r.ID == relayID {
			v.Spec.Relays = append(v.Spec.Relays, r)
		}
	}
	for _, t := range s.Spec.Targets {
		if usedTargets[t.ID] {
			v.Spec.Targets = append(v.Spec.Targets, t)
		}
	}
	v.Spec = cloneSpec(v.Spec)
	return v, true
}

func (v DeploymentView) Validate(principal, relayID string, now time.Time) error {
	if v.SchemaVersion != 1 || principal == "" || !validText(principal, 256) || v.PrincipalID != principal || v.RelayID != relayID || !validID(relayID) {
		return invalid("deployment schema or recipient identity mismatch")
	}
	if len(v.Spec.Relays) != 1 || v.Spec.Relays[0].ID != relayID || len(v.Spec.ReservedIPs) != 0 {
		return invalid("deployment contains foreign relay or pool reservations")
	}
	nodes := map[string]bool{}
	targets := map[string]bool{}
	for _, p := range v.Spec.Paths {
		if p.RelayID != relayID || p.Disabled {
			return invalid("foreign or disabled deployment path")
		}
		nodes[p.NodeID] = true
		for _, id := range p.TargetIDs {
			targets[id] = true
		}
	}
	if len(v.Spec.Paths) != len(v.Bindings) || len(v.Spec.Targets) != len(targets) {
		return invalid("deployment must contain only bound paths and referenced targets")
	}
	for _, b := range v.Bindings {
		if !b.RetiredAt.IsZero() {
			return invalid("retired deployment binding")
		}
	}
	s := State{ControllerID: v.ControllerID, Generation: v.Generation, IssuedAt: v.IssuedAt, ExpiresAt: v.ExpiresAt, Spec: v.Spec, Bindings: v.Bindings,
		ReservedRelayKeys: []string{v.Spec.Relays[0].PublicKey}}
	if e := s.Validate(Environment{Nodes: nodes}); e != nil {
		return e
	}
	if v.IssuedAt.After(now.Add(30 * time.Second)) {
		return invalid("deployment issued in the future")
	}
	if !now.Before(v.ExpiresAt) {
		return ErrExpired
	}
	return nil
}
