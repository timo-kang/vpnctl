// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycatalog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

func cloneSpec(s Spec) Spec {
	s.ReservedIPs = slices.Clone(s.ReservedIPs)
	s.Relays = slices.Clone(s.Relays)
	s.Targets = slices.Clone(s.Targets)
	s.Paths = slices.Clone(s.Paths)
	for i := range s.Relays {
		s.Relays[i].Endpoints = slices.Clone(s.Relays[i].Endpoints)
	}
	for i := range s.Targets {
		s.Targets[i].Prefixes = slices.Clone(s.Targets[i].Prefixes)
	}
	for i := range s.Paths {
		s.Paths[i].TargetIDs = slices.Clone(s.Paths[i].TargetIDs)
	}
	return s
}
func clone(s *State) *State {
	n := *s
	n.Spec = cloneSpec(s.Spec)
	n.ReservedRelayKeys = slices.Clone(s.ReservedRelayKeys)
	n.Bindings = slices.Clone(s.Bindings)
	n.RetiredPathIDs = slices.Clone(s.RetiredPathIDs)
	n.RetiredRelayIDs = slices.Clone(s.RetiredRelayIDs)
	return &n
}
func normalize(s Spec) Spec {
	s = cloneSpec(s)
	slices.Sort(s.ReservedIPs)
	slices.SortFunc(s.Relays, func(a, b Relay) int { return compare(a.ID, b.ID) })
	slices.SortFunc(s.Targets, func(a, b Target) int { return compare(a.ID, b.ID) })
	slices.SortFunc(s.Paths, func(a, b Path) int { return compare(a.ID, b.ID) })
	for i := range s.Relays {
		slices.SortFunc(s.Relays[i].Endpoints, func(a, b Endpoint) int { return compare(a.ID, b.ID) })
	}
	for i := range s.Targets {
		slices.Sort(s.Targets[i].Prefixes)
	}
	for i := range s.Paths {
		slices.Sort(s.Paths[i].TargetIDs)
	}
	return s
}
func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func nextGeneration(s *State) error {
	if s.Generation >= ^uint64(0)-1 {
		return fmt.Errorf("%w: generation exhausted", ErrCapacity)
	}
	s.Generation++
	return nil
}
func definitionHash(s Spec, p Path) string {
	p.Priority = 0
	p.Cost = 0
	p.Drain = false
	p.Disabled = false
	v := struct {
		Path       Path
		Key        string
		Generation uint64
		Endpoint   Endpoint
		Targets    []Target
	}{Path: p}
	for _, r := range s.Relays {
		if r.ID == p.RelayID {
			v.Key = r.PublicKey
			v.Generation = r.KeyGeneration
			for _, ep := range r.Endpoints {
				if ep.ID == p.EndpointID {
					v.Endpoint = ep
				}
			}
		}
	}
	for _, id := range p.TargetIDs {
		for _, t := range s.Targets {
			if t.ID == id {
				v.Targets = append(v.Targets, t)
			}
		}
	}
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Apply replaces the approved descriptors using CAS. A lost response is resolved
// by reading status, never by silently applying the request to a newer revision.
func Apply(old *State, r Update, env Environment, now time.Time) (*State, error) {
	if r.TTLSeconds < 60 || r.TTLSeconds > 86400 {
		return nil, invalid("ttl_seconds must be 60..86400")
	}
	spec := normalize(r.Spec)
	if e := ValidateSpec(spec, env); e != nil {
		return nil, e
	}
	var n *State
	if old == nil {
		if r.ControllerID != "" || r.ExpectedGeneration != 0 {
			return nil, fmt.Errorf("%w: initialization requires empty controller_id and generation 0", ErrConflict)
		}
		var id [16]byte
		if _, e := rand.Read(id[:]); e != nil {
			return nil, e
		}
		n = &State{ControllerID: hex.EncodeToString(id[:])}
	} else {
		if r.ControllerID != old.ControllerID || r.ExpectedGeneration != old.Generation {
			return nil, fmt.Errorf("%w: controller identity or generation changed; read status", ErrConflict)
		}
		if spec.PoolCIDR != old.Spec.PoolCIDR || !slices.Equal(spec.ReservedIPs, old.Spec.ReservedIPs) {
			return nil, fmt.Errorf("%w: pool and reservations are immutable", ErrConflict)
		}
		n = clone(old)
		for _, r := range spec.Relays {
			same := false
			for _, prev := range old.Spec.Relays {
				same = same || prev.ID == r.ID && prev.PublicKey == r.PublicKey
			}
			if !same && slices.Contains(old.ReservedRelayKeys, r.PublicKey) {
				return nil, fmt.Errorf("%w: relay key was previously reserved", ErrConflict)
			}
		}
		newPaths := map[string]Path{}
		for _, p := range spec.Paths {
			newPaths[p.ID] = p
		}
		oldPaths := map[string]Path{}
		for _, p := range old.Spec.Paths {
			oldPaths[p.ID] = p
			if _, ok := newPaths[p.ID]; !ok {
				n.RetiredPathIDs = append(n.RetiredPathIDs, p.ID)
			}
		}
		for i, b := range n.Bindings {
			if !b.RetiredAt.IsZero() {
				continue
			}
			p, ok := newPaths[b.PathID]
			if !ok {
				if !oldPaths[b.PathID].Disabled {
					return nil, fmt.Errorf("%w: disable bound path %q in a prior revision before removal", ErrConflict, b.PathID)
				}
				n.Bindings[i].RetiredAt = retirementTime(now, b.CreatedAt)
			} else if p.NodeID != b.NodeID || definitionHash(spec, p) != b.DefinitionHash {
				return nil, fmt.Errorf("%w: bound path identity is immutable; approve a new path ID", ErrConflict)
			}
		}
		newRelays := map[string]Relay{}
		for _, r := range spec.Relays {
			newRelays[r.ID] = r
		}
		for _, r := range old.Spec.Relays {
			next, ok := newRelays[r.ID]
			if !ok {
				n.RetiredRelayIDs = append(n.RetiredRelayIDs, r.ID)
				continue
			}
			if next.PublicKey == r.PublicKey {
				if next.KeyGeneration != r.KeyGeneration {
					return nil, fmt.Errorf("%w: unchanged key must retain its generation", ErrConflict)
				}
			} else if r.KeyGeneration == ^uint64(0) || next.KeyGeneration != r.KeyGeneration+1 {
				return nil, fmt.Errorf("%w: key replacement must increment key_generation by one", ErrConflict)
			}
		}
	}
	n.Spec = spec
	for _, r := range spec.Relays {
		if !slices.Contains(n.ReservedRelayKeys, r.PublicKey) {
			n.ReservedRelayKeys = append(n.ReservedRelayKeys, r.PublicKey)
		}
	}
	slices.Sort(n.ReservedRelayKeys)
	n.IssuedAt = now.UTC()
	n.ExpiresAt = now.UTC().Add(time.Duration(r.TTLSeconds) * time.Second)
	if e := nextGeneration(n); e != nil {
		return nil, e
	}
	slices.Sort(n.RetiredPathIDs)
	slices.Sort(n.RetiredRelayIDs)
	if e := n.Validate(env); e != nil {
		return nil, e
	}
	return n, nil
}

// Bind never accepts an IP from the client. Every accepted key is scoped to one
// approved node/path and receives a unique host lease from the dedicated pool.
func Bind(old *State, r BindRequest, env Environment, now time.Time) (*State, error) {
	if r.SchemaVersion != SchemaVersion {
		return nil, invalid("unsupported binding schema")
	}
	if old == nil {
		return nil, ErrNotFound
	}
	if r.ControllerID != old.ControllerID || r.ExpectedGeneration == 0 || r.ExpectedGeneration > old.Generation {
		return nil, fmt.Errorf("%w: invalid controller identity/generation", ErrConflict)
	}
	if !now.Before(old.ExpiresAt) {
		return nil, ErrExpired
	}
	if e := ValidatePublicKey(r.PublicKey); e != nil {
		return nil, e
	}
	var path Path
	found := false
	for _, p := range old.Spec.Paths {
		if p.ID == r.PathID && p.NodeID == r.NodeID {
			path = p
			found = true
			break
		}
	}
	if !found || !env.Nodes[r.NodeID] {
		return nil, ErrNotFound
	}
	for _, b := range old.Bindings {
		if b.PathID == r.PathID && b.NodeID == r.NodeID && b.RetiredAt.IsZero() {
			if b.PublicKey == r.PublicKey {
				return old, nil
			}
			return nil, fmt.Errorf("%w: path is already bound to another key", ErrConflict)
		}
	}
	if r.ExpectedGeneration != old.Generation {
		return nil, fmt.Errorf("%w: stale generation; fetch current catalog", ErrConflict)
	}
	if path.Disabled || path.Drain {
		return nil, fmt.Errorf("%w: path does not admit new bindings", ErrConflict)
	}
	if env.ReservedKeys[r.PublicKey] {
		return nil, fmt.Errorf("%w: key is already reserved", ErrConflict)
	}
	for _, relayKey := range old.ReservedRelayKeys {
		if relayKey == r.PublicKey {
			return nil, fmt.Errorf("%w: relay key cannot identify a node path", ErrConflict)
		}
	}
	for _, b := range old.Bindings {
		if b.PublicKey == r.PublicKey {
			return nil, fmt.Errorf("%w: key already belongs to another or retired path", ErrConflict)
		}
	}
	pool, _ := prefix(old.Spec.PoolCIDR)
	used := map[string]bool{}
	for _, ip := range old.Spec.ReservedIPs {
		used[ip] = true
	}
	for _, b := range old.Bindings {
		p, _ := netip.ParsePrefix(b.InnerAddress)
		used[p.Addr().String()] = true
	}
	lease := ""
	for ip := pool.Addr().Next(); ip.IsValid() && ip != last(pool); ip = ip.Next() {
		if !used[ip.String()] {
			lease = ip.String() + "/32"
			break
		}
	}
	if lease == "" {
		return nil, fmt.Errorf("%w: path IP pool (retired leases remain reserved)", ErrCapacity)
	}
	n := clone(old)
	n.Bindings = append(n.Bindings, Binding{PathID: path.ID, NodeID: path.NodeID, PublicKey: r.PublicKey, InnerAddress: lease, DefinitionHash: definitionHash(n.Spec, path), CreatedAt: now.UTC()})
	slices.SortFunc(n.Bindings, func(a, b Binding) int { return compare(a.PathID, b.PathID) })
	if e := nextGeneration(n); e != nil {
		return nil, e
	}
	if e := n.Validate(env); e != nil {
		return nil, e
	}
	return n, nil
}

// RemoveNode retires every approved path and binding in the same transaction as
// identity removal. It changes no validity deadline and preserves all leases.
func RemoveNode(old *State, nodeID string, now time.Time) (*State, error) {
	if old == nil {
		return nil, nil
	}
	n := clone(old)
	n.Spec.Paths = nil
	for _, p := range old.Spec.Paths {
		if p.NodeID == nodeID {
			n.RetiredPathIDs = append(n.RetiredPathIDs, p.ID)
		} else {
			n.Spec.Paths = append(n.Spec.Paths, p)
		}
	}
	if len(n.Spec.Paths) == len(old.Spec.Paths) {
		return old, nil
	}
	for i, b := range n.Bindings {
		if b.NodeID == nodeID && b.RetiredAt.IsZero() {
			n.Bindings[i].RetiredAt = retirementTime(now, b.CreatedAt)
		}
	}
	slices.Sort(n.RetiredPathIDs)
	if e := nextGeneration(n); e != nil {
		return nil, e
	}
	return n, nil
}
func (s *State) NodeView(id string) View {
	v := View{ControllerID: s.ControllerID, Generation: s.Generation, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt, NodeID: id, Spec: Spec{SchemaVersion: SchemaVersion, PoolCIDR: s.Spec.PoolCIDR}}
	usedRelays := map[string]bool{}
	usedTargets := map[string]bool{}
	usedPaths := map[string]bool{}
	for _, p := range s.Spec.Paths {
		if p.NodeID == id {
			v.Spec.Paths = append(v.Spec.Paths, p)
			usedPaths[p.ID] = true
			usedRelays[p.RelayID] = true
			for _, t := range p.TargetIDs {
				usedTargets[t] = true
			}
		}
	}
	for _, r := range s.Spec.Relays {
		if usedRelays[r.ID] {
			v.Spec.Relays = append(v.Spec.Relays, r)
		}
	}
	for _, t := range s.Spec.Targets {
		if usedTargets[t.ID] {
			v.Spec.Targets = append(v.Spec.Targets, t)
		}
	}
	for _, b := range s.Bindings {
		if b.NodeID == id && b.RetiredAt.IsZero() && usedPaths[b.PathID] {
			v.Bindings = append(v.Bindings, b)
		}
	}
	v.Spec = cloneSpec(v.Spec)
	return v
}

// KeyReserved prevents legacy registration from claiming a path or relay key.
func (s *State) KeyReserved(key string) bool {
	if s == nil || key == "" {
		return false
	}
	key = PublicKeyID(key)
	if slices.Contains(s.ReservedRelayKeys, key) {
		return true
	}
	for _, b := range s.Bindings {
		if b.PublicKey == key {
			return true
		}
	}
	return false
}

// A backwards wall-clock adjustment must not make security removal persist an
// invalid ledger. It does not extend catalog validity or release any lease.
func retirementTime(now, created time.Time) time.Time {
	if now.Before(created) {
		return created
	}
	return now.UTC()
}

// DefinitionHash identifies a validated candidate's immutable binding identity.
// Callers must validate the containing spec/view before using this value.
func DefinitionHash(spec Spec, path Path) string { return definitionHash(spec, path) }
