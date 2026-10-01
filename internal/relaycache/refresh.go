// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

const MaxRefreshDuration = 2 * time.Minute
const MaxConflicts = relaycatalog.MaxNodes * relaycatalog.MaxPathsPerNode

type Client interface {
	RelayCatalog(context.Context, string) (relaycatalog.View, error)
	BindRelayPath(context.Context, relaycatalog.BindRequest) (relaycatalog.View, error)
}

// Refresh serializes all local mutations and bounds both CAS contention and total
// wall time. A caller gets an error on any failed refresh even if older, valid
// cached candidates remain available in the accompanying redacted Report.
func (s *Store) Refresh(ctx context.Context, client Client) (Report, error) {
	if !s.mu.TryLock() {
		return busyReport(s.nodeID), ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return Report{}, osClosed()
	}
	ctx, cancel := context.WithTimeout(ctx, MaxRefreshDuration)
	defer cancel()
	if s.uncertain {
		if e := s.repair(); e != nil {
			return s.report(), e
		}
	}
	if s.clockRegressed() {
		return s.fail("rejected", "clock_regressed", true, errors.New("local clock moved backwards; correct the clock before refreshing"))
	}
	next := cloneState(s.state)
	// A prior refresh may have observed denial before its final state could be
	// persisted. A transport failure is not evidence that approval is restored.
	if next.Refresh.Result == "in_progress" && next.BlockedReason == "" {
		next.BlockedReason = "refresh_interrupted"
	}
	next.Refresh.Result = "in_progress"
	next.Refresh.Reason = "refresh_interrupted"
	next.Refresh.AttemptedAt = s.now().UTC()
	next.Refresh.CompletedAt = time.Time{}
	if e := s.save(next); e != nil {
		return s.report(), e
	}
	if e := ctx.Err(); e != nil {
		return s.remoteFailure(e)
	}
	view, e := client.RelayCatalog(ctx, s.nodeID)
	if e != nil {
		return s.remoteFailure(e)
	}
	if e = s.accept(view); e != nil {
		return s.reject(e)
	}
	conflicts := 0
	for {
		if e = ctx.Err(); e != nil {
			return s.remoteFailure(e)
		}
		path, found := s.pendingPath()
		if !found {
			next = cloneState(s.state)
			next.Refresh.Result = "success"
			next.Refresh.Reason = ""
			next.Refresh.CompletedAt = s.now().UTC()
			next.Refresh.LastSuccessAt = next.Refresh.CompletedAt
			if e = s.save(next); e != nil {
				return s.report(), e
			}
			return s.report(), nil
		}
		key, found := s.key(path.ID)
		if !found {
			if len(s.state.Keys) >= relaycatalog.MaxPathIDs {
				return s.fail("partial", "key_ledger_full", false, errors.New("node path key ledger is full"))
			}
			private, public, e := generateKey()
			if e != nil {
				return s.fail("partial", "key_generation", false, errors.New("path key generation failed"))
			}
			next = cloneState(s.state)
			key = pathKey{PathID: path.ID, PrivateKey: private, PublicKey: public, DefinitionHash: relaycatalog.DefinitionHash(next.Catalog.Spec, path)}
			next.Keys = append(next.Keys, key)
			// Never send a generated key until its private half is durably committed.
			if e = s.save(next); e != nil {
				return s.report(), e
			}
		}
		generation := s.state.Catalog.Generation
		req := relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: s.state.Catalog.ControllerID, ExpectedGeneration: generation, NodeID: s.nodeID, PathID: path.ID, PublicKey: key.PublicKey}
		response, e := client.BindRelayPath(ctx, req)
		if e == nil {
			// Validate even alternate Client implementations before changing local state.
			matching := false
			for _, b := range response.Bindings {
				matching = matching || b.PathID == path.ID && b.PublicKey == key.PublicKey
			}
			if !matching {
				return s.reject(errors.New("binding response omitted requested key/path"))
			}
			if e = s.accept(response); e != nil {
				return s.reject(e)
			}
			continue
		}
		var h *api.HTTPError
		if !errors.As(e, &h) || h.StatusCode != 409 || h.Code != "relay_catalog_conflict" {
			return s.remoteFailure(e)
		}
		conflicts++
		if conflicts > MaxConflicts {
			return s.fail("partial", "contention_limit", false, errors.New("catalog changed too often; retry refresh later"))
		}
		if e = s.wait(ctx, conflicts); e != nil {
			return s.remoteFailure(e)
		}
		view, e = client.RelayCatalog(ctx, s.nodeID)
		if e != nil {
			return s.remoteFailure(e)
		}
		if e = s.accept(view); e != nil {
			return s.reject(e)
		}
		if view.Generation == generation {
			return s.fail("rejected", "binding_conflict", true, errors.New("binding conflict without a newer catalog; reconcile path ownership"))
		}
	}
}
func osClosed() error { return errors.New("relay cache is closed") }
func backoff(ctx context.Context, n int) error {
	maximum := min(10*time.Millisecond*time.Duration(1<<min(n-1, 5)), 250*time.Millisecond)
	timer := time.NewTimer(maximum/2 + time.Duration(rand.Int64N(int64(maximum/2))))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (s *Store) key(id string) (pathKey, bool) {
	for _, k := range s.state.Keys {
		if k.PathID == id {
			return k, true
		}
	}
	return pathKey{}, false
}
func (s *Store) pendingPath() (relaycatalog.Path, bool) {
	for _, p := range s.state.Catalog.Spec.Paths {
		if p.Drain || p.Disabled {
			continue
		}
		k, found := s.key(p.ID)
		if !found || k.Binding == nil {
			return p, true
		}
	}
	return relaycatalog.Path{}, false
}
func (s *Store) accept(v relaycatalog.View) error {
	if e := v.Validate(s.nodeID, s.currentTime()); e != nil {
		return fmt.Errorf("catalog validation: %w", e)
	}
	h := digest(v)
	hash := hex.EncodeToString(h[:])
	if s.state.ControllerID != "" {
		if s.state.ControllerID != v.ControllerID {
			return errors.New("controller identity changed; explicit recovery required")
		}
		if v.Generation < s.state.Generation {
			return errors.New("catalog generation moved backwards; restore current controller state")
		}
		if v.Generation == s.state.Generation && hash != s.state.ViewDigest {
			return errors.New("catalog content changed within the same generation")
		}
	}
	if old := s.state.Catalog; old != nil && v.Spec.PoolCIDR != old.Spec.PoolCIDR {
		return errors.New("catalog pool changed within controller identity")
	}
	// Remember every structurally valid authenticated revision before checking
	// local keys. A rejected newer binding must not allow an older revision later.
	if v.Generation > s.state.Generation {
		observed := cloneState(s.state)
		observed.ControllerID = v.ControllerID
		observed.Generation = v.Generation
		observed.ViewDigest = hash
		observed.BlockedReason = "pending_validation"
		if e := s.save(observed); e != nil {
			return e
		}
	}
	next := cloneState(s.state)
	paths := map[string]relaycatalog.Path{}
	bindings := map[string]relaycatalog.Binding{}
	for _, p := range v.Spec.Paths {
		paths[p.ID] = p
	}
	for _, b := range v.Bindings {
		bindings[b.PathID] = b
	}
	known := map[string]bool{}
	for i, k := range next.Keys {
		known[k.PathID] = true
		p, active := paths[k.PathID]
		if !active {
			next.Keys[i].Retired = true
			continue
		}
		if k.Retired {
			return errors.New("retired path identity reappeared")
		}
		if k.DefinitionHash != relaycatalog.DefinitionHash(v.Spec, p) {
			return errors.New("key's approved path definition changed; approve a new path identity")
		}
		b, bound := bindings[k.PathID]
		if k.Binding != nil && (!bound || !same(k.Binding, &b)) {
			return errors.New("previously confirmed path binding changed or disappeared")
		}
		if bound {
			if b.PublicKey != k.PublicKey {
				return errors.New("controller path key does not match the node's stored private key")
			}
			next.Keys[i].Binding = &b
		}
	}
	for _, b := range v.Bindings {
		if !known[b.PathID] {
			return errors.New("controller binding has no local private key; restore complete cache or approve a new path identity")
		}
	}
	// Copy the view rather than retaining a client's mutable slices.
	raw := cloneView(v)
	next.Catalog = &raw
	next.BlockedReason = ""
	return s.save(next)
}
func cloneView(v relaycatalog.View) relaycatalog.View {
	n := cloneState(diskState{Catalog: &v})
	return *n.Catalog
}
func (s *Store) reject(e error) (Report, error) {
	if s.uncertain {
		return s.report(), e
	}
	return s.fail("rejected", "catalog_rejected", true, e)
}
func (s *Store) fail(result, reason string, block bool, cause error) (Report, error) {
	next := cloneState(s.state)
	next.Refresh.Result = result
	next.Refresh.Reason = reason
	next.Refresh.CompletedAt = s.now().UTC()
	if block {
		next.BlockedReason = reason
	}
	if e := s.save(next); e != nil {
		return s.report(), errors.Join(cause, e)
	}
	return s.report(), cause
}
func (s *Store) remoteFailure(e error) (Report, error) {
	var h *api.HTTPError
	if errors.As(e, &h) {
		if h.StatusCode == 401 || h.StatusCode == 403 {
			return s.fail("denied", "identity_denied", true, errors.New("controller rejected node identity; renew credentials or re-enroll explicitly"))
		}
		if h.Code == "relay_catalog_uncertain" {
			return s.fail("rejected", "controller_uncertain", true, errors.New("controller catalog durability is uncertain"))
		}
		if h.StatusCode >= 500 || h.StatusCode == 429 {
			return s.fail("unavailable", "controller_unavailable", false, errors.New("controller unavailable; inspect cached preparation status"))
		}
		if h.Code == "relay_catalog_expired" {
			return s.fail("rejected", "catalog_expired", true, relaycatalog.ErrExpired)
		}
		return s.fail("rejected", "controller_rejected", true, errors.New("controller rejected catalog operation"))
	}
	if errors.Is(e, relaycatalog.ErrExpired) {
		return s.fail("rejected", "catalog_expired", true, e)
	}
	var verification *tls.CertificateVerificationError
	if errors.As(e, &verification) {
		return s.fail("rejected", "tls_verification", true, errors.New("controller TLS verification failed"))
	}
	underlying := e
	var u *url.Error
	if errors.As(e, &u) {
		underlying = u.Err
	}
	var op *net.OpError
	if errors.As(underlying, &op) && op.Op == "remote error" {
		return s.fail("denied", "tls_identity_denied", true, errors.New("TLS peer rejected credentials"))
	}
	var network net.Error
	if errors.As(underlying, &network) || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) || errors.Is(e, net.ErrClosed) {
		return s.fail("unavailable", "transport_unavailable", false, fmt.Errorf("catalog refresh interrupted or unavailable: %w", e))
	}
	return s.fail("rejected", "invalid_response_or_credentials", true, errors.New("catalog response or local credentials failed validation"))
}
