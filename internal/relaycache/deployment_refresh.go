// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

const MaxDeploymentRefreshDuration = 20 * time.Second

type DeploymentClient interface {
	RelayDeployment(context.Context, string, string) (relaycatalog.DeploymentView, error)
}

func (s *DeploymentStore) Refresh(ctx context.Context, client DeploymentClient) (DeploymentReport, error) {
	if !s.mu.TryLock() {
		return s.busyReport(), ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return DeploymentReport{}, osClosed()
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDeploymentRefreshDuration)
	defer cancel()
	if s.uncertain {
		if e := s.repair(); e != nil {
			return s.report(), e
		}
	}
	if s.clockRegressed() {
		return s.fail("rejected", "clock_regressed", true, errors.New("local clock moved backwards"))
	}
	next := s.state
	// A prior process may have received a denial before dying or failing to
	// persist it. Only a fresh accepted response can clear this uncertainty.
	if next.Refresh.Result == "in_progress" && next.BlockedReason == "" {
		next.BlockedReason = "refresh_interrupted"
	}
	next.Refresh.Result, next.Refresh.Reason = "in_progress", "refresh_interrupted"
	next.Refresh.AttemptedAt, next.Refresh.CompletedAt = s.now().UTC(), time.Time{}
	if e := s.save(next); e != nil {
		return s.report(), e
	}
	if e := ctx.Err(); e != nil {
		return s.remoteFailure(e)
	}
	v, e := client.RelayDeployment(ctx, s.principal, s.relay)
	if e != nil {
		return s.remoteFailure(e)
	}
	if e = ctx.Err(); e != nil {
		return s.remoteFailure(e)
	}
	if e = s.accept(v); e != nil {
		if s.uncertain {
			return s.report(), e
		}
		return s.fail("rejected", "deployment_rejected", true, e)
	}
	return s.report(), nil
}

func (s *DeploymentStore) accept(v relaycatalog.DeploymentView) error {
	if e := v.Validate(s.principal, s.relay, s.currentTime()); e != nil {
		return e
	}
	hash := deploymentDigest(v)
	if s.state.ControllerID != "" {
		if v.ControllerID != s.state.ControllerID {
			return errors.New("deployment controller identity changed")
		}
		if v.Generation < s.state.Generation {
			return errors.New("deployment generation moved backwards")
		}
		if v.Generation == s.state.Generation && hash != s.state.ViewDigest {
			return errors.New("deployment changed within the same generation")
		}
	}
	// Remember a structurally valid higher revision even when it violates a
	// transition invariant. An older response must never restore authorization.
	if v.Generation > s.state.Generation {
		next := s.state
		next.ControllerID, next.Generation, next.ViewDigest = v.ControllerID, v.Generation, hash
		next.BlockedReason = "pending_validation"
		if e := s.save(next); e != nil {
			return e
		}
	}
	if old := s.state.Deployment; old != nil {
		if old.Spec.PoolCIDR != v.Spec.PoolCIDR {
			return errors.New("deployment pool changed within controller identity")
		}
		a, b := old.Spec.Relays[0], v.Spec.Relays[0]
		if b.KeyGeneration < a.KeyGeneration || b.KeyGeneration == a.KeyGeneration && b.PublicKey != a.PublicKey {
			return errors.New("relay key changed without a newer key generation")
		}
	}
	next := s.state
	copy := copyDeployment(v)
	next.Deployment = &copy
	next.BlockedReason = ""
	next.Refresh.Result, next.Refresh.Reason = "success", ""
	next.Refresh.CompletedAt = s.now().UTC()
	next.Refresh.LastSuccessAt = next.Refresh.CompletedAt
	return s.save(next)
}

func (s *DeploymentStore) fail(result, reason string, block bool, cause error) (DeploymentReport, error) {
	next := s.state
	next.Refresh.Result, next.Refresh.Reason = result, reason
	next.Refresh.CompletedAt = s.now().UTC()
	if block {
		next.BlockedReason = reason
	}
	if e := s.save(next); e != nil {
		return s.report(), errors.Join(cause, e)
	}
	return s.report(), cause
}

func (s *DeploymentStore) remoteFailure(e error) (DeploymentReport, error) {
	var h *api.HTTPError
	if errors.As(e, &h) {
		if h.StatusCode == 401 || h.StatusCode == 403 {
			return s.fail("denied", "identity_or_grant_denied", true, errors.New("controller rejected relay identity or grant"))
		}
		if h.Code == "relay_catalog_uncertain" {
			return s.fail("rejected", "controller_uncertain", true, errors.New("controller catalog durability is uncertain"))
		}
		if h.Code == "relay_catalog_expired" {
			return s.fail("rejected", "catalog_expired", true, relaycatalog.ErrExpired)
		}
		if h.StatusCode >= 500 || h.StatusCode == 429 {
			return s.fail("unavailable", "controller_unavailable", false, errors.New("controller unavailable"))
		}
		return s.fail("rejected", "controller_rejected", true, errors.New("controller rejected deployment request"))
	}
	if errors.Is(e, relaycatalog.ErrExpired) {
		return s.fail("rejected", "catalog_expired", true, relaycatalog.ErrExpired)
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
		return s.fail("unavailable", "transport_unavailable", false, errors.New("deployment refresh interrupted or unavailable"))
	}
	return s.fail("rejected", "invalid_response_or_credentials", true, errors.New("deployment response or local credentials failed validation"))
}
