// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
)

func controllerPKIPolicy(cfg config.ControllerConfig) (pki.Policy, error) {
	var out pki.Policy
	if cfg.PKI == nil {
		return out, fmt.Errorf("PKI disabled")
	}
	if cfg.PKI.KeyAlgorithm != "" && cfg.PKI.KeyAlgorithm != "ecdsa-p256" {
		return out, fmt.Errorf("unsupported PKI key algorithm")
	}
	for _, field := range []struct {
		name, value string
		target      *time.Duration
	}{
		{"ca_expiry", cfg.PKI.CAExpiry, &out.CALifetime}, {"server_expiry", cfg.PKI.ServerExpiry, &out.ServerLifetime}, {"client_expiry", cfg.PKI.ClientExpiry, &out.ClientLifetime},
		{"server_renew_before", cfg.PKI.ServerRenewBefore, &out.ServerRenewBefore}, {"client_renew_before", cfg.PKI.ClientRenewBefore, &out.ClientRenewBefore}, {"check_interval", cfg.PKI.CheckInterval, &out.CheckInterval}, {"ca_overlap", cfg.PKI.CAOverlap, &out.CAOverlap},
	} {
		if field.value == "" {
			continue
		}
		parsed, err := time.ParseDuration(field.value)
		if err != nil || parsed <= 0 {
			return out, fmt.Errorf("invalid pki.%s", field.name)
		}
		*field.target = parsed
	}
	out.SANs = cfg.PKI.ServerSANs
	if len(out.SANs) == 0 {
		out.SANs = extractSANs(cfg.Listen)
	}
	return out, out.Defaults()
}

func publicTrust(status pki.AuthorityStatus) api.TrustState {
	return api.TrustState{Generation: status.Generation, CACert: status.CACert, Active: status.Active, Phase: status.Phase, RenewBeforeSeconds: status.RenewBeforeSeconds}
}

func (s *Server) handlePKITrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "GET required")
		return
	}
	if s.authority == nil {
		writeJSONError(w, 409, "PKI disabled")
		return
	}
	writeJSON(w, 200, publicTrust(s.authority.Status()))
}

func (s *Server) handlePKIRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "POST required")
		return
	}
	identity, ok := requestNodeIdentity(r)
	if s.authority == nil || !ok {
		writeJSONError(w, 403, "authenticated PKI identity required")
		return
	}
	var req api.RenewRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, 400, "invalid renewal request")
		return
	}
	if err := pki.ValidateCSR([]byte(req.CSR)); err != nil {
		writeJSONError(w, 400, "invalid CSR")
		return
	}
	cert, status, err := s.authority.Renew([]byte(req.CSR), identity.id, r.TLS.VerifiedChains[0][0])
	s.logPKIResult("renew", identity.id, err)
	if errors.Is(err, pki.ErrRenewalBlocked) {
		writeJSONError(w, 409, err.Error())
		return
	}
	if err != nil {
		writeJSONError(w, 503, "certificate renewal unavailable")
		return
	}
	writeJSON(w, 200, api.RenewResponse{TrustState: publicTrust(status), ClientCert: cert})
}

func (s *Server) handlePKIAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "POST required")
		return
	}
	identity, ok := requestNodeIdentity(r)
	if s.authority == nil || !ok {
		writeJSONError(w, 403, "authenticated PKI identity required")
		return
	}
	var req api.TrustAckRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, 400, "invalid trust acknowledgement")
		return
	}
	err := s.authority.Acknowledge(identity.id, r.TLS.VerifiedChains[0][0], req.Generation)
	if err != nil {
		s.logPKIResult("ack", identity.id, err)
		writeJSONError(w, 409, "trust acknowledgement failed; refresh and retry")
		return
	}
	// Acknowledgement proves the issued credential reached durable node storage.
	// Include this identity in future CA gates even before its first WG register.
	if err := s.confirmEnrollment(identity.id); err != nil {
		writeJSONError(w, 503, "enrollment confirmation unavailable; retry")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) confirmEnrollment(id string) error {
	// Most acknowledgements belong to active identities. Keep those reads isolated
	// from slow WG/registry writers, just like fleet/status.
	s.mu.Lock()
	needsCommit := s.registryUncertain
	for _, node := range s.reg.Nodes {
		if node.ID == id && node.EnrollmentPending {
			needsCommit = true
			break
		}
	}
	s.mu.Unlock()
	if !needsCommit {
		return nil
	}

	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureRegistryDurableLocked(); err != nil {
		return err
	}
	for i, node := range s.reg.Nodes {
		if node.ID == id && node.EnrollmentPending {
			next := cloneRegistry(s.reg)
			next.Nodes[i].EnrollmentPending = false
			next.Nodes[i].Status = "enrolled"
			return s.commitRegistryLocked(next, false)
		}
	}
	return nil
}

func (s *Server) logPKIResult(operation, target string, err error) {
	result := "success"
	if err != nil {
		result = "failed"
	}
	metrics.PKIEventsTotal.WithLabelValues("controller", operation, result).Inc()
	if err != nil {
		slog.Error("PKI operation", "operation", operation, "target", target, "result", result, "err", err)
	} else {
		slog.Info("PKI operation", "operation", operation, "target", target, "result", result)
	}
}

func (s *Server) updatePKIMetrics() float64 {
	status := s.authority.Status()
	metrics.PKIExpirySeconds.WithLabelValues("server").Set(time.Until(status.Server.ExpiresAt).Seconds())
	minCA := float64(0)
	for i, ca := range status.CAs {
		left := time.Until(ca.ExpiresAt).Seconds()
		if i == 0 || left < minCA {
			minCA = left
		}
	}
	metrics.PKIExpirySeconds.WithLabelValues("ca").Set(minCA)
	counts := map[string]float64{"active": 0, "expired": 0, "revoked": 0, "retired_ca": 0, "identity_removed": 0}
	s.mu.Lock()
	for _, cert := range status.Certificates {
		state := cert.Status
		if _, removed := s.reg.RemovedNodes[cert.NodeID]; removed {
			state = "identity_removed"
		}
		counts[state]++
	}
	s.mu.Unlock()
	for state, count := range counts {
		metrics.PKICertificates.WithLabelValues(state).Set(count)
	}
	overlap := float64(0)
	if status.Phase != "stable" {
		overlap = 1
	}
	metrics.PKIOverlap.Set(overlap)
	return minCA
}

func (s *Server) startPKIMaintenance() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(s.authority.CheckInterval())
		defer ticker.Stop()
		var lastCAWarning time.Time
		for {
			release, err := s.pkiAdmission.acquirePriority(ctx)
			if err != nil {
				return
			}
			s.mutationAdmission.RLock()
			s.stateMu.RLock()
			renewed, err := s.authority.MaintainServer()
			if renewed || err != nil {
				s.logPKIResult("server.renew", "controller", err)
			}
			caRemaining := s.updatePKIMetrics()
			if caRemaining < 30*24*3600 && time.Since(lastCAWarning) > time.Hour {
				lastCAWarning = time.Now()
				slog.Warn("CA expiry approaching", "remaining_seconds", caRemaining)
			}
			s.stateMu.RUnlock()
			s.mutationAdmission.RUnlock()
			release()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
