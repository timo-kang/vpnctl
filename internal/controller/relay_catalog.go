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
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/store"
)

var errRelayUncertain = errors.New("registry durability uncertain; retry the last mutation before using relay catalog")

func relayEnvironment(reg *store.Registry, cfg config.ControllerConfig) relaycatalog.Environment {
	env := relaycatalog.Environment{VPNCIDR: cfg.VPNCIDR, Nodes: map[string]bool{}, ReservedKeys: map[string]bool{}}
	if cfg.ServerPublicKey != "" {
		env.ReservedKeys[relaycatalog.PublicKeyID(cfg.ServerPublicKey)] = true
	}
	for _, n := range reg.Nodes {
		env.Nodes[n.ID] = !n.EnrollmentPending
		if n.PubKey != "" {
			env.ReservedKeys[relaycatalog.PublicKeyID(n.PubKey)] = true
		}
	}
	return env
}
func validateRelayRegistry(reg *store.Registry, cfg config.ControllerConfig) error {
	if reg.RelayCatalog == nil {
		return nil
	}
	if cfg.PKI == nil {
		return fmt.Errorf("relay catalog requires controller PKI")
	}
	if e := reg.RelayCatalog.Validate(relayEnvironment(reg, cfg)); e != nil {
		return fmt.Errorf("registry relay catalog: %w", e)
	}
	return nil
}
func writeRelayError(w http.ResponseWriter, e error) {
	status, code := http.StatusInternalServerError, "relay_catalog_storage"
	message := "relay catalog operation failed; inspect controller logs"
	switch {
	case errors.Is(e, relaycatalog.ErrInvalid):
		status, code, message = 400, "relay_catalog_invalid", e.Error()
	case errors.Is(e, relaycatalog.ErrNotFound):
		status, code, message = 404, "relay_catalog_not_found", e.Error()
	case errors.Is(e, relaycatalog.ErrExpired):
		status, code, message = 409, "relay_catalog_expired", e.Error()
	case errors.Is(e, relaycatalog.ErrConflict):
		status, code, message = 409, "relay_catalog_conflict", e.Error()
	case errors.Is(e, relaycatalog.ErrCapacity):
		status, code, message = 409, "relay_catalog_capacity", e.Error()
	case errors.Is(e, errRelayUncertain):
		status, code, message = 503, "relay_catalog_uncertain", e.Error()
	}
	if status == 500 {
		slog.Error("relay catalog operation failed", "err", e)
	}
	writeJSON(w, status, api.ErrorResponse{Error: message, Code: code})
}
func (s *Server) adminRelayCatalog(r api.AdminRequest) (*relaycatalog.State, error) {
	if r.Operation == "relay.catalog.status" {
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.registryUncertain {
			return nil, errRelayUncertain
		}
		return s.reg.RelayCatalog, nil
	}
	if r.RelayCatalog == nil {
		return nil, fmt.Errorf("%w: relay_catalog update required", relaycatalog.ErrInvalid)
	}
	// Like existing administrator mutations, an admitted update completes even
	// after disconnect. Admission precedes stateMu so queued writers don't stall reads.
	release, _ := s.registryAdmission.admit(context.Background(), true, "registry_writer")
	defer release()
	s.mutationAdmission.RLock()
	defer s.mutationAdmission.RUnlock()
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authority == nil {
		return nil, fmt.Errorf("%w: PKI required", relaycatalog.ErrConflict)
	}
	if e := s.ensureRegistryDurableLocked(); e != nil {
		return nil, e
	}
	catalog, e := relaycatalog.Apply(s.reg.RelayCatalog, *r.RelayCatalog, relayEnvironment(s.reg, s.cfg), time.Now())
	if e != nil {
		return nil, e
	}
	next := cloneRegistry(s.reg)
	next.RelayCatalog = catalog
	if e = s.commitRegistryLocked(next, false); e != nil {
		return nil, e
	}
	slog.Info("relay catalog published", "generation", catalog.Generation, "paths", len(catalog.Spec.Paths), "expires_at", catalog.ExpiresAt)
	return catalog, nil
}
func (s *Server) relayNodeAuthorized(w http.ResponseWriter, r *http.Request, nodeID string) bool {
	// This new API always requires a verified identity, even if legacy HTTP APIs
	// are enabled. Query/body fields never establish authority.
	if _, ok := requestNodeIdentity(r); !ok {
		writeJSONError(w, 401, "relay catalog requires mTLS node identity")
		return false
	}
	return s.authorizeNode(w, r, nodeID)
}
func (s *Server) handleRelayCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "GET required")
		return
	}
	if r.URL.Query().Get("schema_version") != "1" {
		writeRelayError(w, fmt.Errorf("%w: schema_version=1 required", relaycatalog.ErrInvalid))
		return
	}
	id := r.URL.Query().Get("node_id")
	if !s.relayNodeAuthorized(w, r, id) {
		return
	}
	s.mu.Lock()
	catalog := s.reg.RelayCatalog
	uncertain := s.registryUncertain
	s.mu.Unlock()
	if uncertain {
		writeRelayError(w, errRelayUncertain)
		return
	}
	if catalog == nil {
		writeRelayError(w, relaycatalog.ErrNotFound)
		return
	}
	if !time.Now().Before(catalog.ExpiresAt) {
		writeRelayError(w, relaycatalog.ErrExpired)
		return
	}
	writeJSON(w, 200, catalog.NodeView(id))
}
func (s *Server) handleRelayBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "POST required")
		return
	}
	var req relaycatalog.BindRequest
	if e := decodeJSON(w, r, &req); e != nil {
		writeRelayError(w, fmt.Errorf("%w: invalid binding request", relaycatalog.ErrInvalid))
		return
	}
	if !s.relayNodeAuthorized(w, r, req.NodeID) {
		return
	}
	view, e := s.bindRelayPath(req)
	if e != nil {
		writeRelayError(w, e)
		return
	}
	writeJSON(w, 200, view)
}

func (s *Server) bindRelayPath(req relaycatalog.BindRequest) (relaycatalog.View, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ensureRegistryDurableLocked(); e != nil {
		return relaycatalog.View{}, e
	}
	catalog, e := relaycatalog.Bind(s.reg.RelayCatalog, req, relayEnvironment(s.reg, s.cfg), time.Now())
	if e != nil {
		return relaycatalog.View{}, e
	}
	if catalog != s.reg.RelayCatalog {
		next := cloneRegistry(s.reg)
		next.RelayCatalog = catalog
		if e = s.commitRegistryLocked(next, false); e != nil {
			return relaycatalog.View{}, e
		}
		slog.Info("relay path bound", "node_id", req.NodeID, "path_id", req.PathID, "generation", catalog.Generation)
	}
	return catalog.NodeView(req.NodeID), nil
}
