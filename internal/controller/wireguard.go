// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/wgstats"
)

type wireGuardStorage interface {
	IngestWireGuard(context.Context, wgstats.Report, time.Time) error
	LatestWireGuard(time.Time) map[string]wgstats.Snapshot
	QueryWireGuard(context.Context, string, time.Time, time.Duration, int) (history.WireGuardHistory, error)
}

func (s *Server) handleWireGuard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	var req wgstats.Report
	if e := decodeJSON(w, r, &req); e != nil {
		writeJSONError(w, 400, "invalid WireGuard report")
		return
	}
	if !s.monitorAuthorized(w, r, req.Reporter.NodeID) {
		return
	}
	if e := req.Validate(time.Now()); e != nil {
		writeJSONError(w, 400, e.Error())
		return
	}
	bindings := map[string]wgstats.Binding{}
	keys := map[string]bool{}
	for _, n := range s.fleetNodes() {
		keys[n.PubKey] = true
		if !n.EnrollmentPending {
			bindings[n.ID] = monitorPeer(n)
		}
	}
	matched := bindings[req.Reporter.NodeID] == req.Reporter
	for _, p := range req.Peers {
		if p.Peer.NodeID == "" {
			matched = matched && !keys[p.Peer.PublicKey]
		} else {
			matched = matched && bindings[p.Peer.NodeID] == p.Peer
		}
	}
	if !matched {
		writeJSON(w, 409, api.ErrorResponse{Code: "monitor_binding_changed", Error: "reporter or peer binding changed"})
		return
	}
	storage, ok := s.history.(wireGuardStorage)
	if !ok {
		writeJSONError(w, 503, "WireGuard history unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if e := storage.IngestWireGuard(ctx, req, time.Now()); e != nil {
		var quota *history.QuotaError
		if errors.As(e, &quota) {
			writeJSON(w, 503, api.ErrorResponse{Code: api.CodeHistoryQuota, Error: e.Error(), Resource: quota.Resource, Limit: quota.Limit})
			return
		}
		code := 503
		if errors.Is(e, history.ErrInvalid) {
			code = 400
		}
		if errors.Is(e, history.ErrConflict) {
			code = 409
		}
		writeJSONError(w, code, e.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleAuthorizedWireGuard(w http.ResponseWriter, r *http.Request) {
	admitted := false
	s.requireClientCert(func(http.ResponseWriter, *http.Request) { admitted = true })(w, r)
	if !admitted {
		return
	}
	buffer := &historyResponseBuffer{header: make(http.Header)}
	s.handleFleetWireGuard(buffer, r)
	s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) {
		// A removed subject must also disappear during a long query, independently
		// of whether the caller's own certificate remains admitted.
		found := false
		for _, n := range s.fleetNodes() {
			if n.ID == r.URL.Query().Get("node_id") {
				found = true
			}
		}
		if buffer.status == 200 && !found {
			writeJSONError(w, 404, "node not found")
			return
		}
		for k, vs := range buffer.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})(w, r)
}
func (s *Server) handleFleetWireGuard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	node := r.URL.Query().Get("node_id")
	if node == "" {
		writeJSONError(w, 400, "node_id required")
		return
	}
	found := false
	for _, n := range s.fleetNodes() {
		if n.ID == node {
			found = true
		}
	}
	if !found {
		writeJSONError(w, 404, "node not found")
		return
	}
	window := time.Hour
	var e error
	if v := r.URL.Query().Get("window"); v != "" {
		window, e = time.ParseDuration(v)
		if e != nil {
			writeJSONError(w, 400, "invalid window")
			return
		}
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, e = strconv.Atoi(v)
		if e != nil {
			writeJSONError(w, 400, "invalid limit")
			return
		}
	}
	storage, ok := s.history.(wireGuardStorage)
	if !ok {
		writeJSONError(w, 503, "WireGuard history unavailable")
		return
	}
	out, e := storage.QueryWireGuard(r.Context(), node, time.Now().UTC(), window, limit)
	if e != nil {
		code := 503
		if errors.Is(e, history.ErrInvalid) {
			code = 400
		}
		writeJSONError(w, code, e.Error())
		return
	}
	writeJSON(w, 200, out)
}
