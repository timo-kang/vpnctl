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
	"vpnctl/internal/uplink"
)

type uplinkStorage interface {
	IngestUplink(context.Context, string, uplink.Snapshot, time.Time) error
	LatestUplinks(time.Time) map[string]uplink.Snapshot
	QueryUplinks(context.Context, string, time.Time, time.Duration, int) (history.UplinkHistory, error)
}

func (s *Server) handleUplinkObservation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	var req api.UplinkRequest
	r.Body = http.MaxBytesReader(w, r.Body, uplink.MaxSnapshotBytes+1024)
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, 400, "invalid uplink request")
		return
	}
	if !s.authorizeNode(w, r, req.NodeID) {
		return
	}
	registered := false
	for _, n := range s.fleetNodes() {
		if n.ID == req.NodeID {
			registered = true
			break
		}
	}
	if !registered {
		writeJSONError(w, 403, "reporter is not registered")
		return
	}
	storage, ok := s.history.(uplinkStorage)
	if !ok {
		writeJSONError(w, 503, "uplink history unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := storage.IngestUplink(ctx, req.NodeID, req.Snapshot, time.Now()); err != nil {
		code := 503
		if errors.Is(err, history.ErrInvalid) {
			code = 400
		}
		if errors.Is(err, history.ErrConflict) {
			code = 409
		}
		writeJSONError(w, code, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleAuthorizedUplinks(w http.ResponseWriter, r *http.Request) {
	admitted := false
	s.requireClientCert(func(http.ResponseWriter, *http.Request) { admitted = true })(w, r)
	if !admitted {
		return
	}
	buffer := &historyResponseBuffer{header: make(http.Header)}
	s.handleFleetUplinks(buffer, r)
	s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) {
		for k, vs := range buffer.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})(w, r)
}
func (s *Server) handleFleetUplinks(w http.ResponseWriter, r *http.Request) {
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
			break
		}
	}
	if !found {
		writeJSONError(w, 404, "node not found")
		return
	}
	window := time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if v == "7d" {
			v = "168h"
		}
		var e error
		window, e = time.ParseDuration(v)
		if e != nil {
			writeJSONError(w, 400, "invalid window")
			return
		}
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		var e error
		limit, e = strconv.Atoi(v)
		if e != nil {
			writeJSONError(w, 400, "invalid limit")
			return
		}
	}
	storage, ok := s.history.(uplinkStorage)
	if !ok {
		writeJSONError(w, 503, "uplink history unavailable")
		return
	}
	out, err := storage.QueryUplinks(r.Context(), node, time.Now(), window, limit)
	if err != nil {
		code := 503
		if errors.Is(err, history.ErrInvalid) {
			code = 400
		}
		writeJSONError(w, code, err.Error())
		return
	}
	writeJSON(w, 200, out)
}
