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
)

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req api.EventRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid event request")
		return
	}
	if !s.authorizeNode(w, r, req.NodeID) {
		return
	}
	if !s.nodeRegistered(req.NodeID) {
		writeJSONError(w, http.StatusForbidden, "reporter is not registered")
		return
	}
	storage, ok := s.history.(history.EventStorage)
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable, "event history unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := storage.IngestEvent(ctx, req.NodeID, req.Event, time.Now()); err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, history.ErrInvalid) {
			code = http.StatusBadRequest
		} else if errors.Is(err, history.ErrConflict) {
			code = http.StatusConflict
		}
		writeJSONError(w, code, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuthorizedEvents(w http.ResponseWriter, r *http.Request) {
	admitted := false
	s.requireClientCert(func(http.ResponseWriter, *http.Request) { admitted = true })(w, r)
	if !admitted {
		return
	}
	buffer := &historyResponseBuffer{header: make(http.Header)}
	s.handleFleetEvents(buffer, r)
	s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) {
		for k, values := range buffer.header {
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})(w, r)
}

func (s *Server) handleFleetEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	node := r.URL.Query().Get("node_id")
	if !s.nodeRegistered(node) {
		if node == "" {
			writeJSONError(w, http.StatusBadRequest, "node_id required")
		} else {
			writeJSONError(w, http.StatusNotFound, "node not found")
		}
		return
	}
	window, err := parseEventWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid window")
		return
	}
	limit := 500
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid limit")
			return
		}
	}
	storage, ok := s.history.(history.EventStorage)
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable, "event history unavailable")
		return
	}
	out, err := storage.QueryEvents(r.Context(), node, time.Now(), window, limit)
	if err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, history.ErrInvalid) {
			code = http.StatusBadRequest
		}
		writeJSONError(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuthorizedAlerts(w http.ResponseWriter, r *http.Request) {
	admitted := false
	s.requireClientCert(func(http.ResponseWriter, *http.Request) { admitted = true })(w, r)
	if !admitted {
		return
	}
	buffer := &historyResponseBuffer{header: make(http.Header)}
	s.handleFleetAlerts(buffer, r)
	s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) {
		for k, values := range buffer.header {
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})(w, r)
}

func (s *Server) handleFleetAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	node := r.URL.Query().Get("node_id")
	if !s.nodeRegistered(node) {
		if node == "" {
			writeJSONError(w, http.StatusBadRequest, "node_id required")
		} else {
			writeJSONError(w, http.StatusNotFound, "node not found")
		}
		return
	}
	storage, ok := s.history.(history.EventStorage)
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable, "event history unavailable")
		return
	}
	out, err := storage.Alerts(r.Context(), node, time.Now())
	if err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, history.ErrInvalid) {
			code = http.StatusBadRequest
		}
		writeJSON(w, code, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func parseEventWindow(raw string) (time.Duration, error) {
	if raw == "" {
		return 24 * time.Hour, nil
	}
	if raw == "7d" {
		raw = "168h"
	}
	return time.ParseDuration(raw)
}
