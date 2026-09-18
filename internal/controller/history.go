// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"

	"errors"
	"log/slog"
	"net/http"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/quality"
	"vpnctl/internal/store"
	"vpnctl/internal/uplink"
)

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request, req api.MetricsRequest) {
	if len(req.Samples) > 0 {
		writeJSONError(w, 400, "use observations or legacy samples, not both")
		return
	}
	if len(req.Observations) > history.MaxBatch {
		writeJSONError(w, 400, "observation batch exceeds 256")
		return
	}
	// Even development/no-TLS mode must refer to a registered reporter.
	s.mu.Lock()
	registered := false
	for _, n := range s.reg.Nodes {
		if n.ID == req.NodeID {
			registered = true
			break
		}
	}
	s.mu.Unlock()
	if !registered {
		writeJSONError(w, 403, "reporter is not registered")
		return
	}
	for _, o := range req.Observations {
		if !s.authorizePeer(w, req.NodeID, o.PeerID) {
			return
		}
		if o.RelayID != "" && o.RelayID != "controller" && !s.authorizePeer(w, req.NodeID, o.RelayID) {
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.history.Ingest(ctx, req.NodeID, req.Observations, time.Now()); err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, history.ErrInvalid) {
			code = http.StatusBadRequest
		}
		if errors.Is(err, history.ErrConflict) {
			code = http.StatusConflict
		}
		writeJSONError(w, code, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) fleetNodes() []store.NodeInfo {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	observeStage("fleet", "registry_wait", start)
	return append([]store.NodeInfo(nil), s.reg.Nodes...)
}
func (s *Server) fleetSnapshot() api.FleetStatusResponse {
	nodes := s.fleetNodes()
	latest := s.history.Latest(time.Time{})
	uplinks := map[string]uplink.Snapshot{}
	if store, ok := s.history.(uplinkStorage); ok {
		uplinks = store.LatestUplinks(time.Time{})
	}
	resp := api.FleetStatusResponse{SchemaVersion: 2, Nodes: []api.FleetNodeStatus{}}
	now := time.Now()
	for _, node := range nodes {
		m := history.Measurement{Stream: history.Stream{NodeID: node.ID}, PeerQuality: quality.ReplayQuality(nil)}
		measurements := latest[node.ID]
		if measurements == nil {
			measurements = []history.Measurement{}
		}
		if len(measurements) > 0 {
			m = measurements[0]
		}
		seen := ""
		if !node.LastSeenAt.IsZero() {
			seen = node.LastSeenAt.Format(time.RFC3339)
		}
		var observation *uplink.Snapshot
		if value, ok := uplinks[node.ID]; ok {
			observation = &value
		}
		resp.Nodes = append(resp.Nodes, api.FleetNodeStatus{UplinkObservation: observation, Measurement: m, Name: node.Name, VPNIP: node.VPNIP, NATType: node.NATType, LastSeen: seen, Status: fleetNodeState(node, now), Measurements: measurements})
	}
	return resp
}

func (s *Server) handleFleetHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	window := time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if v == "7d" {
			v = "168h"
		}
		var err error
		window, err = time.ParseDuration(v)
		if err != nil {
			writeJSONError(w, 400, "invalid window")
			return
		}
	}
	width := history.DefaultWidth(window)
	if v := r.URL.Query().Get("bucket"); v != "" {
		var err error
		width, err = time.ParseDuration(v)
		if err != nil {
			writeJSONError(w, 400, "invalid bucket")
			return
		}
	}
	if err := history.ValidateQuery(window, width); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	nodes := s.fleetNodes()
	found := nodeID == ""
	for _, n := range nodes {
		if n.ID == nodeID {
			found = true
		}
	}
	if !found {
		writeJSONError(w, 404, "node not found")
		return
	}
	end := time.Now().UTC().Truncate(time.Microsecond)
	buckets, err := s.history.Query(r.Context(), nodeID, end, window, width)
	if err != nil {
		writeJSONError(w, 503, err.Error())
		return
	}
	byNode := map[string][]history.Bucket{}
	for _, b := range buckets {
		byNode[b.NodeID] = append(byNode[b.NodeID], b)
	}
	resp := api.FleetHistoryResponse{SchemaVersion: 2, Start: end.Add(-window), End: end, BucketSeconds: width.Seconds(), RetentionSeconds: history.Retention.Seconds(), Nodes: []api.FleetNodeHistory{}}
	for _, n := range nodes {
		if nodeID != "" && nodeID != n.ID {
			continue
		}
		bs := byNode[n.ID]
		if bs == nil {
			bs = []history.Bucket{}
		}
		resp.Nodes = append(resp.Nodes, api.FleetNodeHistory{NodeID: n.ID, Name: n.Name, Buckets: bs})
	}
	writeJSON(w, 200, resp)
}
func (s *Server) startHistoryMaintenance() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				work, stop := context.WithTimeout(ctx, history.QueryTimeout)
				err := s.history.Maintain(work, now)
				stop()
				if err != nil && ctx.Err() == nil {
					slog.Error("fleet history retention failed", "error", err)
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

// Long history reads run outside admission's state lock. They are authenticated
// both before querying and immediately before publication, so a revoked/removed
// caller cannot receive results after the security transition commits.
func (s *Server) handleAuthorizedFleetHistory(w http.ResponseWriter, r *http.Request) {
	admitted := false
	s.requireClientCert(func(_ http.ResponseWriter, _ *http.Request) { admitted = true })(w, r)
	if !admitted {
		return
	}
	result := &historyResponseBuffer{header: make(http.Header)}
	s.handleFleetHistory(result, r)
	s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) {
		for k, vs := range result.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(result.status)
		_, _ = w.Write(result.body.Bytes())
	})(w, r)
}

type historyResponseBuffer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *historyResponseBuffer) Header() http.Header { return b.header }
func (b *historyResponseBuffer) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}
func (b *historyResponseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}
