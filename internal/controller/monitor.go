// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/store"
)

func validateObservationEpoch(epoch string) error {
	if epoch == "" {
		return nil // Legacy registry.
	}
	b, err := hex.DecodeString(epoch)
	if err != nil || len(b) != 16 {
		return fmt.Errorf("invalid observation epoch")
	}
	return nil
}

func newObservationEpoch() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
func monitorPeer(n store.NodeInfo) api.MonitorPeer {
	epoch := n.ObservationEpoch
	if epoch == "" {
		// Legacy v1 registries keep a stable binding across restarts. The first
		// key/IP mutation writes a random epoch, including an A->B->A transition.
		b, _ := json.Marshal([]string{n.ID, n.PubKey, n.VPNIP})
		sum := sha256.Sum256(b)
		epoch = hex.EncodeToString(sum[:])
	}
	return api.MonitorPeer{NodeID: n.ID, PublicKey: n.PubKey, VPNIP: strings.SplitN(n.VPNIP, "/", 2)[0], Epoch: epoch}
}
func (s *Server) monitorAuthorized(w http.ResponseWriter, r *http.Request, node string) bool {
	if !s.mtlsEnabled() {
		writeJSONError(w, 403, "monitor history requires mTLS")
		return false
	}
	return s.authorizeNode(w, r, node)
}
func (s *Server) handleMonitorPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	node := r.URL.Query().Get("node_id")
	if !s.monitorAuthorized(w, r, node) {
		return
	}
	s.mu.Lock()
	out := api.MonitorPeersResponse{SchemaVersion: 1, Peers: []api.MonitorPeer{}}
	for _, n := range s.reg.Nodes {
		if n.ID == node || n.EnrollmentPending || n.PubKey == "" || n.VPNIP == "" {
			continue
		}
		out.Peers = append(out.Peers, monitorPeer(n))
		if len(out.Peers) > api.MaxMonitorPeers {
			s.mu.Unlock()
			writeJSONError(w, 503, "monitor peer catalog exceeds capacity")
			return
		}
	}
	s.mu.Unlock()
	writeJSON(w, 200, out)
}
func (s *Server) handleMonitorMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	var req api.MonitorMetricsRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	if !s.monitorAuthorized(w, r, req.NodeID) {
		return
	}
	o := req.Observation
	if o.Source != "monitor-overlay" || o.Path != "unknown" || o.RelayID != "" || o.Uplink != "" || o.PeerID != req.Peer.NodeID || o.PeerID == req.NodeID {
		writeJSONError(w, 400, "monitor requires a bound peer and an unconfirmed path")
		return
	}
	s.mu.Lock()
	matched := false
	for _, n := range s.reg.Nodes {
		if n.ID == o.PeerID && !n.EnrollmentPending && n.PubKey != "" && n.VPNIP != "" && monitorPeer(n) == req.Peer {
			matched = true
			break
		}
	}
	s.mu.Unlock()
	if !matched {
		writeJSON(w, 409, api.ErrorResponse{Code: "monitor_binding_changed", Error: "peer identity changed or is no longer registered"})
		return
	}
	// Deletion/revocation drain this admitted request through requireClientCert.
	// Key changes after admission do not retag the captured peer or observation.
	s.ingestObservations(w, r, api.MetricsRequest{NodeID: req.NodeID, Observations: []history.Observation{o}})
}
