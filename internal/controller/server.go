package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/metrics"
	"vpnctl/internal/store"
)

// Server provides the controller HTTP API.
type Server struct {
	cfg     config.ControllerConfig
	regPath string
	mu      sync.Mutex
	reg     *store.Registry
}

// NewServer constructs a controller server.
func NewServer(cfg config.ControllerConfig) (*Server, error) {
	regPath := filepath.Join(cfg.DataDir, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, regPath: regPath, reg: reg}, nil
}

// ListenAndServe runs the HTTP server.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/candidates", s.handleCandidates)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/nat-probe", s.handleNATProbe)
	mux.HandleFunc("/direct-result", s.handleDirectResult)

	server := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("controller listening on %s", s.cfg.Listen)
	return server.ListenAndServe()
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req api.RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" || req.PubKey == "" {
		writeJSONError(w, http.StatusBadRequest, "name and pub_key are required")
		return
	}

	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	var nodeID string
	updated := false
	for i := range s.reg.Nodes {
		if s.reg.Nodes[i].Name == req.Name {
			s.reg.Nodes[i].PubKey = req.PubKey
			s.reg.Nodes[i].VPNIP = req.VPNIP
			s.reg.Nodes[i].Endpoint = req.Endpoint
			s.reg.Nodes[i].PublicAddr = req.PublicAddr
			s.reg.Nodes[i].NATType = req.NATType
			s.reg.Nodes[i].LastSeenAt = now
			s.reg.Nodes[i].Status = "online"
			nodeID = s.reg.Nodes[i].ID
			updated = true
			break
		}
	}

	if !updated {
		nodeID = req.Name
		s.reg.Nodes = append(s.reg.Nodes, store.NodeInfo{
			ID:         nodeID,
			Name:       req.Name,
			PubKey:     req.PubKey,
			VPNIP:      req.VPNIP,
			Endpoint:   req.Endpoint,
			PublicAddr: req.PublicAddr,
			NATType:    req.NATType,
			LastSeenAt: now,
			Status:     "online",
		})
	}

	if err := store.SaveRegistry(s.regPath, s.reg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := api.RegisterResponse{
		NodeID: nodeID,
		Peers:  s.peersLocked(nodeID),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := api.CandidatesResponse{Peers: s.peersLocked(nodeID)}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req api.MetricsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Samples) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := s.cfg.MetricsPath
	if path == "" {
		path = filepath.Join(s.cfg.DataDir, "metrics.csv")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := metrics.AppendCSV(path, req.Samples); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNATProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req api.NATProbeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.NodeID == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.reg.Nodes {
		if s.reg.Nodes[i].ID == req.NodeID {
			s.reg.Nodes[i].NATType = req.NATType
			s.reg.Nodes[i].PublicAddr = req.PublicAddr
			s.reg.Nodes[i].LastSeenAt = time.Now().UTC()
			break
		}
	}

	if err := store.SaveRegistry(s.regPath, s.reg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDirectResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req api.DirectResultRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	log.Printf("direct result node=%s peer=%s success=%v rtt_ms=%.2f reason=%s", req.NodeID, req.PeerID, req.Success, req.RTTMs, req.Reason)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) peersLocked(nodeID string) []api.PeerCandidate {
	peers := make([]api.PeerCandidate, 0, len(s.reg.Nodes))
	for _, node := range s.reg.Nodes {
		if node.ID == nodeID {
			continue
		}
		peers = append(peers, api.PeerCandidate{
			ID:         node.ID,
			Name:       node.Name,
			PubKey:     node.PubKey,
			VPNIP:      node.VPNIP,
			Endpoint:   node.Endpoint,
			PublicAddr: node.PublicAddr,
			NATType:    node.NATType,
		})
	}
	return peers
}

func decodeJSON(r *http.Request, v any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
