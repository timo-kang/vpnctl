// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

// Server provides the controller HTTP API.
type Server struct {
	cfg     config.ControllerConfig
	regPath string
	mu      sync.Mutex
	reg     *store.Registry
	// metricsMu serializes appends to the metrics CSV to avoid interleaved writes
	// when multiple nodes submit samples concurrently.
	metricsMu sync.Mutex
	wg        *wireguard.Manager
	// directOK tracks recent direct probe successes reported by nodes.
	// Used to gate P2P WireGuard /32 injection so relay doesn't get blackholed.
	directOK       map[string]map[string]time.Time // node_id -> peer_id -> last success
	probeResponder *direct.Responder
	tokenStore     *pki.TokenStore
	pkiDir         string
}

// NewServer constructs a controller server.
func NewServer(cfg config.ControllerConfig) (*Server, error) {
	regPath := filepath.Join(cfg.DataDir, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		return nil, err
	}
	// Backward/forward compatibility: older registries might not have IDs.
	// Keep IDs stable so callers can consistently use node_id.
	changed := false
	for i := range reg.Nodes {
		if reg.Nodes[i].ID == "" && reg.Nodes[i].Name != "" {
			reg.Nodes[i].ID = reg.Nodes[i].Name
			changed = true
		}
		if reg.Nodes[i].Name == "" && reg.Nodes[i].ID != "" {
			reg.Nodes[i].Name = reg.Nodes[i].ID
			changed = true
		}
	}
	if changed {
		if err := store.SaveRegistry(regPath, reg); err != nil {
			return nil, err
		}
	}
	return &Server{
		cfg:      cfg,
		regPath:  regPath,
		reg:      reg,
		wg:       wireguard.DefaultManager(),
		directOK: make(map[string]map[string]time.Time),
	}, nil
}

// InitPKI initialises the PKI directory, generates the CA and server certificate
// if they don't exist, opens the bootstrap token store, and creates an initial
// token when the store is empty. The returned string is the bootstrap token if
// one was freshly created (empty otherwise).
func (s *Server) InitPKI() (string, error) {
	if s.cfg.PKI == nil {
		return "", fmt.Errorf("controller.pki config section is required")
	}

	pkiDir := filepath.Join(s.cfg.DataDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		return "", fmt.Errorf("create pki dir: %w", err)
	}
	s.pkiDir = pkiDir

	caKeyPath := filepath.Join(pkiDir, "ca.key")
	caCertPath := filepath.Join(pkiDir, "ca.crt")

	// Generate CA if it doesn't exist.
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		caExpiry, err := time.ParseDuration(s.cfg.PKI.CAExpiry)
		if err != nil {
			return "", fmt.Errorf("parse ca_expiry: %w", err)
		}
		if err := pki.GenerateCA(caKeyPath, caCertPath, caExpiry); err != nil {
			return "", fmt.Errorf("generate CA: %w", err)
		}
		slog.Info("generated CA certificate", "path", caCertPath)
	}

	serverKeyPath := filepath.Join(pkiDir, "server.key")
	serverCertPath := filepath.Join(pkiDir, "server.crt")

	// Generate server cert if it doesn't exist.
	if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
		serverExpiry, err := time.ParseDuration(s.cfg.PKI.ServerExpiry)
		if err != nil {
			return "", fmt.Errorf("parse server_expiry: %w", err)
		}
		sans := extractSANs(s.cfg.Listen)
		if err := pki.GenerateServerCert(caCertPath, caKeyPath, serverKeyPath, serverCertPath, sans, serverExpiry); err != nil {
			return "", fmt.Errorf("generate server cert: %w", err)
		}
		slog.Info("generated server certificate", "path", serverCertPath, "sans", sans)
	}

	// Open token store.
	tokenPath := filepath.Join(pkiDir, "bootstrap-tokens.json")
	ts, err := pki.OpenTokenStore(tokenPath)
	if err != nil {
		return "", fmt.Errorf("open token store: %w", err)
	}
	s.tokenStore = ts

	// Create initial bootstrap token if store is empty.
	var bootstrapToken string
	if len(ts.List()) == 0 {
		bootstrapToken = ts.Create()
		slog.Info("created initial bootstrap token")
	}

	return bootstrapToken, nil
}

// extractSANs parses the host part of a listen address and returns suitable
// SANs for the server certificate. If the host is empty, it adds "127.0.0.1"
// and "localhost".
func extractSANs(listen string) []string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return []string{"127.0.0.1", "localhost"}
	}
	return []string{host}
}

// ListenAndServe runs the HTTP server.
func (s *Server) ListenAndServe() error {
	if s.cfg.ProbePort > 0 {
		addr, err := s.StartProbeResponder()
		if err != nil {
			return fmt.Errorf("probe responder: %w", err)
		}
		slog.Info("probe responder listening", "addr", addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/bootstrap", s.handleBootstrap)
	mux.HandleFunc("/register", s.requireClientCert(s.handleRegister))
	mux.HandleFunc("/candidates", s.requireClientCert(s.handleCandidates))
	mux.HandleFunc("/metrics", s.requireClientCert(s.handleMetrics))
	mux.HandleFunc("/nat-probe", s.requireClientCert(s.handleNATProbe))
	mux.HandleFunc("/direct-result", s.requireClientCert(s.handleDirectResult))
	mux.HandleFunc("/wg-config", s.requireClientCert(s.handleWGConfig))
	mux.HandleFunc("/fleet/status", s.requireClientCert(s.handleFleetStatus))
	mux.HandleFunc("/fleet/history", s.requireClientCert(s.handleFleetHistory))

	server := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if s.cfg.PKI != nil && s.pkiDir != "" {
		tlsCfg, err := pki.ServerTLSConfig(
			filepath.Join(s.pkiDir, "ca.crt"),
			filepath.Join(s.pkiDir, "server.crt"),
			filepath.Join(s.pkiDir, "server.key"),
		)
		if err != nil {
			return fmt.Errorf("server TLS config: %w", err)
		}
		// Allow /bootstrap to work without a client cert. The
		// requireClientCert middleware enforces client certs for all
		// other endpoints.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		server.TLSConfig = tlsCfg
		slog.Info("controller listening (mTLS)", "addr", s.cfg.Listen)
		return server.ListenAndServeTLS("", "")
	}

	slog.Info("controller listening", "addr", s.cfg.Listen)
	return server.ListenAndServe()
}

// StartProbeResponder starts a UDP probe responder for health checks.
func (s *Server) StartProbeResponder() (string, error) {
	addr := fmt.Sprintf(":%d", s.cfg.ProbePort)
	resp, err := direct.StartResponder(addr)
	if err != nil {
		return "", err
	}
	s.probeResponder = resp
	return resp.LocalAddr(), nil
}

// StopProbeResponder stops the probe responder if running.
func (s *Server) StopProbeResponder() {
	if s.probeResponder != nil {
		_ = s.probeResponder.Close()
		s.probeResponder = nil
	}
}

// requireClientCert wraps a handler and rejects requests without a valid
// client certificate when mTLS is configured.
func (s *Server) requireClientCert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.PKI != nil && s.pkiDir != "" {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client certificate required", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// handleBootstrap handles POST /bootstrap for node enrollment via token + CSR.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req api.BootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Token == "" || req.Name == "" || req.CSR == "" {
		writeJSONError(w, http.StatusBadRequest, "token, name, and csr are required")
		return
	}

	// Validate token.
	if s.tokenStore == nil || !s.tokenStore.Validate(req.Token) {
		writeJSONError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}

	// Load CA and sign the CSR.
	caKeyPath := filepath.Join(s.pkiDir, "ca.key")
	caCertPath := filepath.Join(s.pkiDir, "ca.crt")
	caCert, caKey, err := pki.LoadCA(caKeyPath, caCertPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load CA: "+err.Error())
		return
	}

	clientExpiry, err := time.ParseDuration(s.cfg.PKI.ClientExpiry)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "invalid client_expiry: "+err.Error())
		return
	}

	signedCert, err := pki.SignCSR(caCert, caKey, []byte(req.CSR), clientExpiry)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to sign CSR: "+err.Error())
		return
	}

	// Read CA cert PEM for the response.
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read CA cert: "+err.Error())
		return
	}

	// Register the node in the registry (reuse registration logic).
	nodeID, vpnIP := s.registerNodeLocked(req.Name, "" /* pubKey */, "" /* vpnIP */, "" /* endpoint */, 0 /* probePort */, "" /* publicAddr */, "" /* natType */)

	writeJSON(w, http.StatusOK, api.BootstrapResponse{
		CACert:     string(caCertPEM),
		ClientCert: string(signedCert),
		NodeID:     nodeID,
		VPNIP:      vpnIP,
	})
}

// registerNodeLocked registers or updates a node in the registry, allocating a
// VPN IP when one is not provided. It returns (nodeID, vpnIP). This method is
// shared by handleRegister and handleBootstrap.
func (s *Server) registerNodeLocked(name, pubKey, vpnIP, endpoint string, probePort int, publicAddr, natType string) (string, string) {
	now := time.Now().UTC()
	assignedVPNIP := vpnIP

	s.mu.Lock()
	defer s.mu.Unlock()

	if assignedVPNIP == "" {
		var err error
		assignedVPNIP, err = allocateVPNIP(s.cfg.VPNCIDR, s.reg)
		if err != nil {
			return name, ""
		}
	}

	var nodeID string
	updated := false
	for i := range s.reg.Nodes {
		if s.reg.Nodes[i].Name == name {
			if s.reg.Nodes[i].ID == "" {
				s.reg.Nodes[i].ID = name
			}
			if pubKey != "" {
				s.reg.Nodes[i].PubKey = pubKey
			}
			s.reg.Nodes[i].VPNIP = assignedVPNIP
			if endpoint != "" {
				s.reg.Nodes[i].Endpoint = endpoint
			}
			s.reg.Nodes[i].ProbePort = probePort
			if publicAddr != "" {
				s.reg.Nodes[i].PublicAddr = publicAddr
			}
			if natType != "" {
				s.reg.Nodes[i].NATType = natType
			}
			s.reg.Nodes[i].LastSeenAt = now
			s.reg.Nodes[i].Status = "online"
			nodeID = s.reg.Nodes[i].ID
			updated = true
			break
		}
	}

	if !updated {
		nodeID = name
		s.reg.Nodes = append(s.reg.Nodes, store.NodeInfo{
			ID:         nodeID,
			Name:       name,
			PubKey:     pubKey,
			VPNIP:      assignedVPNIP,
			Endpoint:   endpoint,
			ProbePort:  probePort,
			PublicAddr: publicAddr,
			NATType:    natType,
			LastSeenAt: now,
			Status:     "online",
		})
	}

	_ = store.SaveRegistry(s.regPath, s.reg)
	return nodeID, assignedVPNIP
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
	assignedVPNIP := req.VPNIP

	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()

	if assignedVPNIP == "" {
		var err error
		assignedVPNIP, err = allocateVPNIP(s.cfg.VPNCIDR, s.reg)
		if err != nil {
			// Important: never return while holding the registry lock.
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	var nodeID string
	updated := false
	for i := range s.reg.Nodes {
		if s.reg.Nodes[i].Name == req.Name {
			if s.reg.Nodes[i].ID == "" {
				s.reg.Nodes[i].ID = req.Name
			}
			s.reg.Nodes[i].PubKey = req.PubKey
			s.reg.Nodes[i].VPNIP = assignedVPNIP
			s.reg.Nodes[i].Endpoint = req.Endpoint
			s.reg.Nodes[i].ProbePort = req.ProbePort
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
			VPNIP:      assignedVPNIP,
			Endpoint:   req.Endpoint,
			ProbePort:  req.ProbePort,
			PublicAddr: req.PublicAddr,
			NATType:    req.NATType,
			LastSeenAt: now,
			Status:     "online",
		})
	}

	if err := store.SaveRegistry(s.regPath, s.reg); err != nil {
		s.mu.Unlock()
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	autoApply := s.cfg.WGApply
	peers := s.peersForWGLocked()
	resp := api.RegisterResponse{
		NodeID: nodeID,
		Peers:  s.peersLocked(nodeID),
		VPNIP:  assignedVPNIP,
	}

	s.mu.Unlock()
	locked = false

	// Fill observed WireGuard endpoints for candidates (best-effort).
	s.fillObservedEndpoints(resp.Peers)

	if autoApply {
		if err := applyWG(s.cfg, peers); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
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
	peers := s.peersLocked(nodeID)
	s.mu.Unlock()

	s.fillObservedEndpoints(peers)

	resp := api.CandidatesResponse{Peers: peers}
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

	// AppendCSV is not safe for concurrent use across processes/goroutines because
	// CSV writes are buffered and can interleave. Serialize appends in-process.
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
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

	if req.NodeID != "" && req.PeerID != "" && req.Success {
		s.mu.Lock()
		m := s.directOK[req.NodeID]
		if m == nil {
			m = make(map[string]time.Time)
			s.directOK[req.NodeID] = m
		}
		m[req.PeerID] = time.Now().UTC()
		s.mu.Unlock()
	}

	slog.Debug("direct result", "node", req.NodeID, "peer", req.PeerID, "success", req.Success, "rtt_ms", req.RTTMs, "reason", req.Reason)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWGConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.cfg.ServerPublicKey == "" || s.cfg.ServerEndpoint == "" || len(s.cfg.ServerAllowedIPs) == 0 {
		slog.Warn("wg-config: server config not set", "has_public_key", s.cfg.ServerPublicKey != "", "has_endpoint", s.cfg.ServerEndpoint != "", "allowed_ips_count", len(s.cfg.ServerAllowedIPs))
		writeJSONError(w, http.StatusInternalServerError, "server config not set")
		return
	}

	resp := api.WGConfigResponse{
		ServerPublicKey:    s.cfg.ServerPublicKey,
		ServerEndpoint:     s.cfg.ServerEndpoint,
		ServerAllowedIPs:   s.cfg.ServerAllowedIPs,
		ServerKeepaliveSec: s.cfg.ServerKeepaliveSec,
		ServerProbePort:    s.cfg.ProbePort,
	}
	writeJSON(w, http.StatusOK, resp)
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
			ProbePort:  node.ProbePort,
			P2PReady:   s.p2pReadyLocked(nodeID, node.ID),
		})
	}
	return peers
}

func (s *Server) p2pReadyLocked(a, b string) bool {
	// Require mutual direct probe success within TTL.
	const ttl = 2 * time.Minute
	now := time.Now().UTC()

	ab := s.directOK[a]
	ba := s.directOK[b]
	if ab == nil && ba == nil {
		return false
	}
	t1, ok1 := ab[b]
	t2, ok2 := ba[a]
	switch strings.ToLower(strings.TrimSpace(s.cfg.P2PReadyMode)) {
	case "either":
		if ok1 && now.Sub(t1) <= ttl {
			return true
		}
		if ok2 && now.Sub(t2) <= ttl {
			return true
		}
		return false
	default: // mutual
		if !ok1 || !ok2 {
			return false
		}
		if now.Sub(t1) > ttl || now.Sub(t2) > ttl {
			return false
		}
		return true
	}
}

func (s *Server) fillObservedEndpoints(peers []api.PeerCandidate) {
	if s == nil || s.wg == nil || s.cfg.WGInterface == "" {
		return
	}
	m, err := s.wg.PeerEndpoints(s.cfg.WGInterface)
	if err != nil || len(m) == 0 {
		return
	}
	for i := range peers {
		// If the node explicitly advertised an endpoint (e.g. port-forwarded), don't override it.
		if peers[i].Endpoint != "" {
			continue
		}
		if peers[i].PubKey == "" {
			continue
		}
		if ep := m[peers[i].PubKey]; ep != "" {
			peers[i].Endpoint = ep
		}
	}
}

func (s *Server) handleFleetStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var nodes []api.FleetNodeStatus
	for _, node := range s.reg.Nodes {
		lastSeen := ""
		if !node.LastSeenAt.IsZero() {
			lastSeen = node.LastSeenAt.Format(time.RFC3339)
		}
		nodes = append(nodes, api.FleetNodeStatus{
			Name:     node.Name,
			VPNIP:    node.VPNIP,
			NATType:  node.NATType,
			LastSeen: lastSeen,
		})
	}
	writeJSON(w, http.StatusOK, api.FleetStatusResponse{Nodes: nodes})
}

func (s *Server) handleFleetHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var nodes []api.FleetNodeHistory
	for _, node := range s.reg.Nodes {
		nodes = append(nodes, api.FleetNodeHistory{
			Name:    node.Name,
			Buckets: []api.FleetHistoryBucket{},
		})
	}
	writeJSON(w, http.StatusOK, api.FleetHistoryResponse{Nodes: nodes})
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

func (s *Server) peersForWGLocked() []wireguard.Peer {
	peers := make([]wireguard.Peer, 0, len(s.reg.Nodes))
	for _, node := range s.reg.Nodes {
		if node.PubKey == "" || node.VPNIP == "" {
			continue
		}
		allowed := normalizeHostCIDR(node.VPNIP)
		if allowed == "" {
			continue
		}
		peers = append(peers, wireguard.Peer{
			PublicKey:  node.PubKey,
			AllowedIPs: []string{allowed},
		})
	}
	return peers
}

func normalizeHostCIDR(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "/") {
		return value
	}
	return value + "/32"
}

func applyWG(cfg config.ControllerConfig, peers []wireguard.Peer) error {
	serverCfg := wireguard.ServerConfig{
		Interface:  cfg.WGInterface,
		PrivateKey: cfg.WGPrivateKey,
		Address:    cfg.WGAddress,
		ListenPort: cfg.WGPort,
		MTU:        cfg.MTU,
	}
	return wireguard.ApplyServer(serverCfg, peers)
}

func allocateVPNIP(cidr string, reg *store.Registry) (string, error) {
	if cidr == "" {
		return "", fmt.Errorf("vpn_cidr is required for allocation")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("vpn_cidr must be IPv4")
	}

	used := map[netip.Addr]bool{}
	for _, node := range reg.Nodes {
		if node.VPNIP == "" {
			continue
		}
		p, err := netip.ParsePrefix(node.VPNIP)
		if err == nil {
			used[p.Addr()] = true
			continue
		}
		addr, err := netip.ParseAddr(node.VPNIP)
		if err == nil {
			used[addr] = true
		}
	}

	base := prefix.Masked().Addr()
	ones, bits := prefix.Bits(), 32
	size := 1 << uint(bits-ones)
	// Defensive: avoid accidentally iterating millions of addresses due to misconfiguration.
	// This controller is intended for small-ish overlays (tens to low thousands of nodes).
	if size > 1_048_576 {
		return "", fmt.Errorf("vpn_cidr %s is too large (size=%d)", cidr, size)
	}
	for i := 1; i < size-1; i++ { // skip network/broadcast
		addr := addIPv4(base, uint32(i))
		if !used[addr] {
			return addr.String() + "/32", nil
		}
	}
	return "", fmt.Errorf("no available vpn_ip in %s", cidr)
}

func addIPv4(base netip.Addr, offset uint32) netip.Addr {
	v := base.As4()
	val := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	val += offset
	return netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
}
