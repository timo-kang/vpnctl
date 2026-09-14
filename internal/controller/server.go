// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
	"vpnctl/internal/statuspage"
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
	metricsMu    sync.Mutex
	wg           *wireguard.Manager
	saveRegistry func(string, *store.Registry) error
	// directOK tracks recent direct probe successes reported by nodes.
	// Used to gate P2P WireGuard /32 injection so relay doesn't get blackholed.
	directOK         map[string]map[string]time.Time // node_id -> peer_id -> last success
	probeResponder   *direct.Responder
	tokenStore       *pki.TokenStore
	pkiDir           string
	legacyCertLogged sync.Map
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
		cfg:          cfg,
		regPath:      regPath,
		reg:          reg,
		wg:           wireguard.DefaultManager(),
		saveRegistry: store.SaveRegistry,
		directOK:     make(map[string]map[string]time.Time),
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

	// Determine desired SANs: explicit config takes precedence; otherwise derive from listen addr.
	desiredSANs := s.cfg.PKI.ServerSANs
	if len(desiredSANs) == 0 {
		desiredSANs = extractSANs(s.cfg.Listen)
	}

	// Generate server cert if missing, or regenerate if existing SANs don't match desired.
	regenerate := false
	if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
		regenerate = true
	} else {
		existing, err := pki.LoadCert(serverCertPath)
		if err != nil {
			slog.Warn("could not load existing server cert, regenerating", "err", err)
			regenerate = true
		} else if !sansEqual(pki.CertSANs(existing), desiredSANs) {
			slog.Info("server cert SANs changed, regenerating", "existing", pki.CertSANs(existing), "desired", desiredSANs)
			regenerate = true
		}
	}

	if regenerate {
		serverExpiry, err := time.ParseDuration(s.cfg.PKI.ServerExpiry)
		if err != nil {
			return "", fmt.Errorf("parse server_expiry: %w", err)
		}
		if err := pki.GenerateServerCert(caCertPath, caKeyPath, serverKeyPath, serverCertPath, desiredSANs, serverExpiry); err != nil {
			return "", fmt.Errorf("generate server cert: %w", err)
		}
		slog.Info("generated server certificate", "path", serverCertPath, "sans", desiredSANs)
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

// sansEqual returns true if both slices contain the same set of SANs (order-independent).
func sansEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
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
	// Prometheus metrics endpoint — no client cert required so Prometheus can scrape without mTLS.
	mux.Handle("/prom/metrics", promhttp.Handler())
	// Status page — simple HTML dashboard, no auth required.
	mux.HandleFunc("/status", statuspage.Handler(s.statusPageData))

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

type nodeIdentityContextKey struct{}

// requireClientCert authenticates the verified client certificate and places
// its node identity in the request context. Node-scoped handlers must then use
// authorizeNode to bind the authenticated identity to the requested resource.
func (s *Server) requireClientCert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.mtlsEnabled() {
			next(w, r)
			return
		}

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			writeJSONError(w, http.StatusUnauthorized, "verified client certificate required")
			return
		}

		cert := r.TLS.VerifiedChains[0][0]
		identity, legacy, err := pki.CertificateNodeIdentity(cert)
		if err != nil {
			slog.Warn("client certificate identity rejected",
				"fingerprint_sha256", certificateFingerprint(cert),
				"path", r.URL.Path,
				"err", err)
			writeJSONError(w, http.StatusUnauthorized, "client certificate has no valid node identity")
			return
		}
		if legacy {
			fingerprint := certificateFingerprint(cert)
			if _, loaded := s.legacyCertLogged.LoadOrStore(fingerprint, struct{}{}); !loaded {
				slog.Warn("legacy Common Name client identity accepted; re-enroll node to receive a URI identity",
					"node_id", identity,
					"fingerprint_sha256", fingerprint)
			}
		}

		ctx := context.WithValue(r.Context(), nodeIdentityContextKey{}, identity)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) mtlsEnabled() bool {
	return s.cfg.PKI != nil && s.pkiDir != ""
}

func requestNodeIdentity(r *http.Request) (string, bool) {
	identity, ok := r.Context().Value(nodeIdentityContextKey{}).(string)
	return identity, ok && identity != ""
}

func (s *Server) authorizeNode(w http.ResponseWriter, r *http.Request, claimedNodeID string) bool {
	if !s.mtlsEnabled() {
		return true
	}
	authenticatedNodeID, ok := requestNodeIdentity(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "authenticated node identity required")
		return false
	}
	if authenticatedNodeID == claimedNodeID {
		return true
	}

	cert := r.TLS.VerifiedChains[0][0]
	slog.Warn("node authorization denied",
		"authenticated_node_id", authenticatedNodeID,
		"claimed_node_id", claimedNodeID,
		"fingerprint_sha256", certificateFingerprint(cert),
		"path", r.URL.Path)
	writeJSONError(w, http.StatusForbidden, "client certificate identity does not match requested node")
	return false
}

func certificateFingerprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return "unknown"
	}
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum[:])
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

	signedCert, err := pki.SignNodeCSR(caCert, caKey, []byte(req.CSR), req.Name, clientExpiry)
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

	// Persist the registration before returning credentials to the node.
	result, err := s.registerNode(nodeRegistration{Name: req.Name}, s.cfg.WGApply)
	if err != nil {
		writeRegistrationError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, api.BootstrapResponse{
		CACert:     string(caCertPEM),
		ClientCert: string(signedCert),
		NodeID:     result.NodeID,
		VPNIP:      result.VPNIP,
	})
}

var errVPNIPAllocation = errors.New("vpn IP allocation failed")

type nodeRegistration struct {
	Name       string
	PubKey     string
	VPNIP      string
	Endpoint   string
	ProbePort  int
	PublicAddr string
	NATType    string
}

type nodeRegistrationResult struct {
	NodeID string
	VPNIP  string
	Peers  []api.PeerCandidate
}

// registerNode registers or updates a node using a copy-on-write registry
// transaction. The live registry changes only after the replacement has been
// durably written and, when enabled, applied to the WireGuard dataplane.
func (s *Server) registerNode(input nodeRegistration, autoApply bool) (nodeRegistrationResult, error) {
	now := time.Now().UTC()
	assignedVPNIP := input.VPNIP

	s.mu.Lock()
	defer s.mu.Unlock()

	previous := cloneRegistry(s.reg)
	next := cloneRegistry(s.reg)
	existingIndex := -1
	for i := range next.Nodes {
		if next.Nodes[i].Name == input.Name {
			existingIndex = i
			break
		}
	}
	if assignedVPNIP == "" && existingIndex >= 0 {
		assignedVPNIP = next.Nodes[existingIndex].VPNIP
	}
	if assignedVPNIP == "" {
		var err error
		assignedVPNIP, err = allocateVPNIP(s.cfg.VPNCIDR, next)
		if err != nil {
			return nodeRegistrationResult{}, fmt.Errorf("%w: %v", errVPNIPAllocation, err)
		}
	}

	var nodeID string
	if existingIndex >= 0 {
		node := &next.Nodes[existingIndex]
		if node.ID == "" {
			node.ID = input.Name
		}
		if input.PubKey != "" {
			node.PubKey = input.PubKey
		}
		node.VPNIP = assignedVPNIP
		if input.Endpoint != "" {
			node.Endpoint = input.Endpoint
		}
		node.ProbePort = input.ProbePort
		if input.PublicAddr != "" {
			node.PublicAddr = input.PublicAddr
		}
		if input.NATType != "" {
			node.NATType = input.NATType
		}
		node.LastSeenAt = now
		node.Status = "online"
		nodeID = node.ID
	} else {
		nodeID = input.Name
		next.Nodes = append(next.Nodes, store.NodeInfo{
			ID:         nodeID,
			Name:       input.Name,
			PubKey:     input.PubKey,
			VPNIP:      assignedVPNIP,
			Endpoint:   input.Endpoint,
			ProbePort:  input.ProbePort,
			PublicAddr: input.PublicAddr,
			NATType:    input.NATType,
			LastSeenAt: now,
			Status:     "online",
		})
	}

	if err := s.persistRegistry(next); err != nil {
		return nodeRegistrationResult{}, fmt.Errorf("save registry: %w", err)
	}

	if autoApply {
		if err := s.applyWG(peersForWGRegistry(next)); err != nil {
			applyErr := fmt.Errorf("apply WireGuard registry: %w", err)
			rollbackWGErr := s.applyWG(peersForWGRegistry(previous))
			rollbackStoreErr := s.persistRegistry(previous)
			if rollbackWGErr != nil {
				rollbackWGErr = fmt.Errorf("rollback WireGuard registry: %w", rollbackWGErr)
			}
			if rollbackStoreErr != nil {
				rollbackStoreErr = fmt.Errorf("rollback persisted registry: %w", rollbackStoreErr)
			}
			return nodeRegistrationResult{}, errors.Join(applyErr, rollbackWGErr, rollbackStoreErr)
		}
	}

	s.reg = next
	return nodeRegistrationResult{
		NodeID: nodeID,
		VPNIP:  assignedVPNIP,
		Peers:  s.peersLocked(nodeID),
	}, nil
}

func cloneRegistry(reg *store.Registry) *store.Registry {
	if reg == nil {
		return &store.Registry{}
	}
	clone := *reg
	clone.Nodes = append([]store.NodeInfo(nil), reg.Nodes...)
	return &clone
}

func (s *Server) persistRegistry(reg *store.Registry) error {
	if s.saveRegistry == nil {
		return store.SaveRegistry(s.regPath, reg)
	}
	return s.saveRegistry(s.regPath, reg)
}

func writeRegistrationError(w http.ResponseWriter, err error) {
	if errors.Is(err, errVPNIPAllocation) {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Error("node registration transaction failed", "err", err)
	writeJSONError(w, http.StatusInternalServerError, "node registration failed")
}

// updateMetrics refreshes Prometheus gauges based on current registry and directOK state.
func (s *Server) updateMetrics() {
	s.mu.Lock()
	defer s.mu.Unlock()

	metrics.NodesRegistered.Set(float64(len(s.reg.Nodes)))

	online := 0
	for _, n := range s.reg.Nodes {
		if time.Since(n.LastSeenAt) < 60*time.Second {
			online++
		}
	}
	metrics.NodesOnline.Set(float64(online))

	// Count P2P ready pairs
	pairs := 0
	for _, peers := range s.directOK {
		for _, t := range peers {
			if time.Since(t) < 2*time.Minute {
				pairs++
			}
		}
	}
	metrics.P2PReadyPairs.Set(float64(pairs))
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
	if !s.authorizeNode(w, r, req.Name) {
		return
	}

	result, err := s.registerNode(nodeRegistration{
		Name:       req.Name,
		PubKey:     req.PubKey,
		VPNIP:      req.VPNIP,
		Endpoint:   req.Endpoint,
		ProbePort:  req.ProbePort,
		PublicAddr: req.PublicAddr,
		NATType:    req.NATType,
	}, s.cfg.WGApply)
	if err != nil {
		writeRegistrationError(w, err)
		return
	}

	resp := api.RegisterResponse{
		NodeID: result.NodeID,
		Peers:  result.Peers,
		VPNIP:  result.VPNIP,
	}

	// Fill observed WireGuard endpoints for candidates (best-effort).
	s.fillObservedEndpoints(resp.Peers)

	s.updateMetrics()
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
	if !s.authorizeNode(w, r, nodeID) {
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
	if req.NodeID == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id required")
		return
	}
	if !s.authorizeNode(w, r, req.NodeID) {
		return
	}
	if len(req.Samples) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	for _, sample := range req.Samples {
		if sample.NodeID != req.NodeID {
			writeJSONError(w, http.StatusForbidden, "metric sample node_id does not match request node_id")
			return
		}
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
	if !s.authorizeNode(w, r, req.NodeID) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next := cloneRegistry(s.reg)
	for i := range next.Nodes {
		if next.Nodes[i].ID == req.NodeID {
			next.Nodes[i].NATType = req.NATType
			next.Nodes[i].PublicAddr = req.PublicAddr
			next.Nodes[i].LastSeenAt = time.Now().UTC()
			break
		}
	}

	if err := s.persistRegistry(next); err != nil {
		slog.Error("NAT probe registry update failed", "node_id", req.NodeID, "err", err)
		writeJSONError(w, http.StatusInternalServerError, "registry update failed")
		return
	}
	s.reg = next

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
	if req.NodeID == "" || req.PeerID == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id and peer_id are required")
		return
	}
	if !s.authorizeNode(w, r, req.NodeID) {
		return
	}

	if req.Success {
		s.mu.Lock()
		m := s.directOK[req.NodeID]
		if m == nil {
			m = make(map[string]time.Time)
			s.directOK[req.NodeID] = m
		}
		m[req.PeerID] = time.Now().UTC()
		s.mu.Unlock()
	}

	if req.NodeID != "" && req.PeerID != "" {
		result := "success"
		if !req.Success {
			result = "failure"
		}
		metrics.DirectProbesTotal.WithLabelValues(req.NodeID, req.PeerID, result).Inc()
	}

	slog.Debug("direct result", "node", req.NodeID, "peer", req.PeerID, "success", req.Success, "rtt_ms", req.RTTMs, "reason", req.Reason)
	s.updateMetrics()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWGConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id required")
		return
	}
	if !s.authorizeNode(w, r, nodeID) {
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
	return peersForWGRegistry(s.reg)
}

func peersForWGRegistry(reg *store.Registry) []wireguard.Peer {
	if reg == nil {
		return nil
	}
	peers := make([]wireguard.Peer, 0, len(reg.Nodes))
	for _, node := range reg.Nodes {
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

func (s *Server) applyWG(peers []wireguard.Peer) error {
	serverCfg := wireguard.ServerConfig{
		Interface:  s.cfg.WGInterface,
		PrivateKey: s.cfg.WGPrivateKey,
		Address:    s.cfg.WGAddress,
		ListenPort: s.cfg.WGPort,
		MTU:        s.cfg.MTU,
	}
	return s.wg.ApplyServer(serverCfg, peers)
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

func (s *Server) statusPageData() statuspage.Data {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := statuspage.Data{Title: "vpnctl"}
	for _, n := range s.reg.Nodes {
		online := time.Since(n.LastSeenAt) < 60*time.Second
		quality := "offline"
		if online {
			quality = "good"
		}
		lastSeen := "never"
		if !n.LastSeenAt.IsZero() {
			d := time.Since(n.LastSeenAt)
			switch {
			case d < time.Minute:
				lastSeen = fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				lastSeen = fmt.Sprintf("%dm ago", int(d.Minutes()))
			default:
				lastSeen = fmt.Sprintf("%dh ago", int(d.Hours()))
			}
		}
		data.Nodes = append(data.Nodes, statuspage.NodeStatus{
			Name:     n.Name,
			VPNIP:    n.VPNIP,
			NATType:  n.NATType,
			LastSeen: lastSeen,
			Online:   online,
			Quality:  quality,
			RTTMs:    "-",
			LossPct:  "-",
		})
		if online {
			data.OnlineCount++
		}
	}
	data.TotalCount = len(s.reg.Nodes)
	return data
}
