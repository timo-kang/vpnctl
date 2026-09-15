// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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

const (
	maxRequestBodyBytes = 1 << 20
	maxWGPublicKeyBytes = 128
	maxEndpointBytes    = 512
	maxNATTypeBytes     = 64
)

// Server provides the controller HTTP API.
type Server struct {
	cfg     config.ControllerConfig
	regPath string
	mu      sync.Mutex
	// stateMu drains admitted requests before removal, including metric writes.
	stateMu sync.RWMutex
	reg     *store.Registry
	ipam    *ipam
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
	authority        *pki.Authority
	pkiDir           string
	legacyCertLogged sync.Map
}

// NewServer constructs a controller server.
func NewServer(cfg config.ControllerConfig) (*Server, error) {
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "restore.pending")); err == nil {
		return nil, fmt.Errorf("controller restore is incomplete; resume with the same backup")
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	regPath := filepath.Join(cfg.DataDir, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		return nil, err
	}
	// Backward/forward compatibility: older registries might not have IDs.
	// Keep IDs stable so callers can consistently use node_id.
	changed := false
	for id := range reg.RemovedNodes {
		if _, err := pki.NodeIdentityURI(id); err != nil {
			return nil, fmt.Errorf("invalid removed identity: %w", err)
		}
	}
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
	for _, node := range reg.Nodes {
		if _, removed := reg.RemovedNodes[node.ID]; removed {
			return nil, fmt.Errorf("node %q is both active and removed", node.ID)
		}
	}
	if err := validateRegistryNodeMetadata(reg); err != nil {
		return nil, fmt.Errorf("registry node metadata validation: %w", err)
	}
	allocator, err := newIPAM(cfg.VPNCIDR, cfg.WGAddress, cfg.ReservedVPNIPs)
	if err != nil {
		return nil, fmt.Errorf("IPAM configuration: %w", err)
	}
	ipamChanged, err := allocator.validateAndNormalizeRegistry(reg)
	if err != nil {
		return nil, fmt.Errorf("registry IPAM validation: %w", err)
	}
	changed = changed || ipamChanged
	if changed {
		if err := store.SaveRegistry(regPath, reg); err != nil {
			return nil, err
		}
	}
	return &Server{
		cfg:          cfg,
		regPath:      regPath,
		reg:          reg,
		ipam:         allocator,
		wg:           wireguard.DefaultManager(),
		saveRegistry: store.SaveRegistry,
		directOK:     make(map[string]map[string]time.Time),
	}, nil
}

// InitPKI initialises the PKI directory, generates the CA and server certificate
// if they don't exist, opens the bootstrap token store, and creates an initial
// token only when the token file is absent. The returned string is the token if
// one was freshly created (empty otherwise).
func (s *Server) InitPKI() (string, error) {
	if s.cfg.PKI == nil {
		return "", fmt.Errorf("controller.pki config section is required")
	}

	pkiDir := filepath.Join(s.cfg.DataDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return "", fmt.Errorf("create pki dir: %w", err)
	}
	s.pkiDir = pkiDir

	policy, err := controllerPKIPolicy(s.cfg)
	if err != nil {
		return "", err
	}
	authority, err := pki.OpenAuthority(pkiDir, policy)
	if err != nil {
		return "", fmt.Errorf("initialize certificate authority: %w", err)
	}
	s.authority = authority

	// Open token store.
	tokenPath := filepath.Join(pkiDir, "bootstrap-tokens.json")
	_, tokenFileErr := os.Stat(tokenPath)
	if tokenFileErr != nil && !os.IsNotExist(tokenFileErr) {
		return "", tokenFileErr
	}
	ts, err := pki.OpenTokenStore(tokenPath)
	if err != nil {
		return "", fmt.Errorf("open token store: %w", err)
	}
	s.tokenStore = ts

	// Only first-time initialization creates a token; revoked/empty stores stay closed.
	var bootstrapToken string
	if os.IsNotExist(tokenFileErr) {
		bootstrapToken, err = ts.CreateWithOptions(24*time.Hour, false)
		if err != nil {
			return "", fmt.Errorf("persist initial bootstrap token: %w", err)
		}
		slog.Info("created initial bootstrap token", "ttl", "24h")
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
	if s.cfg.PKI != nil && s.authority == nil {
		return fmt.Errorf("controller PKI is configured but not initialized")
	}
	if s.cfg.WGApply {
		if err := s.reconcileWG(); err != nil {
			return fmt.Errorf("reconcile WireGuard from registry: %w", err)
		}
	}
	if s.cfg.ProbePort > 0 {
		addr, err := s.StartProbeResponder()
		if err != nil {
			return fmt.Errorf("probe responder: %w", err)
		}
		slog.Info("probe responder listening", "addr", addr)
	}

	stopAdmin, err := s.startAdmin()
	if err != nil {
		return fmt.Errorf("admin IPC: %w", err)
	}
	defer stopAdmin()

	server := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.httpHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if s.mtlsEnabled() {
		server.TLSConfig = s.authority.DynamicTLSConfig()
		stopPKI := s.startPKIMaintenance()
		defer stopPKI()

		slog.Info("controller listening (mTLS)", "addr", s.cfg.Listen)
		return server.ListenAndServeTLS("", "")
	}

	slog.Info("controller listening", "addr", s.cfg.Listen)
	return server.ListenAndServe()
}

// httpHandler is shared by the production listener and network integration tests.
func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/bootstrap", s.handleBootstrap)
	mux.HandleFunc("/pki/trust", s.requireClientCert(s.handlePKITrust))
	mux.HandleFunc("/pki/renew", s.requireClientCert(s.handlePKIRenew))
	mux.HandleFunc("/pki/ack", s.requireClientCert(s.handlePKIAck))
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

	return mux
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

type authenticatedNode struct {
	id          string
	fingerprint string
}

// requireClientCert authenticates the verified client certificate and places
// its node identity in the request context. Node-scoped handlers must then use
// authorizeNode to bind the authenticated identity to the requested resource.
func (s *Server) requireClientCert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
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
		if !s.nodeRegistered(identity) {
			writeJSONError(w, http.StatusForbidden, "authenticated node is not registered")
			return
		}
		if s.authority != nil {
			if err := s.authority.Observe(cert, identity); err != nil {
				code := http.StatusServiceUnavailable
				if errors.Is(err, pki.ErrCertificateDenied) {
					code = http.StatusForbidden
				}
				slog.Warn("certificate authorization denied", "node_id", identity, "fingerprint", certificateFingerprint(cert), "err", err)
				metrics.PKIEventsTotal.WithLabelValues("controller", "authorize", "denied").Inc()
				writeJSONError(w, code, "certificate authorization failed")
				return
			}
		}
		if legacy {
			fingerprint := certificateFingerprint(cert)
			if _, loaded := s.legacyCertLogged.LoadOrStore(fingerprint, struct{}{}); !loaded {
				slog.Warn("legacy Common Name client identity accepted; re-enroll node to receive a URI identity",
					"node_id", identity,
					"fingerprint_sha256", fingerprint)
			}
		}

		ctx := context.WithValue(r.Context(), nodeIdentityContextKey{}, authenticatedNode{
			id:          identity,
			fingerprint: certificateFingerprint(cert),
		})
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) mtlsEnabled() bool {
	return s.cfg.PKI != nil
}

func requestNodeIdentity(r *http.Request) (authenticatedNode, bool) {
	identity, ok := r.Context().Value(nodeIdentityContextKey{}).(authenticatedNode)
	return identity, ok && identity.id != ""
}

func (s *Server) authorizeNode(w http.ResponseWriter, r *http.Request, claimedNodeID string) bool {
	if !s.mtlsEnabled() {
		s.mu.Lock()
		_, removed := s.reg.RemovedNodes[claimedNodeID]
		s.mu.Unlock()
		if removed {
			writeJSONError(w, http.StatusForbidden, errNodeRemoved.Error())
			return false
		}
		return true
	}
	identity, ok := requestNodeIdentity(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "authenticated node identity required")
		return false
	}
	if identity.id != claimedNodeID {
		slog.Warn("node authorization denied",
			"authenticated_node_id", identity.id,
			"claimed_node_id", claimedNodeID,
			"fingerprint_sha256", identity.fingerprint,
			"path", r.URL.Path,
			"reason", "identity_mismatch")
		writeJSONError(w, http.StatusForbidden, "client certificate identity does not match requested node")
		return false
	}
	if !s.nodeRegistered(identity.id) {
		slog.Warn("node authorization denied",
			"authenticated_node_id", identity.id,
			"fingerprint_sha256", identity.fingerprint,
			"path", r.URL.Path,
			"reason", "node_not_registered")
		writeJSONError(w, http.StatusForbidden, "authenticated node is not registered")
		return false
	}
	return true
}

func (s *Server) nodeRegistered(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, node := range s.reg.Nodes {
		if node.ID == nodeID {
			return true
		}
	}
	return false
}

func (s *Server) authorizePeer(w http.ResponseWriter, nodeID, peerID string) bool {
	if peerID == "" {
		writeJSONError(w, http.StatusBadRequest, "peer_id required")
		return false
	}
	if peerID == nodeID {
		writeJSONError(w, http.StatusBadRequest, "peer_id must differ from node_id")
		return false
	}
	if s.nodeRegistered(peerID) {
		return true
	}
	writeJSONError(w, http.StatusBadRequest, "peer_id does not reference a registered node")
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
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req api.BootstrapRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Token == "" || req.Name == "" || req.CSR == "" {
		writeJSONError(w, http.StatusBadRequest, "token, name, and csr are required")
		return
	}

	// Validate token against persisted state so CLI create/revoke operations take
	// effect without restarting the controller.
	if s.tokenStore == nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}
	validToken, err := s.tokenStore.Validate(req.Token)
	if err != nil {
		slog.Error("bootstrap token validation failed", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "bootstrap token store unavailable")
		return
	}
	if !validToken {
		writeJSONError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}

	if s.authority == nil {
		writeJSONError(w, 503, "certificate authority unavailable")
		return
	}
	if err := pki.ValidateCSR([]byte(req.CSR)); err != nil {
		writeJSONError(w, 400, "invalid CSR")
		return
	}
	var signedCert string
	var issuedState pki.AuthorityStatus

	// Persist the registration before returning credentials to the node.
	var result nodeRegistrationResult
	err = s.tokenStore.Use(req.Token, req.Name, func() error {
		var registrationErr error
		result, registrationErr = s.registerNode(nodeRegistration{Name: req.Name}, s.cfg.WGApply)
		if registrationErr != nil {
			return registrationErr
		}
		signedCert, issuedState, registrationErr = s.authority.Issue([]byte(req.CSR), req.Name)
		s.logPKIResult("issue", req.Name, registrationErr)
		return registrationErr
	})
	if errors.Is(err, pki.ErrInvalidToken) {
		writeJSONError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}
	if err != nil {
		writeRegistrationError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, api.BootstrapResponse{
		CACert:     issuedState.CACert,
		Generation: issuedState.Generation,
		ClientCert: signedCert,
		NodeID:     result.NodeID,
		VPNIP:      result.VPNIP,
	})
}

var (
	errNodeRemoved            = errors.New("node identity was removed; enroll with a new identity")
	errVPNIPAllocation        = errors.New("vpn IP allocation failed")
	errRegistrationValidation = errors.New("node registration validation failed")
)

type nodeRegistration struct {
	Name       string
	PubKey     string
	VPNIP      string
	Endpoint   string
	ProbePort  int
	PublicAddr string
	NATType    string
}

func validateRegistrationInput(input nodeRegistration) error {
	if _, err := pki.NodeIdentityURI(input.Name); err != nil {
		return fmt.Errorf("invalid node name: %w", err)
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{name: "pub_key", value: input.PubKey, limit: maxWGPublicKeyBytes},
		{name: "endpoint", value: input.Endpoint, limit: maxEndpointBytes},
		{name: "public_addr", value: input.PublicAddr, limit: maxEndpointBytes},
		{name: "nat_type", value: input.NATType, limit: maxNATTypeBytes},
	} {
		if err := validateRegistryText(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	if input.ProbePort < 0 || input.ProbePort > 65535 {
		return fmt.Errorf("probe_port must be between 0 and 65535")
	}
	return nil
}

func validateRegistryText(field, value string, limit int) error {
	if value == "" {
		return nil
	}
	if len(value) > limit {
		return fmt.Errorf("%s exceeds %d bytes", field, limit)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s has surrounding whitespace", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", field)
		}
	}
	return nil
}

func validateRegistryNodeMetadata(reg *store.Registry) error {
	if reg == nil {
		return nil
	}
	identities := make(map[string]int, len(reg.Nodes))
	keyOwners := make(map[string]string, len(reg.Nodes))
	for index, node := range reg.Nodes {
		if node.ID == "" {
			return fmt.Errorf("node at index %d has no identity", index)
		}
		if previousIndex, duplicate := identities[node.ID]; duplicate {
			return fmt.Errorf("node identity %q appears more than once (indexes %d and %d)", node.ID, previousIndex, index)
		}
		identities[node.ID] = index
		if node.Name != node.ID {
			return fmt.Errorf("node %q name %q does not match its identity", node.ID, node.Name)
		}
		if err := validateRegistrationInput(nodeRegistration{
			Name: node.ID, PubKey: node.PubKey, Endpoint: node.Endpoint, ProbePort: node.ProbePort,
			PublicAddr: node.PublicAddr, NATType: node.NATType,
		}); err != nil {
			return fmt.Errorf("node %q: %w", node.ID, err)
		}
		if node.PubKey == "" {
			continue
		}
		if owner, duplicate := keyOwners[node.PubKey]; duplicate {
			return fmt.Errorf("public key is assigned to both node %q and node %q", owner, node.ID)
		}
		keyOwners[node.PubKey] = node.ID
	}
	return nil
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
	if err := validateRegistrationInput(input); err != nil {
		return nodeRegistrationResult{}, fmt.Errorf("%w: %v", errRegistrationValidation, err)
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, removed := s.reg.RemovedNodes[input.Name]; removed {
		return nodeRegistrationResult{}, errNodeRemoved
	}
	next := cloneRegistry(s.reg)
	existingIndex := -1
	for i := range next.Nodes {
		if next.Nodes[i].ID == input.Name {
			existingIndex = i
		}
		if input.PubKey != "" && next.Nodes[i].ID != input.Name && next.Nodes[i].PubKey == input.PubKey {
			return nodeRegistrationResult{}, fmt.Errorf("%w: public key is already registered to node %q", errRegistrationValidation, next.Nodes[i].ID)
		}
	}
	assignedVPNIP, err := s.ipam.lease(input.Name, input.VPNIP, next)
	if err != nil {
		return nodeRegistrationResult{}, fmt.Errorf("%w: %v", errVPNIPAllocation, err)
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

	if err := s.commitRegistryLocked(next, autoApply); err != nil {
		return nodeRegistrationResult{}, err
	}

	return nodeRegistrationResult{
		NodeID: nodeID,
		VPNIP:  assignedVPNIP,
		Peers:  s.peersLocked(nodeID),
	}, nil
}

// commitRegistryLocked applies the replacement before persistence and restores
// the previous dataplane on any failure. Caller owns s.mu.
func (s *Server) commitRegistryLocked(next *store.Registry, autoApply bool) error {
	previous := s.reg
	if autoApply {
		if err := s.applyWG(peersForWGRegistry(next)); err != nil {
			applyErr := fmt.Errorf("apply WireGuard registry: %w", err)
			rollbackErr := s.applyWG(peersForWGRegistry(previous))
			if rollbackErr != nil {
				rollbackErr = fmt.Errorf("rollback WireGuard registry: %w", rollbackErr)
			}
			return errors.Join(applyErr, rollbackErr)
		}
	}

	if err := s.persistRegistry(next); err != nil {
		saveErr := fmt.Errorf("save registry: %w", err)
		if !autoApply {
			return saveErr
		}
		rollbackErr := s.applyWG(peersForWGRegistry(previous))
		if rollbackErr != nil {
			rollbackErr = fmt.Errorf("rollback WireGuard registry after save failure: %w", rollbackErr)
		}
		return errors.Join(saveErr, rollbackErr)
	}

	s.reg = next
	return nil
}

func cloneRegistry(reg *store.Registry) *store.Registry {
	if reg == nil {
		return &store.Registry{}
	}
	clone := *reg
	clone.Nodes = append([]store.NodeInfo(nil), reg.Nodes...)
	clone.RemovedNodes = make(map[string]time.Time, len(reg.RemovedNodes))
	for id, removedAt := range reg.RemovedNodes {
		clone.RemovedNodes[id] = removedAt
	}
	return &clone
}

func (s *Server) persistRegistry(reg *store.Registry) error {
	if s.saveRegistry == nil {
		return store.SaveRegistry(s.regPath, reg)
	}
	return s.saveRegistry(s.regPath, reg)
}

func writeRegistrationError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNodeRemoved) {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	if errors.Is(err, errVPNIPAllocation) || errors.Is(err, errRegistrationValidation) {
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
	s.updateMetricsLocked()
}

func (s *Server) updateMetricsLocked() {
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
	if err := decodeJSON(w, r, &req); err != nil {
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
	if err := decodeJSON(w, r, &req); err != nil {
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
		if !s.authorizePeer(w, req.NodeID, sample.PeerID) {
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
	if err := decodeJSON(w, r, &req); err != nil {
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
	if err := validateRegistrationInput(nodeRegistration{
		Name: req.NodeID, PublicAddr: req.PublicAddr, NATType: req.NATType,
	}); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
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
	if err := decodeJSON(w, r, &req); err != nil {
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
	if !s.authorizePeer(w, req.NodeID, req.PeerID) {
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

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain a single JSON object")
		}
		return fmt.Errorf("request body must contain a single JSON object: %w", err)
	}
	return nil
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

func (s *Server) reconcileWG() error {
	s.mu.Lock()
	peers := peersForWGRegistry(s.reg)
	s.mu.Unlock()
	return s.applyWG(peers)
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
