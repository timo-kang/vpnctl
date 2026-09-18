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

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/history"
	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
	"vpnctl/internal/statuspage"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"

	"vpnctl/internal/atomicfile"
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
	// mutationMu serializes registry writers while mu only protects published state.
	mutationMu sync.Mutex
	// stateMu drains admitted requests before removal, including metric writes.
	stateMu sync.RWMutex
	// mutationAdmission drains slow/mutating handlers while committed reads continue.
	mutationAdmission sync.RWMutex
	adminAdmission    adminAdmission
	pkiAdmission      writerAdmission
	registryAdmission writerAdmission
	reg               *store.Registry
	ipam              *ipam
	history           history.Storage
	// metricsMu serializes appends to the metrics CSV to avoid interleaved writes
	// when multiple nodes submit samples concurrently.
	metricsMu         sync.Mutex
	wg                *wireguard.Manager
	saveRegistry      func(string, *store.Registry) error
	registryUncertain bool
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
	reg, fresh, err := loadControllerRegistry(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	// Backward/forward compatibility: older registries might not have IDs.
	// Keep IDs stable so callers can consistently use node_id.
	changed := fresh || reg.Version == 0
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
	if err := markRegistryInitialized(cfg.DataDir); err != nil {
		return nil, err
	}
	historyStore, err := history.Open(filepath.Join(cfg.DataDir, "history.db"), time.Now())
	if err != nil {
		return nil, fmt.Errorf("open fleet history: %w", err)
	}
	return &Server{
		cfg:          cfg,
		history:      historyStore,
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
	if err := atomicfile.MkdirAll(pkiDir, 0o700); err != nil {
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

// ListenAndServe runs until a listener fails. CLI owners use the context
// variant to drain admitted mutations before releasing the state lock.
func (s *Server) ListenAndServe() error { return s.ListenAndServeContext(context.Background()) }

func (s *Server) ListenAndServeContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.cfg.PKI != nil && s.authority == nil {
		return fmt.Errorf("controller PKI is configured but not initialized")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if s.cfg.WGApply {
		s.mu.Lock()
		err := s.applyWGContext(ctx, s.peersForWGLocked())
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("reconcile WireGuard from registry: %w", err)
		}
	}
	if s.cfg.ProbePort > 0 {
		addr, err := s.StartProbeResponder()
		if err != nil {
			return fmt.Errorf("probe responder: %w", err)
		}
		defer s.StopProbeResponder()
		slog.Info("probe responder listening", "addr", addr)
	}
	admin, err := s.startAdminService()
	if err != nil {
		return fmt.Errorf("admin IPC: %w", err)
	}
	defer admin.stop()
	if s.mtlsEnabled() {
		stopPKI := s.startPKIMaintenance()
		defer stopPKI()
	}
	stopHistory := s.startHistoryMaintenance()
	defer stopHistory()
	server := &http.Server{
		Handler: s.httpHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	if s.mtlsEnabled() {
		server.TLSConfig = s.authority.DynamicTLSConfig()
	}
	apiServer := startHTTP(server, listener, s.mtlsEnabled())
	// Drain both listeners before stopping maintenance/UDP and returning to owner.
	defer stopHTTP(apiServer, admin)
	slog.Info("controller listening", "addr", listener.Addr(), "mtls", s.mtlsEnabled())
	select {
	case <-ctx.Done():
		return nil
	case <-apiServer.done:
		return serveResult(ctx, apiServer)
	case <-admin.done:
		if err := serveResult(ctx, admin); err != nil {
			return fmt.Errorf("admin IPC stopped: %w", err)
		}
		return nil
	}
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
	mux.HandleFunc("/fleet/history", s.handleAuthorizedFleetHistory)
	mux.HandleFunc("/uplink-observations", s.requireClientCert(s.handleUplinkObservation))
	mux.HandleFunc("/fleet/uplinks", s.handleAuthorizedUplinks)
	mux.HandleFunc("/events", s.requireClientCert(s.handleEvent))
	mux.HandleFunc("/fleet/events", s.handleAuthorizedEvents)
	mux.HandleFunc("/fleet/alerts", s.handleAuthorizedAlerts)
	// Prometheus metrics endpoint — no client cert required so Prometheus can scrape without mTLS.
	mux.Handle("/prom/metrics", s.metricsHandler())
	// Status page — simple HTML dashboard, no auth required.
	mux.HandleFunc("/status", statuspage.Handler(s.statusPageData))

	return observeHTTP(mux)
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
		mayWritePKI := s.requestMayWritePKI(r)
		mayWriteRegistry := r.Method == http.MethodPost && (r.URL.Path == "/register" || r.URL.Path == "/nat-probe")
		if mayWritePKI || r.Method == http.MethodPost {
			// Reject already invalid identities before they can queue behind writers.
			// This preflight grants no authority; recheck after both admissions below.
			if _, ok := s.authenticateClient(w, r, false); !ok {
				return
			}
		}
		if r.Method == http.MethodPost && !bufferAdmissionBody(w, r) {
			return
		}
		if mayWritePKI {
			release, err := s.pkiAdmission.acquire(r.Context())
			if err != nil {
				writeJSONError(w, http.StatusRequestTimeout, "PKI request canceled before admission")
				return
			}
			defer release()
		}
		if mayWriteRegistry {
			release, err := s.registryAdmission.admit(r.Context(), false, "registry_writer")
			if err != nil {
				writeJSONError(w, http.StatusRequestTimeout, "registry request canceled before admission")
				return
			}
			defer release()
		}
		if mayWritePKI || requestNeedsMutationDrain(r) {
			s.mutationAdmission.RLock()
			defer s.mutationAdmission.RUnlock()
		}
		admissionStart := time.Now()
		s.stateMu.RLock()
		observeStage("api", "admission_wait", admissionStart)
		defer s.stateMu.RUnlock()
		if r.Context().Err() != nil {
			writeJSONError(w, http.StatusRequestTimeout, "request canceled before execution")
			return
		}
		identity, ok := s.authenticateClient(w, r, true)
		if !ok {
			return
		}
		if identity.id != "" {
			r = r.WithContext(context.WithValue(r.Context(), nodeIdentityContextKey{}, identity))
		}
		next(w, r)
	}
}

// authenticateClient may skip only legacy first-use persistence during preflight.
// Current identity and known-certificate checks still run; execution admission
// always calls it again with first-use observation enabled.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request, observeFirstUse bool) (authenticatedNode, bool) {
	if !s.mtlsEnabled() {
		return authenticatedNode{}, true
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		writeJSONError(w, http.StatusUnauthorized, "verified client certificate required")
		return authenticatedNode{}, false
	}

	cert := r.TLS.VerifiedChains[0][0]
	identity, legacy, err := pki.CertificateNodeIdentity(cert)
	if err != nil {
		slog.Warn("client certificate identity rejected",
			"fingerprint_sha256", certificateFingerprint(cert),
			"path", r.URL.Path,
			"err", err)
		writeJSONError(w, http.StatusUnauthorized, "client certificate has no valid node identity")
		return authenticatedNode{}, false
	}
	if !s.nodeRegistered(identity) {
		writeJSONError(w, http.StatusForbidden, "authenticated node is not registered")
		return authenticatedNode{}, false
	}
	if s.authority != nil && (observeFirstUse || s.authority.CertificateObserved(cert)) {
		authStart := time.Now()
		authErr := s.authority.Observe(cert, identity)
		observeStage("api", "certificate_authorize", authStart)
		if err := authErr; err != nil {
			code := http.StatusServiceUnavailable
			if errors.Is(err, pki.ErrCertificateDenied) {
				code = http.StatusForbidden
			}
			slog.Warn("certificate authorization denied", "node_id", identity, "fingerprint", certificateFingerprint(cert), "err", err)
			metrics.PKIEventsTotal.WithLabelValues("controller", "authorize", "denied").Inc()
			writeJSONError(w, code, "certificate authorization failed")
			return authenticatedNode{}, false
		}
	}
	if legacy && observeFirstUse {
		fingerprint := certificateFingerprint(cert)
		if _, loaded := s.legacyCertLogged.LoadOrStore(fingerprint, struct{}{}); !loaded {
			slog.Warn("legacy Common Name client identity accepted; re-enroll node to receive a URI identity",
				"node_id", identity,
				"fingerprint_sha256", fingerprint)
		}
	}

	return authenticatedNode{id: identity, fingerprint: certificateFingerprint(cert)}, true
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
	start := time.Now()
	s.mu.Lock()
	observeStage("identity", "registry_wait", start)
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
	if r.Method == http.MethodPost && !bufferAdmissionBody(w, r) {
		return
	}
	release, err := s.pkiAdmission.acquire(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusRequestTimeout, "bootstrap canceled before admission")
		return
	}
	defer release()
	releaseRegistry, err := s.registryAdmission.admit(r.Context(), true, "registry_writer")
	if err != nil {
		writeJSONError(w, http.StatusRequestTimeout, "bootstrap canceled before registry admission")
		return
	}
	defer releaseRegistry()
	s.mutationAdmission.RLock()
	defer s.mutationAdmission.RUnlock()
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if r.Context().Err() != nil {
		writeJSONError(w, http.StatusRequestTimeout, "bootstrap canceled before execution")
		return
	}
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

	// Consume admission durably, validate/reserve in memory, then issue before
	// publishing the enrollment. Failed issuance cannot create a live registry node.
	var result nodeRegistrationResult
	err = s.tokenStore.Use(req.Token, req.Name, func() error {
		var registrationErr error
		result, registrationErr = s.registerWithIssuance(nodeRegistration{Name: req.Name}, s.cfg.WGApply, func() error {
			var issueErr error
			signedCert, issuedState, issueErr = s.authority.Issue([]byte(req.CSR), req.Name)
			s.logPKIResult("issue", req.Name, issueErr)
			return issueErr
		})
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
// transaction. Publication follows persistence and optional WireGuard apply.
// A post-rename sync error publishes the visible replacement but returns an
// uncertain-commit error; it must never roll memory/WG back behind the file.
func (s *Server) registerNode(input nodeRegistration, autoApply bool) (nodeRegistrationResult, error) {
	return s.registerWithIssuance(input, autoApply, nil)
}

// issue runs after validation/lease selection and before registry publication.
// mutationMu reserves the proposed lease while readers retain the prior snapshot.
func (s *Server) registerWithIssuance(input nodeRegistration, autoApply bool, issue func() error) (nodeRegistrationResult, error) {
	if err := validateRegistrationInput(input); err != nil {
		return nodeRegistrationResult{}, fmt.Errorf("%w: %v", errRegistrationValidation, err)
	}
	start := time.Now()
	s.mutationMu.Lock()
	observeStage("register", "writer_wait", start)
	defer s.mutationMu.Unlock()
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureRegistryDurableLocked(); err != nil {
		return nodeRegistrationResult{}, err
	}
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

	if issue != nil {
		err := func() error { s.mu.Unlock(); defer s.mu.Lock(); return issue() }()
		if err != nil {
			return nodeRegistrationResult{}, err
		}
		// Re-enrollment must not alter an existing lease, liveness or WG metadata.
		if existingIndex >= 0 {
			return nodeRegistrationResult{NodeID: input.Name, VPNIP: assignedVPNIP, Peers: s.peersLocked(input.Name)}, nil
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
		node.EnrollmentPending = false
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

	if issue != nil {
		node := &next.Nodes[len(next.Nodes)-1]
		node.EnrollmentPending = true
		node.Status = "pending"
		node.LastSeenAt = time.Time{}
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

// commitRegistryLocked is called with mutationMu and mu held. It temporarily
// releases mu during external I/O so readers can use the last durable state.
// Writers remain serialized, including NAT updates and node removal; publication
// and all caller-side volatile state changes still occur with mu held.
func (s *Server) commitRegistryLocked(next *store.Registry, autoApply bool) error {
	previous := s.reg
	err := func() error {
		s.mu.Unlock()
		defer s.mu.Lock() // restore the caller's lock even if an injected writer panics
		return s.applyAndPersist(previous, next, autoApply)
	}()
	if err == nil || atomicfile.Replaced(err) {
		s.reg = next
		s.registryUncertain = atomicfile.Replaced(err)
	}
	return err
}

// With mutationMu and mu held, confirm a prior visible-but-uncertain replacement
// before an idempotent operation can report success without another file write.
func (s *Server) ensureRegistryDurableLocked() error {
	if !s.registryUncertain {
		return nil
	}
	err := func() error { s.mu.Unlock(); defer s.mu.Lock(); return atomicfile.SyncDir(filepath.Dir(s.regPath)) }()
	if err != nil {
		return &atomicfile.CommitError{Err: err}
	}
	s.registryUncertain = false
	return nil
}

func (s *Server) applyAndPersist(previous, next *store.Registry, autoApply bool) error {
	rollback := func(cause error) error {
		start := time.Now()
		err := s.applyWG(peersForWGRegistry(previous))
		observeStage("transaction", "rollback", start)
		if err != nil {
			err = fmt.Errorf("rollback WireGuard registry: %w", err)
		}
		return errors.Join(cause, err)
	}
	if autoApply {
		start := time.Now()
		err := s.applyWG(peersForWGRegistry(next))
		observeStage("transaction", "apply", start)
		if err != nil {
			return rollback(fmt.Errorf("apply WireGuard registry: %w", err))
		}
	}
	start := time.Now()
	err := s.persistRegistry(next)
	observeStage("transaction", "persist", start)
	if err != nil {
		err = fmt.Errorf("save registry: %w", err)
		if autoApply && !atomicfile.Replaced(err) {
			return rollback(err)
		}
		return err
	}
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
		if !n.EnrollmentPending && time.Since(n.LastSeenAt) < 60*time.Second {
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
	if len(req.Observations) > 0 {
		s.handleObservations(w, r, req)
		return
	}
	if len(req.Samples) > history.MaxBatch {
		writeJSONError(w, http.StatusBadRequest, "metrics batch exceeds 256 samples")
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

	if err := atomicfile.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Warning", `299 vpnctl "Legacy summary metrics do not establish fleet quality; submit observations"`)
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

	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
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

	if err := s.commitRegistryLocked(next, false); err != nil {
		slog.Error("NAT probe registry update failed", "node_id", req.NodeID, "err", err)
		writeJSONError(w, http.StatusInternalServerError, "registry update failed")
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

	s.mu.Lock()
	if req.Success {
		m := s.directOK[req.NodeID]
		if m == nil {
			m = make(map[string]time.Time)
			s.directOK[req.NodeID] = m
		}
		m[req.PeerID] = time.Now().UTC()
	} else {
		// An explicit failure invalidates the pair, including either-direction mode.
		// Neither direction may reuse a success observed before this failure.
		delete(s.directOK[req.NodeID], req.PeerID)
		delete(s.directOK[req.PeerID], req.NodeID)
	}
	s.mu.Unlock()

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
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.fleetSnapshot())
}

// Enrollment completion and recent contact are separate facts. In particular,
// a persisted online registration must not advertise online forever.
func fleetNodeState(node store.NodeInfo, now time.Time) string {
	if node.EnrollmentPending {
		return "pending"
	}
	if node.LastSeenAt.IsZero() && node.PubKey == "" {
		return "enrolled"
	}
	if node.LastSeenAt.IsZero() || node.LastSeenAt.After(now) || now.Sub(node.LastSeenAt) >= 60*time.Second {
		return "offline"
	}
	return "online"
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
		if node.EnrollmentPending || node.PubKey == "" || node.VPNIP == "" {
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
	return s.applyWGContext(context.Background(), peers)
}

func (s *Server) applyWGContext(ctx context.Context, peers []wireguard.Peer) error {
	serverCfg := wireguard.ServerConfig{
		Interface:  s.cfg.WGInterface,
		PrivateKey: s.cfg.WGPrivateKey,
		Address:    s.cfg.WGAddress,
		ListenPort: s.cfg.WGPort,
		MTU:        s.cfg.MTU,
	}
	return s.wg.WithContext(ctx).ApplyServer(serverCfg, peers)
}

func (s *Server) statusPageData() statuspage.Data {
	snapshot := s.fleetSnapshot()
	data := statuspage.Data{Title: "vpnctl", TotalCount: len(snapshot.Nodes)}
	for _, n := range snapshot.Nodes {
		online := n.Status == "online"
		data.Nodes = append(data.Nodes, statuspage.NodeStatus{
			Name: n.Name, VPNIP: n.VPNIP, NATType: n.NATType, LastSeen: n.LastSeen,
			Online: online, Status: n.Status, Quality: n.Quality, RTTMs: history.FormatNumber(n.RTTMs), LossPct: history.FormatNumber(n.LossPct),
			Peer: n.PeerID, Path: n.Path, Relay: n.RelayID, Uplink: n.Uplink, Stale: n.Stale, Reason: n.ErrorReason,
		})
		if online {
			data.OnlineCount++
		}
	}
	return data
}
