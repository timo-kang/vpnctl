package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/metrics"
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
	directOK map[string]map[string]time.Time // node_id -> peer_id -> last success
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

// ListenAndServe runs the HTTP server.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/candidates", s.handleCandidates)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/nat-probe", s.handleNATProbe)
	mux.HandleFunc("/direct-result", s.handleDirectResult)
	mux.HandleFunc("/wg-config", s.handleWGConfig)

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

	log.Printf("direct result node=%s peer=%s success=%v rtt_ms=%.2f reason=%s", req.NodeID, req.PeerID, req.Success, req.RTTMs, req.Reason)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWGConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.cfg.ServerPublicKey == "" || s.cfg.ServerEndpoint == "" || len(s.cfg.ServerAllowedIPs) == 0 {
		log.Printf("wg-config error: server config not set (public_key=%t endpoint=%t allowed_ips=%d)",
			s.cfg.ServerPublicKey != "", s.cfg.ServerEndpoint != "", len(s.cfg.ServerAllowedIPs))
		writeJSONError(w, http.StatusInternalServerError, "server config not set")
		return
	}

	resp := api.WGConfigResponse{
		ServerPublicKey:    s.cfg.ServerPublicKey,
		ServerEndpoint:     s.cfg.ServerEndpoint,
		ServerAllowedIPs:   s.cfg.ServerAllowedIPs,
		ServerKeepaliveSec: s.cfg.ServerKeepaliveSec,
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
	if ab == nil || ba == nil {
		return false
	}
	t1, ok1 := ab[b]
	t2, ok2 := ba[a]
	if !ok1 || !ok2 {
		return false
	}
	if now.Sub(t1) > ttl || now.Sub(t2) > ttl {
		return false
	}
	return true
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
		if peers[i].PubKey == "" {
			continue
		}
		if ep := m[peers[i].PubKey]; ep != "" {
			peers[i].Endpoint = ep
		}
	}
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
