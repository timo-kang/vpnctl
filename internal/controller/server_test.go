// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/execx"
	"vpnctl/internal/model"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

func TestHandleRegister_AllocationError_DoesNotHoldLock(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := config.ControllerConfig{
		DataDir:     tmp,
		VPNCIDR:     "not-a-cidr",
		WGApply:     false,
		Listen:      "127.0.0.1:0",
		WGPort:      51820,
		WGInterface: "wg0",
	}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	body, _ := json.Marshal(api.RegisterRequest{Name: "node-a", PubKey: "pub", VPNIP: ""})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleRegister(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	// If handleRegister returned while holding the lock, this would deadlock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		body2, _ := json.Marshal(api.RegisterRequest{Name: "node-a", PubKey: "pub", VPNIP: "10.7.0.2/32"})
		req2 := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body2))
		rec2 := httptest.NewRecorder()
		s.handleRegister(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Errorf("second status=%d body=%s", rec2.Code, rec2.Body.String())
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleRegister likely deadlocked (registry lock not released)")
	}

	// Registry persisted.
	regPath := filepath.Join(tmp, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(reg.Nodes) != 1 {
		t.Fatalf("nodes=%d", len(reg.Nodes))
	}
	if reg.Nodes[0].VPNIP != "10.7.0.2/32" {
		t.Fatalf("vpn_ip=%q", reg.Nodes[0].VPNIP)
	}
}

func TestAllocateVPNIP_Unique(t *testing.T) {
	t.Parallel()

	reg := &store.Registry{
		Nodes: []store.NodeInfo{
			{Name: "a", VPNIP: "10.7.0.2/32"},
			{Name: "b", VPNIP: "10.7.0.3/32"},
		},
	}

	ip, err := allocateVPNIP("10.7.0.0/24", reg)
	if err != nil {
		t.Fatalf("allocateVPNIP: %v", err)
	}
	if ip == "10.7.0.2/32" || ip == "10.7.0.3/32" {
		t.Fatalf("allocated used ip: %s", ip)
	}
}

func TestAllocateVPNIP_RejectsHugeCIDR(t *testing.T) {
	t.Parallel()

	_, err := allocateVPNIP("10.0.0.0/8", &store.Registry{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

type fakeRunner struct {
	out map[string]string
}

func (f *fakeRunner) Run(name string, args ...string) error { return nil }

func (f *fakeRunner) Output(name string, args ...string) (string, error) {
	k := name + " " + strings.Join(args, " ")
	if f.out == nil {
		return "", nil
	}
	return f.out[k], nil
}

var _ execx.Runner = (*fakeRunner)(nil)

func TestHandleCandidates_FillsObservedEndpointFromWgDump(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := config.ControllerConfig{
		DataDir:     tmp,
		Listen:      "127.0.0.1:0",
		WGInterface: "wg0",
		VPNCIDR:     "10.7.0.0/24",
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	wgDump := "" +
		"wg0\t(priv)\t(pub)\t51820\toff\n" +
		"pub-b\t(psk)\t39.1.2.3:51820\t10.7.0.12/32\t0\t0\t0\toff\n"
	s.wg = wireguard.NewManager(&fakeRunner{
		out: map[string]string{
			"wg show wg0 dump": wgDump,
		},
	})

	s.reg.Nodes = []store.NodeInfo{
		{ID: "node-a", Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32"},
		{ID: "node-b", Name: "node-b", PubKey: "pub-b", VPNIP: "10.7.0.12/32"},
	}

	req := httptest.NewRequest(http.MethodGet, "/candidates?node_id=node-a", nil)
	rec := httptest.NewRecorder()
	s.handleCandidates(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp api.CandidatesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("peers=%d", len(resp.Peers))
	}
	if resp.Peers[0].Name != "node-b" {
		t.Fatalf("peer=%+v", resp.Peers[0])
	}
	if resp.Peers[0].Endpoint != "39.1.2.3:51820" {
		t.Fatalf("endpoint=%q", resp.Peers[0].Endpoint)
	}
}

func TestP2PReadyLocked_MutualSuccess(t *testing.T) {
	t.Parallel()

	s := &Server{
		cfg: config.ControllerConfig{P2PReadyMode: "mutual"},
		directOK: map[string]map[string]time.Time{
			"a": {"b": time.Now().UTC()},
			"b": {"a": time.Now().UTC()},
		},
	}
	if !s.p2pReadyLocked("a", "b") {
		t.Fatalf("expected ready")
	}
}

func TestP2PReadyLocked_EitherSuccess(t *testing.T) {
	t.Parallel()

	s := &Server{
		cfg: config.ControllerConfig{P2PReadyMode: "either"},
		directOK: map[string]map[string]time.Time{
			"a": {"b": time.Now().UTC()},
		},
	}
	if !s.p2pReadyLocked("a", "b") {
		t.Fatalf("expected ready")
	}
}

func TestServer_ProbeResponder(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := config.ControllerConfig{
		DataDir:   tmp,
		ProbePort: 0, // OS-assigned
		Listen:    "127.0.0.1:0",
	}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	addr, err := s.StartProbeResponder()
	if err != nil {
		t.Fatalf("StartProbeResponder: %v", err)
	}
	defer s.StopProbeResponder()

	if addr == "" {
		t.Fatal("expected non-empty address")
	}

	// Send a vpnctl-echo:healthcheck UDP packet to the responder.
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()

	msg := []byte("vpnctl-echo:healthcheck")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	got := string(buf[:n])
	if got != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", got, string(msg))
	}
}

func TestHandleRegister_SaveFailureDoesNotPanicOrMutateLiveRegistry(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	s, err := NewServer(config.ControllerConfig{
		DataDir: tmp,
		VPNCIDR: "10.7.0.0/24",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	blocked := filepath.Join(tmp, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s.regPath = filepath.Join(blocked, "registry.yaml")

	body, _ := json.Marshal(api.RegisterRequest{
		Name:   "node-a",
		PubKey: "pub-a",
		VPNIP:  "10.7.0.2/32",
	})
	rec := httptest.NewRecorder()
	s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(s.reg.Nodes) != 0 {
		t.Fatalf("failed registration mutated live registry: %+v", s.reg.Nodes)
	}

	// A storage failure must not poison the mutex or prevent later requests.
	s.regPath = filepath.Join(tmp, "registry.yaml")
	rec = httptest.NewRecorder()
	s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleBootstrap_RegistrySaveFailureReturnsError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	s, err := NewServer(config.ControllerConfig{
		DataDir: tmp,
		VPNCIDR: "10.7.0.0/24",
		Listen:  "127.0.0.1:8443",
		PKI: &config.PKIConfig{
			CAExpiry:     "24h",
			ServerExpiry: "24h",
			ClientExpiry: "24h",
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if _, err := s.InitPKI(); err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	tokens := s.tokenStore.List()
	if len(tokens) != 1 {
		t.Fatalf("tokens=%d", len(tokens))
	}
	csr, _, err := pki.GenerateCSR("node-a")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	blocked := filepath.Join(tmp, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s.regPath = filepath.Join(blocked, "registry.yaml")

	body, _ := json.Marshal(api.BootstrapRequest{
		Token: tokens[0],
		Name:  "node-a",
		CSR:   string(csr),
	})
	rec := httptest.NewRecorder()
	s.handleBootstrap(rec, httptest.NewRequest(http.MethodPost, "/bootstrap", bytes.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(s.reg.Nodes) != 0 {
		t.Fatalf("failed bootstrap mutated live registry: %+v", s.reg.Nodes)
	}
}

type failingWGRunner struct{}

func (failingWGRunner) Run(name string, args ...string) error {
	if name == "wg" {
		return errors.New("injected wg failure")
	}
	return nil
}

func (failingWGRunner) Output(string, ...string) (string, error) { return "", nil }

func TestHandleRegister_WGApplyFailureRollsBackPersistedRegistry(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	s, err := NewServer(config.ControllerConfig{
		DataDir:      tmp,
		VPNCIDR:      "10.7.0.0/24",
		WGApply:      true,
		WGInterface:  "wg0",
		WGAddress:    "10.7.0.1/24",
		WGPrivateKey: "private",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.wg = wireguard.NewManager(failingWGRunner{})

	body, _ := json.Marshal(api.RegisterRequest{
		Name:   "node-a",
		PubKey: "pub-a",
		VPNIP:  "10.7.0.2/32",
	})
	rec := httptest.NewRecorder()
	s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(s.reg.Nodes) != 0 {
		t.Fatalf("failed apply mutated live registry: %+v", s.reg.Nodes)
	}

	persisted, err := store.LoadRegistry(s.regPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(persisted.Nodes) != 0 {
		t.Fatalf("failed apply remained persisted: %+v", persisted.Nodes)
	}
}

func requestWithNodeCertificate(t *testing.T, method, target string, body []byte, nodeID string) *http.Request {
	t.Helper()
	identityURI, err := pki.NodeIdentityURI(nodeID)
	if err != nil {
		t.Fatalf("NodeIdentityURI: %v", err)
	}
	cert := &x509.Certificate{
		Raw:     []byte("test-certificate-" + nodeID),
		Subject: pkix.Name{CommonName: nodeID},
		URIs:    []*url.URL{identityURI},
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	return req
}

func newIdentityTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(config.ControllerConfig{
		DataDir:         t.TempDir(),
		VPNCIDR:         "10.7.0.0/24",
		ServerPublicKey: "server-key",
		ServerEndpoint:  "controller.example.com:51820",
		ServerAllowedIPs: []string{
			"10.7.0.0/24",
		},
		PKI: &config.PKIConfig{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.pkiDir = t.TempDir()
	s.reg.Nodes = []store.NodeInfo{
		{ID: "node-a", Name: "node-a", PubKey: "old-a", VPNIP: "10.7.0.2/32"},
		{ID: "node-b", Name: "node-b", PubKey: "old-b", VPNIP: "10.7.0.3/32"},
	}
	return s
}

func TestNodeScopedHandlersRejectCrossNodeClaims(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		body    any
		handler func(*Server) http.HandlerFunc
	}{
		{
			name:   "register",
			method: http.MethodPost,
			target: "/register",
			body: api.RegisterRequest{
				Name: "node-b", PubKey: "attacker-key", VPNIP: "10.7.0.99/32",
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleRegister },
		},
		{
			name:    "candidates",
			method:  http.MethodGet,
			target:  "/candidates?node_id=node-b",
			handler: func(s *Server) http.HandlerFunc { return s.handleCandidates },
		},
		{
			name:   "metrics",
			method: http.MethodPost,
			target: "/metrics",
			body: api.MetricsRequest{
				NodeID: "node-b",
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleMetrics },
		},
		{
			name:   "NAT probe",
			method: http.MethodPost,
			target: "/nat-probe",
			body: api.NATProbeRequest{
				NodeID: "node-b", NATType: "spoofed", PublicAddr: "203.0.113.10:1234",
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleNATProbe },
		},
		{
			name:   "direct result",
			method: http.MethodPost,
			target: "/direct-result",
			body: api.DirectResultRequest{
				NodeID: "node-b", PeerID: "node-a", Success: true,
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleDirectResult },
		},
		{
			name:    "WireGuard config",
			method:  http.MethodGet,
			target:  "/wg-config?node_id=node-b",
			handler: func(s *Server) http.HandlerFunc { return s.handleWGConfig },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newIdentityTestServer(t)
			var body []byte
			if tt.body != nil {
				var err error
				body, err = json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
			}
			req := requestWithNodeCertificate(t, tt.method, tt.target, body, "node-a")
			rec := httptest.NewRecorder()
			s.requireClientCert(tt.handler(s))(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if s.reg.Nodes[1].PubKey != "old-b" || s.reg.Nodes[1].NATType != "" {
				t.Fatalf("cross-node request mutated registry: %+v", s.reg.Nodes[1])
			}
			if len(s.directOK) != 0 {
				t.Fatalf("cross-node request mutated direct readiness: %+v", s.directOK)
			}
		})
	}
}

func TestHandleMetricsRejectsSampleForDifferentNode(t *testing.T) {
	s := newIdentityTestServer(t)
	body, err := json.Marshal(api.MetricsRequest{
		NodeID:  "node-a",
		Samples: []model.Metric{{NodeID: "node-b", PeerID: "node-a"}},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	req := requestWithNodeCertificate(t, http.MethodPost, "/metrics", body, "node-a")
	rec := httptest.NewRecorder()
	s.requireClientCert(s.handleMetrics)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireClientCertRejectsUnverifiedPeerCertificate(t *testing.T) {
	s := newIdentityTestServer(t)
	called := false
	handler := s.requireClientCert(func(http.ResponseWriter, *http.Request) {
		called = true
	})
	req := httptest.NewRequest(http.MethodGet, "/candidates?node_id=node-a", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Raw:     []byte("unverified"),
			Subject: pkix.Name{CommonName: "node-a"},
		}},
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("handler ran with an unverified peer certificate")
	}
}

func TestHandleBootstrapIgnoresCSRClaimedIdentity(t *testing.T) {
	tmp := t.TempDir()
	s, err := NewServer(config.ControllerConfig{
		DataDir: tmp,
		VPNCIDR: "10.7.0.0/24",
		Listen:  "127.0.0.1:8443",
		PKI: &config.PKIConfig{
			CAExpiry:     "24h",
			ServerExpiry: "24h",
			ClientExpiry: "24h",
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	token, err := s.InitPKI()
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	s.reg.Nodes = []store.NodeInfo{{
		ID: "node-a", Name: "node-a", VPNIP: "10.7.0.42/32",
	}}
	csr, _, err := pki.GenerateCSR("node-b")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	body, err := json.Marshal(api.BootstrapRequest{
		Token: token,
		Name:  "node-a",
		CSR:   string(csr),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	s.handleBootstrap(rec, httptest.NewRequest(http.MethodPost, "/bootstrap", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response api.BootstrapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	block, _ := pem.Decode([]byte(response.ClientCert))
	if block == nil {
		t.Fatal("failed to decode bootstrapped certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	identity, legacy, err := pki.CertificateNodeIdentity(cert)
	if err != nil {
		t.Fatalf("CertificateNodeIdentity: %v", err)
	}
	if identity != "node-a" || legacy || response.NodeID != "node-a" {
		t.Fatalf("certificate identity=%q legacy=%v response node_id=%q", identity, legacy, response.NodeID)
	}
	if response.VPNIP != "10.7.0.42/32" {
		t.Fatalf("re-enrollment changed VPN IP to %q", response.VPNIP)
	}
}

func TestMTLSIdentityBindingOverTLS(t *testing.T) {
	tmp := t.TempDir()
	caKeyPath := filepath.Join(tmp, "ca.key")
	caCertPath := filepath.Join(tmp, "ca.crt")
	serverKeyPath := filepath.Join(tmp, "server.key")
	serverCertPath := filepath.Join(tmp, "server.crt")
	clientKeyPath := filepath.Join(tmp, "node-a.key")
	clientCertPath := filepath.Join(tmp, "node-a.crt")

	if err := pki.GenerateCA(caKeyPath, caCertPath, 24*time.Hour); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := pki.GenerateServerCert(caCertPath, caKeyPath, serverKeyPath, serverCertPath, []string{"127.0.0.1"}, 24*time.Hour); err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	caCert, caKey, err := pki.LoadCA(caKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	csr, clientKey, err := pki.GenerateCSR("untrusted-csr-name")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	clientCert, err := pki.SignNodeCSR(caCert, caKey, csr, "node-a", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, clientKey, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	if err := os.WriteFile(clientCertPath, clientCert, 0o644); err != nil {
		t.Fatalf("write client certificate: %v", err)
	}

	s, err := NewServer(config.ControllerConfig{
		DataDir: tmp,
		VPNCIDR: "10.7.0.0/24",
		PKI:     &config.PKIConfig{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.pkiDir = tmp
	s.cfg.MetricsPath = filepath.Join(tmp, "metrics.csv")
	s.reg.Nodes = []store.NodeInfo{
		{ID: "node-a", Name: "node-a", VPNIP: "10.7.0.2/32"},
		{ID: "node-b", Name: "node-b", PubKey: "pub-b", VPNIP: "10.7.0.3/32"},
	}

	serverTLS, err := pki.ServerTLSConfig(caCertPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	serverTLS.ClientAuth = tls.VerifyClientCertIfGiven
	mux := http.NewServeMux()
	mux.HandleFunc("/register", s.requireClientCert(s.handleRegister))
	mux.HandleFunc("/candidates", s.requireClientCert(s.handleCandidates))
	mux.HandleFunc("/metrics", s.requireClientCert(s.handleMetrics))
	testServer := httptest.NewUnstartedServer(mux)
	testServer.TLS = serverTLS
	testServer.StartTLS()
	defer testServer.Close()

	clientTLS, err := pki.ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	defer client.CloseIdleConnections()
	doJSON := func(method, target string, payload any) int {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		req, err := http.NewRequest(method, testServer.URL+target, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}

	if status := doJSON(http.MethodPost, "/register", api.RegisterRequest{
		Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32",
	}); status != http.StatusOK {
		t.Fatalf("register status=%d", status)
	}
	response, err := client.Get(testServer.URL + "/candidates?node_id=node-a")
	if err != nil {
		t.Fatalf("same-node candidates GET: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("same-node candidates status=%d", response.StatusCode)
	}
	if status := doJSON(http.MethodPost, "/metrics", api.MetricsRequest{
		NodeID:  "node-a",
		Samples: []model.Metric{{NodeID: "node-a", PeerID: "node-b", Path: "relay"}},
	}); status != http.StatusNoContent {
		t.Fatalf("metrics status=%d", status)
	}

	response, err = client.Get(testServer.URL + "/candidates?node_id=node-b")
	if err != nil {
		t.Fatalf("cross-node GET: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-node status=%d", response.StatusCode)
	}

	unauthenticatedTLS, err := pki.ClientTLSConfig(caCertPath, "", "")
	if err != nil {
		t.Fatalf("ClientTLSConfig without client certificate: %v", err)
	}
	unauthenticatedClient := &http.Client{Transport: &http.Transport{TLSClientConfig: unauthenticatedTLS}}
	defer unauthenticatedClient.CloseIdleConnections()
	response, err = unauthenticatedClient.Get(testServer.URL + "/candidates?node_id=node-a")
	if err != nil {
		t.Fatalf("unauthenticated GET: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", response.StatusCode)
	}
}

func TestHandleRegisterStorageFaultsDoNotMutateLiveRegistry(t *testing.T) {
	faults := []struct {
		name string
		err  error
	}{
		{name: "disk full", err: syscall.ENOSPC},
		{name: "read-only filesystem", err: syscall.EROFS},
		{name: "rename failure", err: &os.LinkError{Op: "rename", Old: "registry.tmp", New: "registry.yaml", Err: syscall.EIO}},
	}

	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			s, err := NewServer(config.ControllerConfig{
				DataDir: t.TempDir(),
				VPNCIDR: "10.7.0.0/24",
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			s.saveRegistry = func(string, *store.Registry) error {
				return fault.err
			}
			body, err := json.Marshal(api.RegisterRequest{
				Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32",
			})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			rec := httptest.NewRecorder()
			s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if len(s.reg.Nodes) != 0 {
				t.Fatalf("storage fault mutated live registry: %+v", s.reg.Nodes)
			}
			if strings.Contains(rec.Body.String(), fault.err.Error()) {
				t.Fatalf("response leaked internal storage error: %s", rec.Body.String())
			}
		})
	}
}

func TestHandleNATProbeSaveFailureRollsBackLiveRegistry(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{
		DataDir: t.TempDir(),
		VPNCIDR: "10.7.0.0/24",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.reg.Nodes = []store.NodeInfo{{
		ID: "node-a", Name: "node-a", NATType: "restricted", PublicAddr: "198.51.100.1:1234",
	}}
	s.saveRegistry = func(string, *store.Registry) error {
		return syscall.ENOSPC
	}
	body, err := json.Marshal(api.NATProbeRequest{
		NodeID: "node-a", NATType: "full-cone", PublicAddr: "203.0.113.10:5678",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	s.handleNATProbe(rec, httptest.NewRequest(http.MethodPost, "/nat-probe", bytes.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if s.reg.Nodes[0].NATType != "restricted" || s.reg.Nodes[0].PublicAddr != "198.51.100.1:1234" {
		t.Fatalf("failed NAT update mutated live registry: %+v", s.reg.Nodes[0])
	}
}

func TestPKIConfigurationFailsClosedWithoutInitialization(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{
		DataDir: t.TempDir(),
		Listen:  "127.0.0.1:0",
		PKI:     &config.PKIConfig{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	called := false
	rec := httptest.NewRecorder()
	s.requireClientCert(func(http.ResponseWriter, *http.Request) {
		called = true
	})(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("middleware status=%d body=%s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("protected handler ran before PKI initialization")
	}
	if err := s.ListenAndServe(); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("ListenAndServe error=%v", err)
	}
}

func TestNodeScopedHandlerRejectsUnregisteredCertificateIdentity(t *testing.T) {
	s := newIdentityTestServer(t)
	req := requestWithNodeCertificate(t, http.MethodGet, "/candidates?node_id=node-removed", nil, "node-removed")
	rec := httptest.NewRecorder()
	s.requireClientCert(s.handleCandidates)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReportedPeerMustBeRegisteredAndDistinct(t *testing.T) {
	tests := []struct {
		name    string
		body    any
		handler func(*Server) http.HandlerFunc
	}{
		{
			name: "direct result unknown peer",
			body: api.DirectResultRequest{
				NodeID: "node-a", PeerID: "unknown-peer", Success: true,
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleDirectResult },
		},
		{
			name: "direct result self peer",
			body: api.DirectResultRequest{
				NodeID: "node-a", PeerID: "node-a", Success: true,
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleDirectResult },
		},
		{
			name: "metric unknown peer",
			body: api.MetricsRequest{
				NodeID:  "node-a",
				Samples: []model.Metric{{NodeID: "node-a", PeerID: "unknown-peer"}},
			},
			handler: func(s *Server) http.HandlerFunc { return s.handleMetrics },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newIdentityTestServer(t)
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			req := requestWithNodeCertificate(t, http.MethodPost, "/", body, "node-a")
			rec := httptest.NewRecorder()
			s.requireClientCert(tt.handler(s))(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if len(s.directOK) != 0 {
				t.Fatalf("invalid peer mutated direct readiness: %+v", s.directOK)
			}
			if _, err := os.Stat(s.cfg.MetricsPath); err == nil {
				t.Fatal("invalid peer wrote metrics")
			} else if !os.IsNotExist(err) {
				t.Fatalf("Stat metrics: %v", err)
			}
		})
	}
}

type recordingWGRunner struct {
	configs []string
}

func (r *recordingWGRunner) Run(name string, args ...string) error {
	if name == "wg" && len(args) == 3 && args[0] == "syncconf" {
		data, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		r.configs = append(r.configs, string(data))
	}
	return nil
}

func (*recordingWGRunner) Output(string, ...string) (string, error) {
	return "", nil
}

func TestReconcileWGAppliesPersistedRegistry(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{
		DataDir:      t.TempDir(),
		WGInterface:  "wg0",
		WGAddress:    "10.7.0.1/24",
		WGPrivateKey: "server-private",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.reg.Nodes = []store.NodeInfo{{
		ID: "node-a", Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32",
	}}
	runner := &recordingWGRunner{}
	s.wg = wireguard.NewManager(runner)

	if err := s.reconcileWG(); err != nil {
		t.Fatalf("reconcileWG: %v", err)
	}
	if len(runner.configs) != 1 {
		t.Fatalf("syncconf calls=%d", len(runner.configs))
	}
	if !strings.Contains(runner.configs[0], "PublicKey = pub-a") || !strings.Contains(runner.configs[0], "AllowedIPs = 10.7.0.2/32") {
		t.Fatalf("reconciled config=%q", runner.configs[0])
	}
}

func TestRegisterSaveFailureRollsBackAppliedDataplane(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{
		DataDir:      t.TempDir(),
		VPNCIDR:      "10.7.0.0/24",
		WGApply:      true,
		WGInterface:  "wg0",
		WGAddress:    "10.7.0.1/24",
		WGPrivateKey: "server-private",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	runner := &recordingWGRunner{}
	s.wg = wireguard.NewManager(runner)
	s.saveRegistry = func(string, *store.Registry) error {
		if len(runner.configs) != 1 {
			t.Fatalf("registry save happened before dataplane apply: syncconf calls=%d", len(runner.configs))
		}
		return syscall.ENOSPC
	}
	body, err := json.Marshal(api.RegisterRequest{
		Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(runner.configs) != 2 {
		t.Fatalf("syncconf calls=%d, want apply and rollback", len(runner.configs))
	}
	if strings.Contains(runner.configs[1], "public_key=pub-a") {
		t.Fatalf("rollback retained failed peer: %q", runner.configs[1])
	}
	if len(s.reg.Nodes) != 0 {
		t.Fatalf("failed registration mutated live registry: %+v", s.reg.Nodes)
	}
}
