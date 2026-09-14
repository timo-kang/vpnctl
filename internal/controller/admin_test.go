// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

func testAdminServer(t *testing.T, dir string) (*Server, func()) {
	t.Helper()
	lock, err := AcquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(config.ControllerConfig{DataDir: dir, VPNCIDR: "10.7.0.0/23", WGAddress: "10.7.0.1/23", Listen: "127.0.0.1:0", PKI: &config.PKIConfig{CAExpiry: "24h", ServerExpiry: "24h", ClientExpiry: "24h"}})
	if err != nil {
		lock.Close()
		t.Fatal(err)
	}
	if _, err := s.InitPKI(); err != nil {
		lock.Close()
		t.Fatal(err)
	}
	stop, err := s.startAdmin()
	if err != nil {
		lock.Close()
		t.Fatal(err)
	}
	var once sync.Once
	closeAll := func() { once.Do(func() { stop(); lock.Close() }) }
	t.Cleanup(closeAll)
	return s, closeAll
}

func testTLSAPI(t *testing.T, s *Server) (*httptest.Server, *api.Client, *tls.Config) {
	t.Helper()
	tlsCfg, err := pki.ServerTLSConfig(filepath.Join(s.pkiDir, "ca.crt"), filepath.Join(s.pkiDir, "server.crt"), filepath.Join(s.pkiDir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	h := httptest.NewUnstartedServer(s.httpHandler())
	h.TLS = tlsCfg
	h.StartTLS()
	t.Cleanup(h.Close)
	clientCfg, err := pki.ClientTLSConfig(filepath.Join(s.pkiDir, "ca.crt"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	return h, api.NewTLSClient(h.URL, clientCfg), clientCfg
}

func enrollTestClient(t *testing.T, h *httptest.Server, bootstrap *api.Client, clientCfg *tls.Config, token, id string) (*api.Client, string, *tls.Config) {
	t.Helper()
	csr, key, err := pki.GenerateCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	response, err := bootstrap.Bootstrap(context.Background(), api.BootstrapRequest{Token: token, Name: id, CSR: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(response.ClientCert), key)
	if err != nil {
		t.Fatal(err)
	}
	nodeTLS := clientCfg.Clone()
	nodeTLS.Certificates = []tls.Certificate{cert}
	client := api.NewTLSClient(h.URL, nodeTLS)
	if _, err := client.Register(context.Background(), api.RegisterRequest{Name: id, PubKey: "pub-" + id, ProbePort: 51900}); err != nil {
		t.Fatal(err)
	}
	return client, response.VPNIP, nodeTLS
}

func TestAdminRemovalOverUnixAndTLSRevokesIdentityAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, stop := testAdminServer(t, dir)
	runner := &recordingWGRunner{}
	s.wg = wireguard.NewManager(runner)
	s.cfg.WGApply = true
	s.cfg.WGInterface = "wg-test"
	s.cfg.WGPrivateKey = "test-key"
	h, bootstrap, tlsCfg := testTLSAPI(t, s)
	tokens, err := s.tokenStore.List()
	if err != nil {
		t.Fatal(err)
	}
	a, oldIP, aTLS := enrollTestClient(t, h, bootstrap, tlsCfg, tokens[0], "a")
	b, _, _ := enrollTestClient(t, h, bootstrap, tlsCfg, tokens[0], "b")
	ctx := context.Background()
	if err := a.SubmitDirectResult(ctx, api.DirectResultRequest{NodeID: "a", PeerID: "b", Success: true}); err != nil {
		t.Fatal(err)
	}
	if err := b.SubmitDirectResult(ctx, api.DirectResultRequest{NodeID: "b", PeerID: "a", Success: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Admin(ctx, dir, api.AdminRequest{Operation: "node.remove", NodeID: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Admin(ctx, dir, api.AdminRequest{Operation: "node.remove", NodeID: "a"}); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	for n := 0; n < 30; n++ {
		if _, err := a.Register(ctx, api.RegisterRequest{Name: "a", PubKey: "pub-a"}); err == nil {
			t.Fatal("deleted identity registered")
		}
		if _, err := a.FleetStatus(ctx); err == nil {
			t.Fatal("deleted identity read fleet")
		}
	}
	candidates, err := b.Candidates(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates.Peers) != 0 {
		t.Fatalf("removed peer retained: %+v", candidates)
	}
	fleet, err := b.FleetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet.Nodes) != 1 || fleet.Nodes[0].Name != "b" {
		t.Fatalf("fleet=%+v", fleet)
	}
	s.mu.Lock()
	if len(s.directOK) != 0 {
		t.Errorf("stale direct state=%v", s.directOK)
	}
	if strings.Contains(runner.configs[len(runner.configs)-1], "PublicKey = pub-a") {
		t.Error("stale WG peer")
	}
	s.mu.Unlock()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "vpnctl_direct_probes_total" {
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if (label.GetName() == "node" || label.GetName() == "peer") && label.GetValue() == "a" {
						t.Error("deleted node metric recreated")
					}
				}
			}
		}
	}
	csr, _, err := pki.GenerateCSR("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Bootstrap(ctx, api.BootstrapRequest{Token: tokens[0], Name: "a", CSR: string(csr)}); err == nil {
		t.Fatal("tombstoned node bootstrapped")
	}
	_, newIP, _ := enrollTestClient(t, h, bootstrap, tlsCfg, tokens[0], "c")
	if newIP != oldIP {
		t.Fatalf("freed lease=%s new=%s", oldIP, newIP)
	}
	h.Close()
	stop()
	restarted, _ := testAdminServer(t, dir)
	h2, _, _ := testTLSAPI(t, restarted)
	oldClient := api.NewTLSClient(h2.URL, aTLS)
	if _, err := oldClient.FleetStatus(ctx); err == nil {
		t.Fatal("old certificate usable after restart")
	}
	if _, err := oldClient.Register(ctx, api.RegisterRequest{Name: "a", PubKey: "pub-a"}); err == nil {
		t.Fatal("old identity resurrected after restart")
	}
	if len(restarted.reg.Nodes) != 2 || len(restarted.reg.RemovedNodes) != 1 {
		t.Fatalf("restart registry=%+v", restarted.reg)
	}
}

func TestAdminBoundaryLockAndAudit(t *testing.T) {
	dir := t.TempDir()
	s, _ := testAdminServer(t, dir)
	if second, err := AcquireStateLock(dir); err == nil {
		second.Close()
		t.Fatal("two controllers acquired ownership")
	}
	info, err := os.Stat(api.AdminSocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions=%v", info.Mode())
	}
	payload := []byte(`{"operation":"token.create"}`)
	denied := httptest.NewRecorder()
	s.handleAdmin(denied, httptest.NewRequest("POST", "/admin", bytes.NewReader(payload)))
	if denied.Code != 403 {
		t.Fatalf("unauthenticated status=%d", denied.Code)
	}
	tcp := httptest.NewServer(s.httpHandler())
	defer tcp.Close()
	resp, err := tcp.Client().Post(tcp.URL+"/admin", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("admin exposed on TCP: %d", resp.StatusCode)
	}
	var audit bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&audit, nil)))
	defer slog.SetDefault(previous)
	result, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.create", SingleUse: true, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.revoke", Token: result.Token}); err != nil {
		t.Fatal(err)
	}
	output := audit.String()
	if strings.Contains(output, result.Token) || !strings.Contains(output, "uid:") || !strings.Contains(output, "sha256:") || !strings.Contains(output, `"result":"success"`) {
		t.Fatalf("bad/redacted audit=%s", output)
	}
}

func TestRemoveFaultsLeaveAllStateUnchangedAndRecover(t *testing.T) {
	for _, fault := range []string{"disk-full", "read-only", "rename", "wg-apply"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := testAdminServer(t, t.TempDir())
			if _, err := s.registerNode(nodeRegistration{Name: "a", PubKey: "pub-a"}, false); err != nil {
				t.Fatal(err)
			}
			before := cloneRegistry(s.reg)
			s.directOK["a"] = map[string]time.Time{"b": time.Now()}
			metrics.DirectProbesTotal.WithLabelValues("a", "b", "success").Inc()
			runner := &recordingWGRunner{}
			s.wg = wireguard.NewManager(runner)
			s.cfg.WGApply = true
			s.cfg.WGInterface = "wg-test"
			s.cfg.WGPrivateKey = "test-key"
			switch fault {
			case "wg-apply":
				s.wg = wireguard.NewManager(failingWGRunner{})
			default:
				injected := error(syscall.ENOSPC)
				if fault == "read-only" {
					injected = syscall.EROFS
				}
				if fault == "rename" {
					injected = &os.LinkError{Op: "rename", Err: syscall.EIO}
				}
				s.saveRegistry = func(string, *store.Registry) error { return injected }
			}
			if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "a"}); err == nil {
				t.Fatal("fault returned success")
			}
			disk, err := store.LoadRegistry(s.regPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.reg.Nodes, before.Nodes) || !reflect.DeepEqual(disk.Nodes, before.Nodes) || len(s.reg.RemovedNodes) != 0 || len(disk.RemovedNodes) != 0 || len(s.directOK) != 1 {
				t.Fatal("failed removal partially committed")
			}
			if fault != "wg-apply" {
				if len(runner.configs) != 2 || !strings.Contains(runner.configs[1], "PublicKey = pub-a") {
					t.Fatalf("rollback config=%v", runner.configs)
				}
			}
			s.wg = wireguard.NewManager(runner)
			s.saveRegistry = store.SaveRegistry
			if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "a"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemovalDrainsAdmittedRequests(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	s.cfg.PKI = nil
	if _, err := s.registerNode(nodeRegistration{Name: "a", PubKey: "pub-a"}, false); err != nil {
		t.Fatal(err)
	}
	admitted, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.requireClientCert(func(http.ResponseWriter, *http.Request) {
			close(admitted)
			<-release
			metrics.DirectProbesTotal.WithLabelValues("a", "b", "success").Inc()
		})(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	<-admitted
	removed := make(chan error, 1)
	go func() { removed <- s.removeNode("a") }()
	select {
	case err := <-removed:
		t.Fatalf("remove passed active request: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
}

func TestAdminVariableMeshConcurrentMutationsAndRestart(t *testing.T) {
	for _, size := range []int{2, 16, 64, 253} {
		t.Run(fmt.Sprintf("nodes_%d", size), func(t *testing.T) {
			dir := t.TempDir()
			s, stop := testAdminServer(t, dir)
			for n := 0; n < size; n++ {
				if _, err := s.registerNode(nodeRegistration{Name: fmt.Sprintf("node-%d", n), PubKey: fmt.Sprintf("pub-%d", n)}, false); err != nil {
					t.Fatal(err)
				}
			}
			// Dense readiness state exercises removal of both outgoing and incoming edges.
			for n := 0; n < size; n++ {
				peers := make(map[string]time.Time, size-1)
				for peer := 0; peer < size; peer++ {
					if peer != n {
						peers[fmt.Sprintf("node-%d", peer)] = time.Now()
					}
				}
				s.directOK[fmt.Sprintf("node-%d", n)] = peers
			}
			var wg sync.WaitGroup
			for n := 0; n < size; n++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					if _, err := s.registerNode(nodeRegistration{Name: fmt.Sprintf("new-%d", n), PubKey: fmt.Sprintf("new-pub-%d", n)}, false); err != nil {
						t.Error(err)
						return
					}
					result, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.create", TTL: "1h", SingleUse: true})
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "node.remove", NodeID: fmt.Sprintf("node-%d", n)}); err != nil {
						t.Error(err)
						return
					}
					if _, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.revoke", Token: result.Token}); err != nil {
						t.Error(err)
					}
					for attempt := 0; attempt < 3; attempt++ {
						if _, err := s.registerNode(nodeRegistration{Name: fmt.Sprintf("node-%d", n), PubKey: fmt.Sprintf("pub-%d", n)}, false); !errors.Is(err, errNodeRemoved) {
							t.Errorf("removed node retry=%v", err)
						}
					}
				}(n)
			}
			wg.Wait()
			if len(s.directOK) != 0 {
				t.Fatal("removed mesh readiness edges survived")
			}
			stop()
			restarted, _ := testAdminServer(t, dir)
			if len(restarted.reg.Nodes) != size || len(restarted.reg.RemovedNodes) != size {
				t.Fatalf("restart nodes=%d removed=%d", len(restarted.reg.Nodes), len(restarted.reg.RemovedNodes))
			}
			records, err := restarted.tokenStore.Records()
			if err != nil {
				t.Fatal(err)
			}
			revoked := 0
			for _, record := range records {
				if !record.RevokedAt.IsZero() {
					revoked++
				}
			}
			if revoked != size {
				t.Fatalf("token updates lost: revoked=%d size=%d", revoked, size)
			}
		})
	}
}

func TestAdminRejectsMalformedAndUnavailableOperations(t *testing.T) {
	dir := t.TempDir()
	s, stop := testAdminServer(t, dir)
	for _, req := range []api.AdminRequest{{Operation: "unknown"}, {Operation: "token.create", TTL: "-1s"}, {Operation: "token.create", TTL: "bad"}, {Operation: "node.remove", NodeID: "missing"}, {Operation: "token.revoke"}} {
		if _, err := api.Admin(context.Background(), dir, req); err == nil {
			t.Fatalf("invalid request accepted: %+v", req)
		}
	}
	if err := s.tokenStore.Revoke("nonexistent"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.regPath)
	if !os.IsNotExist(err) && err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "node.remove", NodeID: "a"}); err == nil {
		t.Fatal("offline admin succeeded")
	}
	after, _ := os.ReadFile(s.regPath)
	if !bytes.Equal(before, after) {
		t.Fatal("offline command wrote registry")
	}
}

func TestRemovedPlainNodeCannotRecreateDirectState(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	s.cfg.PKI = nil
	for _, id := range []string{"a", "b"} {
		if _, err := s.registerNode(nodeRegistration{Name: id, PubKey: "pub-" + id}, false); err != nil {
			t.Fatal(err)
		}
	}
	h := httptest.NewServer(s.httpHandler())
	defer h.Close()
	client := api.NewClient(h.URL)
	if err := client.SubmitDirectResult(context.Background(), api.DirectResultRequest{NodeID: "a", PeerID: "b", Success: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.removeNode("a"); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		if err := client.SubmitDirectResult(context.Background(), api.DirectResultRequest{NodeID: "a", PeerID: "b", Success: true}); err == nil {
			t.Fatal("removed node reported direct state")
		}
		if _, err := client.Register(context.Background(), api.RegisterRequest{Name: "a", PubKey: "pub-a"}); err == nil {
			t.Fatal("removed node registered")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.directOK) != 0 || len(s.reg.Nodes) != 1 {
		t.Fatal("deleted state reappeared")
	}
}

func TestAdminShutdownWaitsForMutation(t *testing.T) {
	s, stop := testAdminServer(t, t.TempDir())
	if _, err := s.registerNode(nodeRegistration{Name: "a"}, false); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	s.saveRegistry = func(path string, reg *store.Registry) error {
		close(entered)
		<-release
		return store.SaveRegistry(path, reg)
	}
	removed := make(chan error, 1)
	go func() {
		_, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "a"})
		removed <- err
	}()
	<-entered
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		close(release)
		t.Fatal("ownership released before mutation finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	<-stopped
	restarted, _ := testAdminServer(t, s.cfg.DataDir)
	if len(restarted.reg.Nodes) != 0 || len(restarted.reg.RemovedNodes) != 1 {
		t.Fatal("shutdown lost acknowledged mutation")
	}
}

func TestBootstrapSingleUseReplayAndRevocationThroughIPC(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	_, bootstrap, _ := testTLSAPI(t, s)
	ctx := context.Background()
	token, err := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "token.create", SingleUse: true})
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := pki.GenerateCSR("a")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	successes := make(chan bool, 32)
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := bootstrap.Bootstrap(ctx, api.BootstrapRequest{Name: "a", Token: token.Token, CSR: string(csr)})
			successes <- err == nil
		}()
	}
	wg.Wait()
	close(successes)
	accepted := 0
	for success := range successes {
		if success {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("single-use admitted %d enrollments", accepted)
	}
	reusable, err := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "token.create"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Bootstrap(ctx, api.BootstrapRequest{Name: "a", Token: reusable.Token, CSR: string(csr)}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "token.revoke", Token: reusable.Token}); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 50; n++ {
		if _, err := bootstrap.Bootstrap(ctx, api.BootstrapRequest{Name: "a", Token: reusable.Token, CSR: string(csr)}); err == nil {
			t.Fatal("revoked token bootstrapped")
		}
	}
}

func TestAdminMalformedBodiesDoNotMutateState(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	before, err := s.tokenStore.Records()
	if err != nil {
		t.Fatal(err)
	}
	payloads := []string{
		`null`, `{`, `{"operation":"token.create","extra":true}`,
		`{"operation":"token.create"} {}`, `{"operation":"node.remove","node_id":"bad\nidentity"}`,
		`{"operation":"token.revoke","token":"` + strings.Repeat("x", maxRequestBodyBytes) + `"}`,
	}
	for n := 0; n < 10; n++ {
		for _, payload := range payloads {
			req := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(payload))
			req = req.WithContext(context.WithValue(req.Context(), adminActorKey{}, "uid:test"))
			response := httptest.NewRecorder()
			s.handleAdmin(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("malformed status=%d", response.Code)
			}
		}
	}
	after, err := s.tokenStore.Records()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("malformed requests changed tokens")
	}
}

func TestAdminRejectsUnsafeSocketPaths(t *testing.T) {
	for _, kind := range []string{"public-directory", "symlink-directory", "symlink-lock", "socket-file"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			runDir := filepath.Join(dir, "run")
			if kind == "symlink-directory" {
				if err := os.Symlink(t.TempDir(), runDir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(runDir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "public-directory":
				if err := os.Chmod(runDir, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-lock":
				if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(runDir, "controller.lock")); err != nil {
					t.Fatal(err)
				}
			case "socket-file":
				path := api.AdminSocketPath(dir)
				if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				lock, err := AcquireStateLock(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				s := &Server{cfg: config.ControllerConfig{DataDir: dir}}
				if stop, err := s.startAdmin(); err == nil {
					stop()
					t.Fatal("replaced regular socket path")
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "keep" {
					t.Fatal("damaged socket path")
				}
				return
			}
			if lock, err := AcquireStateLock(dir); err == nil {
				lock.Close()
				t.Fatal("unsafe path acquired")
			}
		})
	}
}

func TestRestartRejectsConflictingRemovedIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	// Legacy name-only normalization must happen before checking the tombstone.
	if err := store.SaveRegistry(path, &store.Registry{Nodes: []store.NodeInfo{{Name: "a", VPNIP: "10.7.0.2/32"}}, RemovedNodes: map[string]time.Time{"a": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config.ControllerConfig{DataDir: dir, VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24"}); err == nil {
		t.Fatal("active and removed identity loaded")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed startup wrote registry")
	}
}
