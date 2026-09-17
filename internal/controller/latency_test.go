package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

type slowApplyRunner struct {
	entered, release chan struct{}
	once             sync.Once
}

func (r *slowApplyRunner) Output(string, ...string) (string, error) { return "", nil }
func (r *slowApplyRunner) Run(name string, _ ...string) error {
	if name == "wg" {
		r.once.Do(func() { close(r.entered); <-r.release })
	}
	return nil
}

// A single admitted writer must not consume the 1s fleet SLO for 32 unrelated
// authenticated readers. Until durable commit they must see the previous state.
func TestFleetReadsDuringSlowMutation(t *testing.T) {
	for _, fault := range []string{"wg", "disk"} {
		t.Run(fault, func(t *testing.T) {
			s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", WGInterface: "test-wg", WGPrivateKey: "test-private", Listen: "127.0.0.1:0", PKI: &config.PKIConfig{}})
			if err != nil {
				t.Fatal(err)
			}
			s.wg = wireguard.NewManager(&slowApplyRunner{})
			token, err := s.InitPKI()
			if err != nil {
				t.Fatal(err)
			}
			h, bootstrap, tlsCfg := testTLSAPI(t, s)
			var clients []*api.Client
			for i := 0; i < 32; i++ {
				c, _, _ := enrollTestClient(t, h, bootstrap, tlsCfg, token, fmt.Sprintf("node-%d", i))
				clients = append(clients, c)
				defer c.CloseIdleConnections()
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			if fault == "wg" {
				s.cfg.WGApply = true
				s.wg = wireguard.NewManager(&slowApplyRunner{entered: entered, release: release})
			} else {
				s.saveRegistry = func(path string, reg *store.Registry) error {
					close(entered)
					<-release
					return store.SaveRegistry(path, reg)
				}
			}
			written := make(chan error, 1)
			go func() {
				_, err := clients[0].Register(context.Background(), api.RegisterRequest{Name: "node-0", PubKey: "pub-node-0", NATType: "pending"})
				written <- err
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("fault not reached")
			}
			results := make(chan error, len(clients))
			for _, c := range clients {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					resp, err := c.FleetStatus(ctx)
					if err == nil {
						for _, n := range resp.Nodes {
							if n.NATType == "pending" {
								err = fmt.Errorf("uncommitted mutation visible")
							}
						}
					}
					results <- err
				}()
			}
			failed := 0
			for range clients {
				if err := <-results; err != nil {
					failed++
				}
			}
			unblock()
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			t.Logf("%s fault: 32 readers, %d exceeded deadline or saw pending state", fault, failed)
			if failed != 0 {
				t.Fatalf("slow %s blocked or corrupted %d fleet reads", fault, failed)
			}
			resp, err := clients[0].FleetStatus(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, n := range resp.Nodes {
				if n.Name == "node-0" && n.NATType == "pending" {
					found = true
				}
			}
			if !found {
				t.Fatal("completed mutation missing")
			}
		})
	}
}

func TestSerializedRegistryWritersKeepAllUpdates(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		if _, err := s.registerNode(nodeRegistration{Name: fmt.Sprintf("node-%d", i), PubKey: fmt.Sprintf("pub-%d", i)}, false); err != nil {
			t.Fatal(err)
		}
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblock sync.Once
	defer unblock.Do(func() { close(release) })
	s.saveRegistry = func(path string, reg *store.Registry) error {
		once.Do(func() { close(entered); <-release })
		return store.SaveRegistry(path, reg)
	}
	done := make(chan error, 25)
	go func() {
		_, err := s.registerNode(nodeRegistration{Name: "first", PubKey: "pub-first"}, false)
		done <- err
	}()
	<-entered
	for i := 0; i < 8; i++ {
		go func() {
			_, err := s.registerNode(nodeRegistration{Name: fmt.Sprintf("new-%d", i), PubKey: fmt.Sprintf("new-pub-%d", i)}, false)
			done <- err
		}()
	}
	for i := 0; i < 16; i++ {
		go func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/nat-probe", strings.NewReader(fmt.Sprintf(`{"node_id":"node-%d","nat_type":"updated"}`, i)))
			s.httpHandler().ServeHTTP(rec, req)
			var err error
			if rec.Code != http.StatusNoContent {
				err = fmt.Errorf("NAT update %d: %d", i, rec.Code)
			}
			done <- err
		}()
	}
	unblock.Do(func() { close(release) })
	for i := 0; i < 25; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	disk, err := store.LoadRegistry(s.regPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.Nodes) != 25 {
		t.Fatalf("lost registry writes: %d", len(disk.Nodes))
	}
	ips := map[string]bool{}
	for _, n := range disk.Nodes {
		if ips[n.VPNIP] {
			t.Fatal("duplicate lease", n.VPNIP)
		}
		ips[n.VPNIP] = true
		if strings.HasPrefix(n.ID, "node-") && n.NATType != "updated" {
			t.Fatal("NAT update lost", n.ID)
		}
	}
}

type delayedResponse struct {
	entered, release chan struct{}
	header           http.Header
}

func (w *delayedResponse) Header() http.Header { return w.header }
func (w *delayedResponse) WriteHeader(int)     {}
func (w *delayedResponse) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}
func TestSlowFleetResponseDoesNotHoldRegistry(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	w := &delayedResponse{entered: make(chan struct{}), release: make(chan struct{}), header: http.Header{}}
	var once sync.Once
	defer once.Do(func() { close(w.release) })
	done := make(chan struct{})
	go func() { s.handleFleetStatus(w, httptest.NewRequest("GET", "/fleet/status", nil)); close(done) }()
	<-w.entered
	written := make(chan error, 1)
	go func() {
		_, err := s.registerNode(nodeRegistration{Name: "new", PubKey: "pub-new"}, false)
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow HTTP writer blocked registry")
	}
	once.Do(func() { close(w.release) })
	<-done
}

func TestRegistryIOPanicRestoresCallerLock(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	s.saveRegistry = func(string, *store.Registry) error { panic("injected writer panic") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("fault not reached")
			}
		}()
		_, _ = s.registerNode(nodeRegistration{Name: "failed", PubKey: "pub-failed"}, false)
	}()
	s.saveRegistry = store.SaveRegistry
	if _, err := s.registerNode(nodeRegistration{Name: "next", PubKey: "pub-next"}, false); err != nil {
		t.Fatal(err)
	}
	if len(s.reg.Nodes) != 1 || s.reg.Nodes[0].ID != "next" {
		t.Fatal("uncommitted registry published")
	}
}

func TestReadOnlyPKIStatusDoesNotWaitForAdmittedReaders(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", Listen: "127.0.0.1:0", PKI: &config.PKIConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InitPKI(); err != nil {
		t.Fatal(err)
	}
	s.stateMu.RLock()
	done := make(chan error, 1)
	go func() { _, err := s.adminPKI(api.AdminRequest{Operation: "pki.status"}); done <- err }()
	select {
	case err := <-done:
		s.stateMu.RUnlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		s.stateMu.RUnlock()
		<-done
		t.Fatal("read-only status took global write admission")
	}
}
