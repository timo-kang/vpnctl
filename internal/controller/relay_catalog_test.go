// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/atomicfile"
	"vpnctl/internal/pki"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/store"
)

func relayTestKey(label string) string {
	seed := sha256.Sum256([]byte(label))
	k, _ := ecdh.X25519().NewPrivateKey(seed[:])
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func relayTestSpec() relaycatalog.Spec {
	return relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24", ReservedIPs: []string{"10.78.0.1"}, Relays: []relaycatalog.Relay{
		{ID: "ra", PublicKey: relayTestKey("ra"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "192.0.2.11:51820"}}},
		{ID: "rb", PublicKey: relayTestKey("rb"), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "198.51.100.12:51820"}}},
	}, Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Protocol: "tcp", Port: 443}}, Paths: []relaycatalog.Path{
		{ID: "a-primary", NodeID: "a", RelayID: "ra", EndpointID: "e", UnderlayID: "wifi", TargetIDs: []string{"app"}},
		{ID: "a-backup", NodeID: "a", RelayID: "rb", EndpointID: "e", UnderlayID: "ethernet", TargetIDs: []string{"app"}},
		{ID: "b-primary", NodeID: "b", RelayID: "ra", EndpointID: "e", UnderlayID: "wifi", TargetIDs: []string{"app"}},
	}}
}
func relayFixture(t *testing.T) (*Server, *httptest.Server, map[string]*api.Client, map[string]string, *relaycatalog.State) {
	t.Helper()
	s, h := lifecycleServer(t, "1h", "24h", "40m")
	clients := map[string]*api.Client{}
	dirs := map[string]string{}
	for _, id := range []string{"a", "b"} {
		clients[id], dirs[id] = lifecycleNode(t, s, h, id)
		if _, e := clients[id].Register(context.Background(), api.RegisterRequest{Name: id, PubKey: relayTestKey("legacy-" + id)}); e != nil {
			t.Fatal(e)
		}
	}
	result, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.apply", RelayCatalog: &relaycatalog.Update{TTLSeconds: 3600, Spec: relayTestSpec()}})
	if e != nil {
		t.Fatal(e)
	}
	return s, h, clients, dirs, result.RelayCatalog
}
func relayRequest(c *relaycatalog.State, node, path string) relaycatalog.BindRequest {
	return relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: c.ControllerID, ExpectedGeneration: c.Generation, NodeID: node, PathID: path, PublicKey: relayTestKey(path)}
}
func assertRelayHTTP(t *testing.T, e error, status int, code string) {
	t.Helper()
	var h *api.HTTPError
	if !errors.As(e, &h) || h.StatusCode != status || code != "" && h.Code != code {
		t.Fatalf("expected HTTP %d/%s, got %v", status, code, e)
	}
}

func TestRelayCatalogTLSOwnershipAndLegacyCompatibility(t *testing.T) {
	s, _, clients, dirs, c := relayFixture(t)
	a, e := clients["a"].RelayCatalog(context.Background(), "a")
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Spec.Paths) != 2 || len(a.Spec.Relays) != 2 || len(a.Bindings) != 0 {
		t.Fatal("bad authorized view")
	}
	_, e = clients["a"].RelayCatalog(context.Background(), "b")
	assertRelayHTTP(t, e, 403, "")
	foreign := relayRequest(c, "b", "b-primary")
	_, e = clients["a"].BindRelayPath(context.Background(), foreign)
	assertRelayHTTP(t, e, 403, "")
	plain := httptest.NewServer(s.httpHandler())
	defer plain.Close()
	_, e = api.NewClient(plain.URL).RelayCatalog(context.Background(), "a")
	assertRelayHTTP(t, e, 401, "")
	req := relayRequest(c, "a", "a-primary")
	unsupported := req
	unsupported.SchemaVersion = 9
	_, e = clients["a"].BindRelayPath(context.Background(), unsupported)
	assertRelayHTTP(t, e, 400, "relay_catalog_invalid")

	view, e := clients["a"].BindRelayPath(context.Background(), req)
	if e != nil {
		t.Fatal(e)
	}
	again, e := clients["a"].BindRelayPath(context.Background(), req)
	if e != nil || again.Generation != view.Generation || len(again.Bindings) != 1 {
		t.Fatal("idempotent retry", e)
	}
	req2 := relayRequest(c, "b", "b-primary")
	req2.ExpectedGeneration = view.Generation
	req2.PublicKey = req.PublicKey
	_, e = clients["b"].BindRelayPath(context.Background(), req2)
	assertRelayHTTP(t, e, 409, "relay_catalog_conflict")
	_, e = clients["b"].Register(context.Background(), api.RegisterRequest{Name: "b", PubKey: req.PublicKey})
	assertRelayHTTP(t, e, 400, "")
	alias, _ := base64.StdEncoding.DecodeString(req.PublicKey)
	alias[31] |= 128
	_, e = clients["b"].Register(context.Background(), api.RegisterRequest{Name: "b", PubKey: base64.StdEncoding.EncodeToString(alias)})
	assertRelayHTTP(t, e, 400, "")
	// No route/peer configuration is inferred from a binding.
	s.mu.Lock()
	nodes := append([]store.NodeInfo(nil), s.reg.Nodes...)
	s.mu.Unlock()
	for _, n := range nodes {
		if n.PubKey != relayTestKey("legacy-"+n.ID) {
			t.Fatal("legacy key changed")
		}
	}
	old, _ := pki.LoadCredentials(dirs["a"])
	cert, _ := pki.ParseCertificate(old.ClientCert)
	_, e = api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)})
	if e != nil {
		t.Fatal(e)
	}
	_, e = clients["a"].RelayCatalog(context.Background(), "a")
	assertRelayHTTP(t, e, 403, "")
	_, e = clients["a"].BindRelayPath(context.Background(), req)
	assertRelayHTTP(t, e, 403, "")
}
func TestRelayCatalogConcurrentCASAndBindings(t *testing.T) {
	s, _, clients, _, c := relayFixture(t)
	errs := make(chan error, 30)
	var wg sync.WaitGroup
	paths := []struct{ node, path string }{{"a", "a-primary"}, {"a", "a-backup"}, {"b", "b-primary"}}
	for i := 0; i < 30; i++ {
		p := paths[i%len(paths)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last error
			for attempt := 0; attempt < 10; attempt++ {
				v, e := clients[p.node].RelayCatalog(context.Background(), p.node)
				if e != nil {
					last = e
					break
				}
				req := relayRequest(c, p.node, p.path)
				req.ExpectedGeneration = v.Generation
				if _, e = clients[p.node].BindRelayPath(context.Background(), req); e == nil {
					errs <- nil
					return
				}
				var h *api.HTTPError
				if !errors.As(e, &h) || h.Code != "relay_catalog_conflict" {
					last = e
					break
				}
				last = e
			}
			errs <- last
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	status, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.status"})
	if e != nil {
		t.Fatal(e)
	}
	if len(status.RelayCatalog.Bindings) != 3 || status.RelayCatalog.Generation != 4 {
		t.Fatal("duplicate allocations or extra revisions")
	}
	ips := map[string]bool{}
	for _, b := range status.RelayCatalog.Bindings {
		if ips[b.InnerAddress] {
			t.Fatal("duplicate IP")
		}
		ips[b.InnerAddress] = true
	}
	req := api.AdminRequest{Operation: "relay.catalog.apply", RelayCatalog: &relaycatalog.Update{ControllerID: c.ControllerID, ExpectedGeneration: c.Generation, TTLSeconds: 3600, Spec: relayTestSpec()}}
	_, e = api.Admin(context.Background(), s.cfg.DataDir, req)
	assertRelayHTTP(t, e, 409, "relay_catalog_conflict")
}
func TestRelayCatalogDurableFaultsAndRetry(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("after_rename_%t", after), func(t *testing.T) {
			s, _, clients, _, c := relayFixture(t)
			req := relayRequest(c, "a", "a-primary")
			s.saveRegistry = func(path string, reg *store.Registry) error {
				if after {
					if e := store.SaveRegistry(path, reg); e != nil {
						return e
					}
					return &atomicfile.CommitError{Err: syscall.EIO}
				}
				return syscall.ENOSPC
			}
			_, e := clients["a"].BindRelayPath(context.Background(), req)
			assertRelayHTTP(t, e, 500, "relay_catalog_storage")
			disk, e := store.LoadRegistry(s.regPath)
			if e != nil {
				t.Fatal(e)
			}
			want := 0
			if after {
				want = 1
			}
			if len(disk.RelayCatalog.Bindings) != want {
				t.Fatal("wrong visible state")
			}
			if after {
				_, e = clients["a"].RelayCatalog(context.Background(), "a")
				assertRelayHTTP(t, e, 503, "relay_catalog_uncertain")
			} else {
				v, e := clients["a"].RelayCatalog(context.Background(), "a")
				if e != nil || len(v.Bindings) != 0 {
					t.Fatal("failed precommit published", e)
				}
			}
			s.saveRegistry = store.SaveRegistry
			view, e := clients["a"].BindRelayPath(context.Background(), req)
			if e != nil {
				t.Fatal(e)
			}
			if len(view.Bindings) != 1 || view.Generation != 2 {
				t.Fatal("retry changed binding population")
			}
			reloaded, e := NewServer(s.cfg)
			if e != nil {
				t.Fatal(e)
			}
			if reloaded.reg.Version != 2 || reloaded.reg.RelayCatalog.Generation != view.Generation || len(reloaded.reg.RelayCatalog.Bindings) != 1 {
				t.Fatal("restart lost catalog")
			}
		})
	}
}
func TestRelayCatalogRemovalBackupRestore(t *testing.T) {
	s, _, clients, _, c := relayFixture(t)
	req := relayRequest(c, "a", "a-primary")
	_, e := clients["a"].BindRelayPath(context.Background(), req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "a"}); e != nil {
		t.Fatal(e)
	}
	_, e = clients["a"].RelayCatalog(context.Background(), "a")
	assertRelayHTTP(t, e, 403, "")
	snapshot, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.backup"})
	if e != nil {
		t.Fatal(e)
	}
	restored, e := RestoreBackup(snapshot.Backup, filepath.Join(t.TempDir(), "restored"))
	if e != nil {
		t.Fatal(e)
	}
	next, e := NewServer(*restored.Controller)
	if e != nil {
		t.Fatal(e)
	}
	if len(next.reg.RelayCatalog.Bindings) != 1 || next.reg.RelayCatalog.Bindings[0].RetiredAt.IsZero() || len(next.reg.RelayCatalog.NodeView("a").Spec.Paths) != 0 {
		t.Fatal("restore lost tombstones")
	}
	if _, e = store.RemoveNode(next.regPath, "b"); e == nil {
		t.Fatal("offline remove bypassed catalog retirement")
	}
	var broken controllerBackup
	if e = json.Unmarshal(snapshot.Backup, &broken); e != nil {
		t.Fatal(e)
	}
	broken.Registry.RelayCatalog.Bindings[0].InnerAddress = "10.7.0.2/32"
	raw, _ := json.Marshal(broken)
	dest := filepath.Join(t.TempDir(), "invalid")
	if _, e = RestoreBackup(raw, dest); e == nil {
		t.Fatal("invalid catalog backup restored")
	}
	if _, e = os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("invalid backup touched destination")
	}
}
func TestRelayCatalogCommittedReadsAndCanceledWriter(t *testing.T) {
	s, _, clients, _, c := relayFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	s.saveRegistry = func(path string, r *store.Registry) error {
		close(entered)
		<-release
		return store.SaveRegistry(path, r)
	}
	done := make(chan error, 1)
	go func() {
		_, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.apply", RelayCatalog: &relaycatalog.Update{ControllerID: c.ControllerID, ExpectedGeneration: c.Generation, TTLSeconds: 3600, Spec: relayTestSpec()}})
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not enter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, e := clients["a"].RelayCatalog(ctx, "a")
	if e != nil || v.Generation != c.Generation {
		t.Fatal("committed read stalled/changed", e)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	_, e = clients["a"].BindRelayPath(ctx2, relayRequest(c, "a", "a-primary"))
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("queued request did not cancel", e)
	}
	once.Do(func() { close(release) })
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	v, e = clients["a"].RelayCatalog(context.Background(), "a")
	if e != nil || len(v.Bindings) != 0 {
		t.Fatal("canceled binding committed", e)
	}
}
func TestRelayCatalogExpired(t *testing.T) {
	s, _, clients, _, c := relayFixture(t)
	// Advance the validity window without mutating a published catalog pointer.
	s.mutationMu.Lock()
	s.mu.Lock()
	next := cloneRegistry(s.reg)
	copy := *next.RelayCatalog
	copy.IssuedAt = time.Now().Add(-2 * time.Hour)
	copy.ExpiresAt = time.Now().Add(-time.Hour)
	next.RelayCatalog = &copy
	e := s.commitRegistryLocked(next, false)
	s.mu.Unlock()
	s.mutationMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	_, e = clients["a"].RelayCatalog(context.Background(), "a")
	assertRelayHTTP(t, e, 409, "relay_catalog_expired")
	_, e = clients["a"].BindRelayPath(context.Background(), relayRequest(c, "a", "a-primary"))
	assertRelayHTTP(t, e, 409, "relay_catalog_expired")
	// Local administration can still inspect/renew expired approval metadata.
	result, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.status"})
	if e != nil || result.RelayCatalog == nil {
		t.Fatal(e)
	}
}

func TestRelayCatalogQueuedBindingReauthorizes(t *testing.T) {
	for _, operation := range []string{"pki.revoke", "node.remove"} {
		t.Run(operation, func(t *testing.T) {
			s, _, clients, dirs, c := relayFixture(t)
			release, e := s.registryAdmission.admit(context.Background(), false, "registry_writer")
			if e != nil {
				t.Fatal(e)
			}
			var once sync.Once
			unlock := func() { once.Do(release) }
			defer unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, e := clients["a"].BindRelayPath(ctx, relayRequest(c, "a", "a-primary")); done <- e }()
			deadline := time.Now().Add(2 * time.Second)
			for {
				s.registryAdmission.mu.Lock()
				queued := len(s.registryAdmission.normal) > 0
				s.registryAdmission.mu.Unlock()
				if queued {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("binding did not enter registry admission")
				}
				time.Sleep(time.Millisecond)
			}
			req := api.AdminRequest{Operation: operation, NodeID: "a"}
			if operation == "pki.revoke" {
				creds, e := pki.LoadCredentials(dirs["a"])
				if e != nil {
					t.Fatal(e)
				}
				cert, e := pki.ParseCertificate(creds.ClientCert)
				if e != nil {
					t.Fatal(e)
				}
				req.Fingerprint = pki.Fingerprint(cert)
			}
			if _, e = api.Admin(ctx, s.cfg.DataDir, req); e != nil {
				t.Fatal("queued binding stalled security mutation", e)
			}
			unlock()
			assertRelayHTTP(t, <-done, 403, "")
			status, e := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.status"})
			if e != nil || len(status.RelayCatalog.Bindings) != 0 {
				t.Fatal("revoked queued identity committed", e)
			}
		})
	}
}
