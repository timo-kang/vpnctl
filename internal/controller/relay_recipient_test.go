// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
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

func recipientRequest(c *relaycatalog.State, relay, principal string) api.AdminRequest {
	return api.AdminRequest{Operation: "relay.recipient.set", RelayRecipient: &relaycatalog.RecipientUpdate{ControllerID: c.ControllerID, ExpectedGeneration: c.Generation, RelayID: relay, PrincipalID: principal}}
}
func grantRecipient(t *testing.T, s *Server, relay, principal string) *relaycatalog.State {
	t.Helper()
	status, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.status"})
	if e != nil {
		t.Fatal(e)
	}
	result, e := api.Admin(context.Background(), s.cfg.DataDir, recipientRequest(status.RelayCatalog, relay, principal))
	if e != nil {
		t.Fatal(e)
	}
	return result.RelayCatalog
}

func TestRelayRecipientAuthenticatedIsolation(t *testing.T) {
	s, h, clients, _, c := relayFixture(t)
	ctx := context.Background()
	for _, id := range []string{"ra", "rb", "a", "unknown"} {
		_, e := clients["a"].RelayDeployment(ctx, "a", id)
		assertRelayHTTP(t, e, 403, "relay_recipient_denied")
	}
	plain := httptest.NewServer(s.httpHandler())
	defer plain.Close()
	_, e := api.NewClient(plain.URL).RelayDeployment(ctx, "a", "ra")
	assertRelayHTTP(t, e, 401, "")
	// Enrollment alone is not a grant. lifecycleNode completes enrollment/ACK.
	pending, _ := lifecycleNode(t, s, h, "relay-pending")
	_, e = pending.RelayDeployment(ctx, "relay-pending", "ra")
	assertRelayHTTP(t, e, 403, "relay_recipient_denied")
	for _, p := range c.Spec.Paths {
		v, e := clients[p.NodeID].BindRelayPath(ctx, relayRequest(c, p.NodeID, p.ID))
		if e != nil {
			t.Fatal(e)
		}
		c.Generation = v.Generation
	}
	c = grantRecipient(t, s, "ra", "a")
	c = grantRecipient(t, s, "rb", "b")
	for i := 0; i < 30; i++ {
		for _, pair := range [][2]string{{"a", "rb"}, {"b", "ra"}, {"a", "unknown"}} {
			_, e = clients[pair[0]].RelayDeployment(ctx, pair[0], pair[1])
			assertRelayHTTP(t, e, 403, "relay_recipient_denied")
		}
	}
	for _, pair := range [][3]string{{"a", "ra", "2"}, {"b", "rb", "1"}} {
		v, e := clients[pair[0]].RelayDeployment(ctx, pair[0], pair[1])
		if e != nil || fmt.Sprint(len(v.Bindings)) != pair[2] || len(v.Spec.Relays) != 1 || v.Generation != c.Generation {
			t.Fatal("wrong scoped deployment", e)
		}
	}
	// Client-side expected identity cannot spoof the server-authenticated principal.
	if _, e = clients["a"].RelayDeployment(ctx, "b", "ra"); e == nil {
		t.Fatal("recipient mismatch accepted by client")
	}
	grantRecipient(t, s, "ra", "")
	_, e = clients["a"].RelayDeployment(ctx, "a", "ra")
	assertRelayHTTP(t, e, 403, "relay_recipient_denied")
	// Existing node API remains available independently of relay privileges.
	if _, e = clients["a"].RelayCatalog(ctx, "a"); e != nil {
		t.Fatal("withdrawal removed node permission", e)
	}
}

func TestRelayRecipientRenewalRotationRevokeAndReenroll(t *testing.T) {
	s, h, clients, dirs, _ := relayFixture(t)
	ctx := context.Background()
	relay, dir := lifecycleNode(t, s, h, "relay-agent")
	if _, e := relay.Register(ctx, api.RegisterRequest{Name: "relay-agent", PubKey: relayTestKey("legacy-relay-agent")}); e != nil {
		t.Fatal(e)
	}
	clients["relay-agent"], dirs["relay-agent"] = relay, dir
	c := grantRecipient(t, s, "ra", "relay-agent")
	initial, e := pki.LoadCredentials(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"ca.prepare", "ca.activate", "ca.rollback"} {
		if _, e = api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: op}); e != nil {
			t.Fatal(op, e)
		}
		for id, client := range clients {
			if e = client.SyncCredentials(ctx, dirs[id], id); e != nil {
				t.Fatal(op, id, e)
			}
		}
		v, e := relay.RelayDeployment(ctx, "relay-agent", "ra")
		if e != nil || v.Generation != c.Generation {
			t.Fatal("rotation changed recipient permission", e)
		}
	}
	current, e := pki.LoadCredentials(dir)
	if e != nil {
		t.Fatal(e)
	}
	if current.ClientCert == initial.ClientCert {
		t.Fatal("fixture did not renew certificate")
	}
	cert, e := pki.ParseCertificate(current.ClientCert)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)}); e != nil {
		t.Fatal(e)
	}
	_, e = relay.RelayDeployment(ctx, "relay-agent", "ra")
	assertRelayHTTP(t, e, 403, "")
	if _, e = api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "relay-agent"}); e != nil {
		t.Fatal(e)
	}
	disk, e := store.LoadRegistry(s.regPath)
	if e != nil || disk.Version != 3 || len(disk.RelayCatalog.Recipients) != 0 || disk.RelayCatalog.Generation != c.Generation+1 {
		t.Fatal("grant-only identity removal not durable", e)
	}
	// The current identity lifecycle permanently tombstones removed names.
	// A fresh enrollment request cannot bring either identity or grant back.
	tokens, e := s.tokenStore.List()
	if e != nil || len(tokens) == 0 {
		t.Fatal("missing bootstrap fixture token", e)
	}
	csr, _, e := pki.GenerateCSR("relay-agent")
	if e != nil {
		t.Fatal(e)
	}
	_, e = relay.Bootstrap(ctx, api.BootstrapRequest{Name: "relay-agent", Token: tokens[0], CSR: string(csr)})
	assertRelayHTTP(t, e, 403, "")
	newClient, _ := lifecycleNode(t, s, h, "relay-agent-new")
	if _, e = newClient.Register(ctx, api.RegisterRequest{Name: "relay-agent-new", PubKey: relayTestKey("reenrolled-relay-agent")}); e != nil {
		t.Fatal(e)
	}
	_, e = newClient.RelayDeployment(ctx, "relay-agent-new", "ra")
	assertRelayHTTP(t, e, 403, "relay_recipient_denied")
	grantRecipient(t, s, "ra", "relay-agent-new")
	if _, e = newClient.RelayDeployment(ctx, "relay-agent-new", "ra"); e != nil {
		t.Fatal("explicit regrant failed", e)
	}
	_, e = relay.RelayDeployment(ctx, "relay-agent", "ra")
	assertRelayHTTP(t, e, 403, "")
}

func TestRelayRecipientDurabilityAndBackup(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			s, _, clients, _, _ := relayFixture(t)
			ctx := context.Background()
			c := grantRecipient(t, s, "ra", "a")
			req := recipientRequest(c, "ra", "")
			s.saveRegistry = func(path string, reg *store.Registry) error {
				if after {
					if e := store.SaveRegistry(path, reg); e != nil {
						return e
					}
					return &atomicfile.CommitError{Err: syscall.EIO}
				}
				return syscall.ENOSPC
			}
			_, e := api.Admin(ctx, s.cfg.DataDir, req)
			assertRelayHTTP(t, e, 500, "relay_catalog_storage")
			_, e = clients["a"].RelayDeployment(ctx, "a", "ra")
			if after {
				assertRelayHTTP(t, e, 503, "relay_catalog_uncertain")
			} else if e != nil {
				t.Fatal("failed precommit removed grant", e)
			}
			s.saveRegistry = store.SaveRegistry
			// After an uncertain commit, status is unavailable until durability is
			// recovered by retry. The retry may return CAS conflict, never a silent rebase.
			result, e := api.Admin(ctx, s.cfg.DataDir, req)
			if after {
				assertRelayHTTP(t, e, 409, "relay_catalog_conflict")
			} else if e != nil || len(result.RelayCatalog.Recipients) != 0 {
				t.Fatal("withdraw retry", e)
			}
			_, e = clients["a"].RelayDeployment(ctx, "a", "ra")
			assertRelayHTTP(t, e, 403, "relay_recipient_denied")
			grantRecipient(t, s, "rb", "b")
			reloaded, e := NewServer(s.cfg)
			if e != nil || reloaded.reg.Version != 3 {
				t.Fatal("version 3 restart", e)
			}
			if _, ok := reloaded.reg.RelayCatalog.DeploymentFor("b", "rb"); !ok {
				t.Fatal("restart lost grant")
			}
			snapshot, e := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "pki.backup"})
			if e != nil {
				t.Fatal(e)
			}
			cfg, e := RestoreBackup(snapshot.Backup, filepath.Join(t.TempDir(), "restore"))
			if e != nil {
				t.Fatal(e)
			}
			restored, e := NewServer(*cfg.Controller)
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := restored.reg.RelayCatalog.DeploymentFor("b", "rb"); !ok {
				t.Fatal("backup lost recipient")
			}
			var bad controllerBackup
			if e = json.Unmarshal(snapshot.Backup, &bad); e != nil {
				t.Fatal(e)
			}
			bad.Registry.RelayCatalog.Recipients[0].PrincipalID = "unregistered"
			raw, _ := json.Marshal(bad)
			if _, e = RestoreBackup(raw, filepath.Join(t.TempDir(), "bad")); e == nil {
				t.Fatal("invalid grant restored")
			}
		})
	}
}

func TestRelayRecipientConcurrentCASAndExpiry(t *testing.T) {
	s, _, clients, _, c := relayFixture(t)
	req := recipientRequest(c, "ra", "a")
	errs := make(chan error, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := api.Admin(context.Background(), s.cfg.DataDir, req); errs <- e }()
	}
	wg.Wait()
	close(errs)
	success := 0
	for e := range errs {
		if e == nil {
			success++
		} else {
			var h *api.HTTPError
			if !errors.As(e, &h) || h.StatusCode != 503 {
				assertRelayHTTP(t, e, 409, "relay_catalog_conflict")
			}
		}
	}
	if success != 1 {
		t.Fatal("CAS allowed duplicate grant commits", success)
	}
	c = grantRecipient(t, s, "ra", "a")
	if c.Generation != 2 {
		t.Fatal("repeat grant advanced revision")
	}
	// Parse validation is independent from authentication and does not grant it.
	for _, query := range []string{"schema_version=2&relay_id=ra", "schema_version=1&relay_id=ra&relay_id=rb", "schema_version=1&relay_id=ra&principal_id=b", "schema_version=1&relay_id=ra%zz"} {
		r := httptest.NewRequest("GET", "/relay-deployment?"+query, nil)
		r = r.WithContext(context.WithValue(r.Context(), nodeIdentityContextKey{}, authenticatedNode{id: "a"}))
		w := httptest.NewRecorder()
		s.handleRelayDeployment(w, r)
		if w.Code != 400 {
			t.Fatal("ambiguous query accepted", query, w.Code)
		}
	}
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
	_, e = clients["a"].RelayDeployment(context.Background(), "a", "ra")
	assertRelayHTTP(t, e, 409, "relay_catalog_expired")
	// Expiry never prevents a local administrator from withdrawing access.
	grantRecipient(t, s, "ra", "")
	_, e = clients["a"].RelayDeployment(context.Background(), "a", "ra")
	assertRelayHTTP(t, e, 403, "relay_recipient_denied")
}

func TestRelayRecipientQueuedGrantRechecksRemovedPrincipal(t *testing.T) {
	s, h, _, _, c := relayFixture(t)
	_, _ = lifecycleNode(t, s, h, "deployment-only")
	release, e := s.registryAdmission.admit(context.Background(), false, "registry_writer")
	if e != nil {
		t.Fatal(e)
	}
	var once sync.Once
	unlock := func() { once.Do(release) }
	defer unlock()
	done := make(chan error, 1)
	// Admin IPC deliberately serializes mutations. Exercise the inner registry
	// admission boundary directly so removal can occur before this grant runs;
	// this does not claim that two IPC mutations bypass their outer admission.
	go func() {
		_, e := s.adminRelayCatalog(recipientRequest(c, "ra", "deployment-only"))
		done <- e
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.registryAdmission.mu.Lock()
		queued := len(s.registryAdmission.priority) > 0
		s.registryAdmission.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("grant did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, e = api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "deployment-only"}); e != nil {
		t.Fatal("queued grant stalled removal", e)
	}
	unlock()
	if e := <-done; !errors.Is(e, relaycatalog.ErrInvalid) {
		t.Fatal("removed principal granted access", e)
	}
	disk, e := store.LoadRegistry(s.regPath)
	if e != nil || len(disk.RelayCatalog.Recipients) != 0 || disk.RelayCatalog.Generation != c.Generation {
		t.Fatal("queued grant resurrected removed principal", e)
	}
}
