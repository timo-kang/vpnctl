// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
)

func lifecycleServer(t *testing.T, clientLife ...string) (*Server, *httptest.Server) {
	t.Helper()
	dir, err := os.MkdirTemp("", "vpnctl-pki-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	owner, err := AcquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	clientLifetime, clientWindow := "8s", "6s"
	if len(clientLife) > 0 {
		clientLifetime, clientWindow = clientLife[0], "1s"
	}
	s, err := NewServer(config.ControllerConfig{DataDir: dir, Listen: "127.0.0.1:0", VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", PKI: &config.PKIConfig{CAExpiry: "2m", ServerExpiry: "8s", ClientExpiry: clientLifetime, ServerRenewBefore: "6s", ClientRenewBefore: clientWindow, CheckInterval: "100ms", CAOverlap: "1s"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InitPKI(); err != nil {
		t.Fatal(err)
	}
	stopAdmin, err := s.startAdmin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopAdmin)
	h, _, _ := testTLSAPI(t, s)
	stopPKI := s.startPKIMaintenance()
	t.Cleanup(stopPKI)
	return s, h
}

func lifecycleNode(t *testing.T, s *Server, h *httptest.Server, id string) (*api.Client, string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(s.authority.Status().CACert))
	bootstrap := api.NewTLSClient(h.URL, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})
	t.Cleanup(bootstrap.CloseIdleConnections)
	tokens, err := s.tokenStore.List()
	if err != nil || len(tokens) == 0 {
		t.Fatal("bootstrap token unavailable", err)
	}
	csr, key, err := pki.GenerateCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := bootstrap.Bootstrap(context.Background(), api.BootstrapRequest{Name: id, Token: tokens[0], CSR: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	credentials := pki.Credentials{Version: 1, Generation: issued.Generation, CACert: issued.CACert, ClientCert: issued.ClientCert, ClientKey: string(key)}
	if err := credentials.ValidateForInstall(id); err != nil {
		t.Fatal(err)
	}
	if err := pki.SaveCredentials(dir, credentials, ""); err != nil {
		t.Fatal(err)
	}
	client := api.NewCredentialClient(h.URL, dir)
	t.Cleanup(client.CloseIdleConnections)
	if err := client.SyncCredentials(context.Background(), dir, id); err != nil {
		t.Fatal(err)
	}
	return client, dir
}

func startNodePKI(t *testing.T, c *api.Client, dir, id string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.MaintainCredentials(ctx, dir, id) }()
	t.Cleanup(func() { cancel(); <-done })
}

func waitPKI(t *testing.T, limit time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("PKI convergence deadline exceeded")
}

func TestPKIAutomaticClientAndServerRenewal(t *testing.T) {
	s, h := lifecycleServer(t)
	c, dir := lifecycleNode(t, s, h, "a")
	initial, _ := pki.LoadCredentials(dir)
	serverFP := s.authority.Status().Server.Fingerprint
	startNodePKI(t, c, dir, "a")
	waitPKI(t, 6*time.Second, func() bool {
		current, err := pki.LoadCredentials(dir)
		return err == nil && current.ClientCert != initial.ClientCert && s.authority.Status().Server.Fingerprint != serverFP
	})
	current, _ := pki.LoadCredentials(dir)
	before, _ := pki.ParseCertificate(initial.ClientCert)
	after, _ := pki.ParseCertificate(current.ClientCert)
	if !after.NotAfter.After(before.NotAfter) {
		t.Fatal("automatic renewal did not extend certificate")
	}
	for i := 0; i < 30; i++ {
		if _, err := c.FleetStatus(context.Background()); err != nil {
			t.Fatal("renewal interrupted API", err)
		}
	}
}

func TestPKIRevocationRejectsEstablishedConnectionAndRenewal(t *testing.T) {
	s, h := lifecycleServer(t, "30s")
	client, dir := lifecycleNode(t, s, h, "a")
	creds, _ := pki.LoadCredentials(dir)
	cfg, err := creds.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: cfg}
	defer transport.CloseIdleConnections()
	rawClient := &http.Client{Transport: transport, Timeout: time.Second}
	// Consume the first response so the next request reuses its TLS connection.
	response, err := rawClient.Get(h.URL + "/fleet/status")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	cert, _ := pki.ParseCertificate(creds.ClientCert)
	if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)}); err != nil {
		t.Fatal(err)
	}
	response, err = rawClient.Get(h.URL + "/fleet/status")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("revoked established connection status=%d", response.StatusCode)
	}
	csr, _, _ := pki.GenerateCSR("another-identity")
	for i := 0; i < 30; i++ {
		if _, err := client.Renew(context.Background(), string(csr)); err == nil {
			t.Fatal("revoked credential renewed")
		}
		if _, err := client.FleetStatus(context.Background()); err == nil {
			t.Fatal("revoked credential read fleet")
		}
	}
	// A separate certificate for the same identity remains usable; node deletion
	// remains the operation for disabling the entire device/identity.
	replacement, _ := lifecycleNode(t, s, h, "a")
	if _, err := replacement.FleetStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.backup"})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	restoredCfg, err := RestoreBackup(snapshot.Backup, target)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewServer(*restoredCfg.Controller)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := restored.InitPKI(); err != nil || token != "" {
		t.Fatal("restore regenerated bootstrap token", err)
	}
	if err := restored.authority.Observe(cert, "a"); err == nil {
		t.Fatal("restore lost revocation")
	}
}

func TestPKICARotationVariableFleetAndNoAPIInterruption(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprintf("nodes_%d", size), func(t *testing.T) {
			s, h := lifecycleServer(t, "30s")
			clients := make([]*api.Client, size)
			dirs := make([]string, size)
			for n := range clients {
				clients[n], dirs[n] = lifecycleNode(t, s, h, fmt.Sprintf("n-%d", n))
			}
			old := s.authority.Status().Active
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			var failures atomic.Int32
			var successes atomic.Int32
			for _, c := range clients {
				wg.Add(1)
				go func(c *api.Client) {
					defer wg.Done()
					for ctx.Err() == nil {
						if _, err := c.FleetStatus(ctx); err != nil {
							if ctx.Err() == nil {
								failures.Add(1)
							}
						} else {
							successes.Add(1)
						}
						time.Sleep(10 * time.Millisecond)
					}
				}(c)
			}
			defer func() { cancel(); wg.Wait() }()
			admin := func(op string) {
				t.Helper()
				if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: op}); err != nil {
					t.Fatal(op, err)
				}
			}
			admin("ca.prepare")
			if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "ca.activate"}); err == nil {
				t.Fatal("CA activation ignored missing trust acknowledgements")
			}
			for n, c := range clients {
				if err := c.SyncCredentials(context.Background(), dirs[n], fmt.Sprintf("n-%d", n)); err != nil {
					t.Fatal(err)
				}
			}
			admin("ca.activate")
			if s.authority.Status().Active == old {
				t.Fatal("issuer did not rotate")
			}
			for n, c := range clients {
				if err := c.SyncCredentials(context.Background(), dirs[n], fmt.Sprintf("n-%d", n)); err != nil {
					t.Fatal(err)
				}
			}
			until := s.authority.Status().OverlapUntil
			waitPKI(t, 2*time.Second, func() bool { return !time.Now().Before(until) })
			admin("ca.retire")
			for n, c := range clients {
				if err := c.SyncCredentials(context.Background(), dirs[n], fmt.Sprintf("n-%d", n)); err != nil {
					t.Fatal(err)
				}
			}
			if len(s.authority.Status().CAs) != 1 || s.authority.Status().Phase != "stable" {
				t.Fatal("retirement incomplete")
			}
			cancel()
			wg.Wait()
			t.Logf("CA rotation nodes=%d successful_requests=%d failed_requests=%d", size, successes.Load(), failures.Load())
			if failures.Load() != 0 || successes.Load() < int32(size) {
				t.Fatalf("planned rotation API interruptions=%d successful requests=%d", failures.Load(), successes.Load())
			}
		})
	}
}

func TestPKIRenewalBindsIdentityAndRejectsUnauthenticatedTrust(t *testing.T) {
	s, h := lifecycleServer(t, "30s")
	c, dir := lifecycleNode(t, s, h, "a")
	for _, op := range []string{"ca.prepare", "ca.activate"} {
		if op == "ca.activate" {
			if err := c.SyncCredentials(context.Background(), dir, "a"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: op}); err != nil {
			t.Fatal(err)
		}
	}
	csr, key, _ := pki.GenerateCSR("pretend-other-node")
	response, err := c.Renew(context.Background(), string(csr))
	if err != nil {
		t.Fatal(err)
	}
	creds := pki.Credentials{Version: 1, Generation: response.Generation, CACert: response.CACert, ClientCert: response.ClientCert, ClientKey: string(key)}
	if err := creds.ValidateForInstall("a"); err != nil {
		t.Fatal(err)
	}
	if err := creds.ValidateForInstall("pretend-other-node"); err == nil {
		t.Fatal("CSR overrode authenticated identity")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(response.CACert))
	anonymous := api.NewTLSClient(h.URL, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})
	defer anonymous.CloseIdleConnections()
	if _, err := anonymous.Trust(context.Background()); err == nil {
		t.Fatal("anonymous trust endpoint allowed")
	}
}

func TestPKIBackupRefusesLiveOrPartialRestore(t *testing.T) {
	s, _ := lifecycleServer(t)
	backup, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.backup"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreBackup(backup.Backup, s.cfg.DataDir); err == nil {
		t.Fatal("restored over live controller")
	}
	target := filepath.Join(t.TempDir(), "restore")
	restored, err := RestoreBackup(backup.Backup, target)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(target, "pki", "authority.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreBackup(backup.Backup, target); err == nil {
		t.Fatal("overwrote nonempty restore target")
	}
	after, _ := os.ReadFile(filepath.Join(target, "pki", "authority.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("refused restore changed authority")
	}
	if err := os.WriteFile(filepath.Join(target, "restore.pending"), []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(*restored.Controller); err == nil {
		t.Fatal("started partially restored controller")
	}
	if _, err := RestoreBackup(backup.Backup, target); err == nil {
		t.Fatal("resumed a different backup")
	}
	var corrupted map[string]any
	if err := json.Unmarshal(backup.Backup, &corrupted); err != nil {
		t.Fatal(err)
	}
	corrupted["authority"] = map[string]any{"version": 1}
	bad, _ := json.Marshal(corrupted)
	if _, err := RestoreBackup(bad, filepath.Join(t.TempDir(), "bad")); err == nil {
		t.Fatal("accepted corrupt backup")
	}
}

func TestPKIExpiryIsRecheckedOnExistingConnection(t *testing.T) {
	s, h := lifecycleServer(t, "3s")
	_, dir := lifecycleNode(t, s, h, "a")
	creds, _ := pki.LoadCredentials(dir)
	cfg, err := creds.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: cfg}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	first, err := client.Get(h.URL + "/fleet/status")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, first.Body)
	first.Body.Close()
	cert, _ := pki.ParseCertificate(creds.ClientCert)
	waitPKI(t, 4*time.Second, func() bool { return !time.Now().Before(cert.NotAfter) })
	expired, err := client.Get(h.URL + "/fleet/status")
	if err != nil {
		t.Fatal("expected keep-alive HTTP rejection", err)
	}
	defer expired.Body.Close()
	if expired.StatusCode != 403 {
		t.Fatalf("expired keep-alive certificate status=%d", expired.StatusCode)
	}
}

func TestPKIInterruptedRestoreCanResumeSameSnapshot(t *testing.T) {
	s, _ := lifecycleServer(t)
	backup, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.backup"})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "partial")
	if err := os.MkdirAll(filepath.Join(target, "pki"), 0700); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(backup.Backup))
	if err := os.WriteFile(filepath.Join(target, "restore.pending"), []byte(digest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "pki", "authority.json"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := RestoreBackup(backup.Backup, target)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewServer(*cfg.Controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.InitPKI(); err != nil {
		t.Fatal(err)
	}
	if restored.authority.Status().Active != s.authority.Status().Active {
		t.Fatal("restore changed signing CA")
	}
	if _, err := os.Stat(filepath.Join(target, "restore.pending")); !os.IsNotExist(err) {
		t.Fatal("restore marker not cleared")
	}
}

func TestPKIRenewalSurvivesLostResponseAndNodeClientRestart(t *testing.T) {
	s, _ := lifecycleServer(t, "30s")
	inner := s.httpHandler()
	var dropped atomic.Bool
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pki/renew" && dropped.CompareAndSwap(false, true) {
			recorded := httptest.NewRecorder()
			inner.ServeHTTP(recorded, r)
			if recorded.Code != 200 {
				for k, v := range recorded.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(recorded.Code)
				w.Write(recorded.Body.Bytes())
				return
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				connection.Close()
			}
			return
		}
		inner.ServeHTTP(w, r)
	}))
	h.TLS = s.authority.DynamicTLSConfig()
	h.StartTLS()
	defer h.Close()
	c, dir := lifecycleNode(t, s, h, "a")
	for _, op := range []string{"ca.prepare", "ca.activate"} {
		if op == "ca.activate" {
			if err := c.SyncCredentials(context.Background(), dir, "a"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: op}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SyncCredentials(context.Background(), dir, "a"); err == nil {
		t.Fatal("lost response did not fail request")
	}
	pending, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Pending == nil || pending.ClientCert != before.ClientCert {
		t.Fatal("lost response discarded old credentials or pending key")
	}
	issued := len(s.authority.Status().Certificates)
	restarted := api.NewCredentialClient(h.URL, dir)
	defer restarted.CloseIdleConnections()
	if err := restarted.SyncCredentials(context.Background(), dir, "a"); err != nil {
		t.Fatal(err)
	}
	recovered, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Pending != nil || recovered.ClientCert == before.ClientCert {
		t.Fatal("pending renewal not installed")
	}
	if len(s.authority.Status().Certificates) != issued {
		t.Fatal("retry issued another certificate")
	}
	if _, err := restarted.FleetStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPKIMetricsExposeRevocationAndOverlap(t *testing.T) {
	s, h := lifecycleServer(t, "30s")
	_, dir := lifecycleNode(t, s, h, "a")
	creds, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(creds.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []api.AdminRequest{{Operation: "ca.prepare"}, {Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)}} {
		if _, err := api.Admin(context.Background(), s.cfg.DataDir, req); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(creds.CACert))
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get(h.URL + "/prom/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`vpnctl_pki_certificates{status="revoked"} 1`, `vpnctl_pki_ca_overlap 1`, `vpnctl_pki_expiry_seconds{kind="server"}`, `vpnctl_pki_expiry_seconds{kind="ca"}`} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("missing metric %s", expected)
		}
	}
	if strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("metrics leaked private material")
	}
}
