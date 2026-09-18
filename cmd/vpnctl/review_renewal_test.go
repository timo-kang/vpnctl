// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/pki"
)

func TestReviewNodeServeRenewsDuringRegistrationFailure(t *testing.T) {
	for _, busy := range []bool{false, true} {
		t.Run(fmt.Sprintf("probe_port_busy_%t", busy), func(t *testing.T) { testNodeServeRenewalAndProbe(t, busy) })
	}
}

func testNodeServeRenewalAndProbe(t *testing.T, busy bool) {
	dir := t.TempDir()
	a, err := pki.OpenAuthority(filepath.Join(dir, "ca"), pki.Policy{CALifetime: time.Hour, ServerLifetime: time.Hour, ClientLifetime: 6 * time.Second, ClientRenewBefore: 4 * time.Second, CheckInterval: 100 * time.Millisecond, SANs: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	csr, key, err := pki.GenerateCSR("node")
	if err != nil {
		t.Fatal(err)
	}
	cert, status, err := a.Issue(csr, "node")
	if err != nil {
		t.Fatal(err)
	}
	pkiDir := filepath.Join(dir, "node-pki")
	creds := pki.Credentials{Version: 1, Generation: status.Generation, CACert: status.CACert, ClientCert: cert, ClientKey: string(key)}
	if err := pki.SaveCredentials(pkiDir, creds, ""); err != nil {
		t.Fatal(err)
	}
	var registrations, trusts, renewals, recovered atomic.Int32
	var failRegistration atomic.Bool
	failRegistration.Store(true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			registrations.Add(1)
			if failRegistration.Load() {
				http.Error(w, "temporary registry I/O failure", 503)
			} else {
				recovered.Add(1)
				json.NewEncoder(w).Encode(api.RegisterResponse{NodeID: "node", VPNIP: "10.7.0.2/32"})
			}
		case "/pki/trust":
			trusts.Add(1)
			s := a.Status()
			json.NewEncoder(w).Encode(api.TrustState{Generation: s.Generation, CACert: s.CACert, Active: s.Active, Phase: s.Phase, RenewBeforeSeconds: s.RenewBeforeSeconds})
		case "/pki/renew":
			renewals.Add(1)
			var req api.RenewRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			c, s, err := a.Renew([]byte(req.CSR), "node", r.TLS.PeerCertificates[0])
			if err != nil {
				http.Error(w, err.Error(), 503)
				return
			}
			json.NewEncoder(w).Encode(api.RenewResponse{ClientCert: c, TrustState: api.TrustState{Generation: s.Generation, CACert: s.CACert, Active: s.Active, Phase: s.Phase, RenewBeforeSeconds: s.RenewBeforeSeconds}})
		case "/pki/ack":
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = a.DynamicTLSConfig()
	server.Config.ErrorLog = nil
	server.StartTLS()
	defer server.Close()
	for _, name := range []string{"wg", "ip"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	disabled := false
	cfg := config.Config{Node: &config.NodeConfig{Name: "node", Controller: server.URL, PKIDir: pkiDir, WGPrivateKey: "test-private", WGPublicKey: "test-public", VPNIP: "10.7.0.2/32", ServerPublicKey: "server-public", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}, WGConfigPath: filepath.Join(dir, "wg.conf"), DirectMode: "off", PolicyRoutingEnabled: &disabled}}
	// The occupied-port case must still start renewal before any probe/session
	// is possible. A collision must not bypass the maintenance supervisor.
	occupied, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cfg.Node.ProbePort = occupied.LocalAddr().(*net.UDPAddr).Port
	if !busy {
		occupied.Close()
	}
	path := filepath.Join(dir, "node.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	cmd := cliProcess(t, "node", "serve", "--config", path, "--retry-delay", "50ms", "--retry-max-delay", "100ms")
	cmd.Env = append(cmd.Env, "PATH="+dir+":"+os.Getenv("PATH"))
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	leaf, err := pki.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		deadline := time.Now().Add(2 * time.Second)
		for {
			_, err := direct.ProbePeer(context.Background(), "127.0.0.1:0", fmt.Sprintf("127.0.0.1:%d", cfg.Node.ProbePort), 100*time.Millisecond)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("CLI sync failure blocked probe responder", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	time.Sleep(time.Until(leaf.NotAfter) + 200*time.Millisecond)
	if registrations.Load() < 2 {
		t.Fatal("registration retry fixture not exercised")
	}
	installed, err := pki.LoadCredentials(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	installedLeaf, err := pki.ParseCertificate(installed.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if !installedLeaf.NotAfter.After(time.Now()) {
		t.Fatalf("valid certificate expired while register was retrying: registrations=%d trust=%d renew=%d", registrations.Load(), trusts.Load(), renewals.Load())
	}
	if trusts.Load() == 0 || renewals.Load() == 0 {
		t.Fatal("maintenance did not run")
	}
	occupied.Close()
	failRegistration.Store(false)
	deadline := time.Now().Add(3 * time.Second)
	for recovered.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if recovered.Load() < 2 {
		t.Fatal("same identity did not resume registration and agent startup")
	}
	cfgAfter, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := direct.ProbePeer(context.Background(), "127.0.0.1:0", fmt.Sprintf("127.0.0.1:%d", cfg.Node.ProbePort), time.Second); err != nil {
		t.Fatal("probe did not recover with session", err)
	}
	if cfgAfter.Node.Name != "node" || cfgAfter.Node.VPNIP != "10.7.0.2/32" {
		t.Fatal("recovery changed identity/lease")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		waited = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SIGTERM failed to join PKI maintenance")
	}

}

func TestCredentialSupervisorRetainsAndReplacesOneWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var supervisor credentialSupervisor
	defer supervisor.stop()
	cfg := config.NodeConfig{Name: "a", PKIDir: t.TempDir(), Controller: "https://127.0.0.1:1"}
	supervisor.configure(cfg)
	supervisor.start(ctx)
	original := supervisor.done
	for i := 0; i < 50; i++ {
		supervisor.configure(cfg)
		supervisor.start(ctx)
		if supervisor.done != original {
			t.Fatal("duplicated worker on retry")
		}
	}
	cfg.Name = "b"
	supervisor.configure(cfg)
	select {
	case <-original:
	default:
		t.Fatal("old worker not drained before identity change")
	}
	supervisor.start(ctx)
	replacement := supervisor.done
	if replacement == original || replacement == nil {
		t.Fatal("worker not replaced")
	}
	supervisor.stop()
	select {
	case <-replacement:
	default:
		t.Fatal("worker not joined")
	}
}
