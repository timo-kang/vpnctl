// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
)

func TestReviewRegistryLossMustNotResetIdentity(t *testing.T) {
	for _, fault := range []string{"missing", "empty", "null"} {
		t.Run(fault, func(t *testing.T) {
			cfg := config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", Listen: "127.0.0.1:0", PKI: &config.PKIConfig{}}
			s, err := NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			token, err := s.InitPKI()
			if err != nil {
				t.Fatal(err)
			}
			h, b, tc := testTLSAPI(t, s)
			defer b.CloseIdleConnections()
			old, _, oldTLS := enrollTestClient(t, h, b, tc, token, "removed")
			defer old.CloseIdleConnections()
			if err := s.removeNode("removed"); err != nil {
				t.Fatal(err)
			}
			if _, err := old.FleetStatus(context.Background()); err == nil {
				t.Fatal("fixture did not revoke removed identity")
			}
			path := filepath.Join(cfg.DataDir, "registry.yaml")
			switch fault {
			case "missing":
				err = os.Remove(path)
			case "empty":
				err = os.WriteFile(path, nil, 0600)
			case "null":
				err = os.WriteFile(path, []byte("null\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewServer(cfg)
			if err != nil {
				return
			}
			if _, err := restarted.InitPKI(); err != nil {
				t.Fatal(err)
			}
			h2, b2, tc2 := testTLSAPI(t, restarted)
			defer b2.CloseIdleConnections()
			replacement, _, _ := enrollTestClient(t, h2, b2, tc2, token, "removed")
			defer replacement.CloseIdleConnections()
			replay := api.NewTLSClient(h2.URL, oldTLS)
			defer replay.CloseIdleConnections()
			_, err = replay.Register(context.Background(), api.RegisterRequest{Name: "removed", PubKey: "old-device-regained-access"})
			t.Fatalf("controller accepted %s registry; removed identity re-enrolled and old certificate registration error=%v", fault, err)
		})
	}
}

func TestReviewBootstrapIssuanceFailureMustNotPublishLiveNode(t *testing.T) {
	cfg := config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24", Listen: "127.0.0.1:0", PKI: &config.PKIConfig{}}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.InitPKI()
	if err != nil {
		t.Fatal(err)
	}
	_, bootstrap, _ := testTLSAPI(t, s)
	defer bootstrap.CloseIdleConnections()
	path := filepath.Join(cfg.DataDir, "pki", "authority.json")
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	csr, _, err := pki.GenerateCSR("new-node")
	if err != nil {
		t.Fatal(err)
	}
	_, err = bootstrap.Bootstrap(context.Background(), api.BootstrapRequest{Token: token, Name: "new-node", CSR: string(csr)})
	if err == nil {
		t.Fatal("issuance failure not injected")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	_, prepErr := s.adminPKI(api.AdminRequest{Operation: "ca.prepare"})
	if prepErr != nil {
		t.Fatal(prepErr)
	}
	_, activateErr := s.adminPKI(api.AdminRequest{Operation: "ca.activate"})
	if activateErr != nil {
		t.Fatal("failed issuance blocked rotation", activateErr)
	}
	if len(s.reg.Nodes) != 0 {
		t.Fatalf("bootstrap failed but published %d online nodes, certificates=%d; CA activation blocked=%v", len(s.reg.Nodes), len(s.authority.Status().Certificates), activateErr)
	}
}

func TestEnrollmentResponseLossRetryAndConfirmation(t *testing.T) {
	s, h := lifecycleServer(t, "30s")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(s.authority.Status().CACert))
	b := api.NewTLSClient(h.URL, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})
	defer b.CloseIdleConnections()
	token, err := s.tokenStore.CreateWithOptions(time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := pki.GenerateCSR("pending")
	if err != nil {
		t.Fatal(err)
	}
	request := api.BootstrapRequest{Name: "pending", Token: token, CSR: string(csr)}
	issued, err := b.Bootstrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	// Discard issued credentials, as after a lost response. The reserved lease is
	// pending/offline and survives restart; an operator can retry with a new token.
	if len(s.reg.Nodes) != 1 || !s.reg.Nodes[0].EnrollmentPending || !s.reg.Nodes[0].LastSeenAt.IsZero() {
		t.Fatal("unconfirmed enrollment advertised online")
	}
	restarted, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.reg.Nodes[0].EnrollmentPending {
		t.Fatal("restart lost pending state")
	}
	if _, err := b.Bootstrap(context.Background(), request); err == nil {
		t.Fatal("single-use replay admitted")
	}
	for _, op := range []string{"ca.prepare", "ca.activate"} {
		if _, err := s.adminPKI(api.AdminRequest{Operation: op}); err != nil {
			t.Fatal("pending enrollment blocked rotation", err)
		}
	}
	next, err := s.tokenStore.CreateWithOptions(time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	csr, key, err := pki.GenerateCSR("pending")
	if err != nil {
		t.Fatal(err)
	}
	request.Token, request.CSR = next, string(csr)
	// Refresh provisioning roots after rotation; the original CA is still in overlap.
	recovered, err := b.Bootstrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.VPNIP != issued.VPNIP {
		t.Fatal("retry changed reserved lease")
	}
	dir := t.TempDir()
	if err := pki.SaveCredentials(dir, pki.Credentials{Version: 1, Generation: recovered.Generation, CACert: recovered.CACert, ClientCert: recovered.ClientCert, ClientKey: string(key)}, ""); err != nil {
		t.Fatal(err)
	}
	client := api.NewCredentialClient(h.URL, dir)
	defer client.CloseIdleConnections()
	if err := client.SyncCredentials(context.Background(), dir, "pending"); err != nil {
		t.Fatal(err)
	}
	if s.reg.Nodes[0].EnrollmentPending || !s.reg.Nodes[0].LastSeenAt.IsZero() {
		t.Fatal("confirmation did not preserve offline enrollment")
	}
	if _, err := client.Register(context.Background(), api.RegisterRequest{Name: "pending", PubKey: "pending-public"}); err != nil {
		t.Fatal(err)
	}
	if s.reg.Nodes[0].Status != "online" {
		t.Fatal("registration did not activate")
	}
	before := s.reg.Nodes[0]
	if _, err := s.registerWithIssuance(nodeRegistration{Name: "pending"}, false, func() error { return errors.New("issuance failed") }); err == nil {
		t.Fatal("missing failure")
	}
	if s.reg.Nodes[0] != before {
		t.Fatal("failed re-enrollment changed active identity")
	}
	if err := s.removeNode("pending"); err != nil {
		t.Fatal(err)
	}
	result, err := s.registerNode(nodeRegistration{Name: "replacement", PubKey: "replacement-key"}, false)
	if err != nil || result.VPNIP != issued.VPNIP {
		t.Fatalf("lease reuse: %+v %v", result, err)
	}
}

func TestDirectFailureInvalidatesPreviousSuccessInBothModes(t *testing.T) {
	for _, mode := range []string{"mutual", "either"} {
		t.Run(mode, func(t *testing.T) {
			s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", P2PReadyMode: mode})
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"a", "b"} {
				if _, err := s.registerNode(nodeRegistration{Name: id, PubKey: "pub-" + id}, false); err != nil {
					t.Fatal(err)
				}
			}
			submit := func(a, b string, success bool) {
				t.Helper()
				body, _ := json.Marshal(api.DirectResultRequest{NodeID: a, PeerID: b, Success: success})
				rec := httptest.NewRecorder()
				s.handleDirectResult(rec, httptest.NewRequest(http.MethodPost, "/direct-result", bytes.NewReader(body)))
				if rec.Code != 204 {
					t.Fatal(rec.Code, rec.Body.String())
				}
			}
			for i := 0; i < 30; i++ {
				submit("a", "b", true)
				submit("b", "a", true)
				if !s.p2pReadyLocked("a", "b") {
					t.Fatal("fresh success not ready")
				}
				submit("a", "b", false)
				if s.p2pReadyLocked("a", "b") || s.p2pReadyLocked("b", "a") {
					t.Fatal("failure retained stale readiness")
				}
			}
		})
	}
}
