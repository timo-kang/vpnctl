// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"vpnctl/internal/pki"
)

// setupTestPKI creates a CA, server cert, and client cert in a temp dir.
// Returns paths to the CA cert, server cert/key, client cert/key.
func setupTestPKI(t *testing.T) (caCertPath, srvCertPath, srvKeyPath, clientCertPath, clientKeyPath string) {
	t.Helper()
	dir := t.TempDir()

	caKeyPath := dir + "/ca.key"
	caCertPath = dir + "/ca.crt"

	if err := pki.GenerateCA(caKeyPath, caCertPath, 24*time.Hour); err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	srvKeyPath = dir + "/server.key"
	srvCertPath = dir + "/server.crt"
	if err := pki.GenerateServerCert(caCertPath, caKeyPath, srvKeyPath, srvCertPath, []string{"127.0.0.1"}, 24*time.Hour); err != nil {
		t.Fatalf("GenerateServerCert failed: %v", err)
	}

	caCert, caKey, err := pki.LoadCA(caKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	csrPEM, keyPEM, err := pki.GenerateCSR("test-client")
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}

	certPEM, err := pki.SignCSR(caCert, caKey, csrPEM, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR failed: %v", err)
	}

	clientCertPath = dir + "/client.crt"
	clientKeyPath = dir + "/client.key"

	if err := os.WriteFile(clientCertPath, certPEM, 0644); err != nil {
		t.Fatalf("WriteFile client cert failed: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, keyPEM, 0600); err != nil {
		t.Fatalf("WriteFile client key failed: %v", err)
	}

	return caCertPath, srvCertPath, srvKeyPath, clientCertPath, clientKeyPath
}

func TestMTLSHandshake(t *testing.T) {
	caCertPath, srvCertPath, srvKeyPath, clientCertPath, clientKeyPath := setupTestPKI(t)

	serverTLS, err := pki.ServerTLSConfig(caCertPath, srvCertPath, srvKeyPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig failed: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	clientTLS, err := pki.ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("ClientTLSConfig failed: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(body) != "ok" {
		t.Errorf("expected body 'ok', got %q", string(body))
	}
}

func TestMTLS_RejectsNoClientCert(t *testing.T) {
	caCertPath, srvCertPath, srvKeyPath, _, _ := setupTestPKI(t)

	serverTLS, err := pki.ServerTLSConfig(caCertPath, srvCertPath, srvKeyPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig failed: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	// ClientTLSConfig with empty cert/key paths — CA only, no client cert.
	clientTLS, err := pki.ClientTLSConfig(caCertPath, "", "")
	if err != nil {
		t.Fatalf("ClientTLSConfig (CA-only) failed: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	_, err = client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected TLS handshake error when no client cert is presented, but got nil")
	}
}
