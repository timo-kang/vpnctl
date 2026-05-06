// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"vpnctl/internal/pki"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/ca.key"
	certPath := dir + "/ca.crt"

	if err := pki.GenerateCA(keyPath, certPath, 24*time.Hour); err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, _, err := pki.LoadCA(keyPath, certPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if cert.Subject.CommonName != "vpnctl-ca" {
		t.Errorf("expected CN=vpnctl-ca, got %s", cert.Subject.CommonName)
	}
}

func TestSignServerCert(t *testing.T) {
	dir := t.TempDir()
	caKeyPath := dir + "/ca.key"
	caCertPath := dir + "/ca.crt"

	if err := pki.GenerateCA(caKeyPath, caCertPath, 24*time.Hour); err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	srvKeyPath := dir + "/server.key"
	srvCertPath := dir + "/server.crt"
	sans := []string{"127.0.0.1", "0.0.0.0"}

	err := pki.GenerateServerCert(caCertPath, caKeyPath, srvKeyPath, srvCertPath, sans, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateServerCert failed: %v", err)
	}

	cert, _, err := pki.LoadCA(srvKeyPath, srvCertPath)
	if err != nil {
		t.Fatalf("LoadCA (server cert) failed: %v", err)
	}

	if cert.Subject.CommonName != "vpnctl-controller" {
		t.Errorf("expected CN=vpnctl-controller, got %s", cert.Subject.CommonName)
	}

	ipSet := make(map[string]bool)
	for _, ip := range cert.IPAddresses {
		ipSet[ip.String()] = true
	}
	for _, san := range sans {
		if !ipSet[san] {
			t.Errorf("expected IP SAN %s not found in cert", san)
		}
	}
}

func TestSignCSR(t *testing.T) {
	dir := t.TempDir()
	caKeyPath := dir + "/ca.key"
	caCertPath := dir + "/ca.crt"

	if err := pki.GenerateCA(caKeyPath, caCertPath, 24*time.Hour); err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	caCert, caKey, err := pki.LoadCA(caKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	csrPEM, _, err := pki.GenerateCSR("test-node")
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}

	certPEM, err := pki.SignCSR(caCert, caKey, csrPEM, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR failed: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != "test-node" {
		t.Errorf("expected CN=test-node, got %s", cert.Subject.CommonName)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("cert verification against CA pool failed: %v", err)
	}
}
