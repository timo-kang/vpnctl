// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Credentials is a single atomic unit: trust and key/cert cannot be torn apart
// by a crash between individual file writes.
type PendingRenewal struct {
	Parent string `json:"parent"`
	CSR    string `json:"csr"`
	Key    string `json:"key"`
}

type Credentials struct {
	Pending    *PendingRenewal `json:"pending,omitempty"`
	Version    int             `json:"version"`
	Generation uint64          `json:"generation"`
	CACert     string          `json:"ca_cert"`
	ClientCert string          `json:"client_cert"`
	ClientKey  string          `json:"client_key"`
}

func LoadCredentials(dir string) (Credentials, error) {
	var out Credentials
	data, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err == nil {
		if err := json.Unmarshal(data, &out); err != nil {
			return out, err
		}
		if out.Version != 1 {
			return out, fmt.Errorf("unsupported credentials version")
		}
		return out, nil
	}
	if !os.IsNotExist(err) {
		return out, err
	}
	if _, markerErr := os.Stat(filepath.Join(dir, "credentials.initialized")); !os.IsNotExist(markerErr) {
		return out, fmt.Errorf("credentials state is missing; restore or re-enroll instead of using stale legacy keys")
	}
	cert, err := os.ReadFile(filepath.Join(dir, "client.crt"))
	if err != nil {
		return out, err
	}
	key, err := os.ReadFile(filepath.Join(dir, "client.key"))
	if err != nil {
		return out, err
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return out, err
	}
	return Credentials{Version: 1, CACert: string(ca), ClientCert: string(cert), ClientKey: string(key)}, nil
}

func (c Credentials) Digest() string {
	data, _ := json.Marshal(c)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func (c Credentials) TLSConfig() (*tls.Config, error) {
	if c.Version != 1 {
		return nil, fmt.Errorf("unsupported credentials version")
	}
	pair, err := tls.X509KeyPair([]byte(c.ClientCert), []byte(c.ClientKey))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.CACert)) {
		return nil, fmt.Errorf("invalid CA trust bundle")
	}
	return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, nil
}

// ValidateForInstall verifies identity, proof of key possession and current
// validity against the authenticated controller's returned trust bundle.
func (c Credentials) ValidateForInstall(nodeID string) error {
	cfg, err := c.TLSConfig()
	if err != nil {
		return err
	}
	cert, err := ParseCertificate(c.ClientCert)
	if err != nil {
		return err
	}
	id, _, err := CertificateNodeIdentity(cert)
	if err != nil || id != nodeID {
		return fmt.Errorf("issued certificate identity mismatch")
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

// SaveCredentials compares the previous digest while holding a process-shared
// lock. An empty expected digest explicitly installs/replaces bootstrap state.
func SaveCredentials(dir string, next Credentials, expected string) error {
	if _, err := next.TLSConfig(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fd, err := syscall.Open(filepath.Join(dir, "credentials.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), "credentials.lock")
	defer lock.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	if expected != "" {
		current, err := LoadCredentials(dir)
		if err != nil {
			return err
		}
		if current.Digest() != expected {
			return fmt.Errorf("credentials changed concurrently; reload and retry")
		}
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := WriteAtomic(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		return err
	}
	return WriteAtomic(filepath.Join(dir, "credentials.initialized"), []byte("1"), 0600)
}
