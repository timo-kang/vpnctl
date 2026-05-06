// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// ServerTLSConfig builds a *tls.Config for a mutual-TLS server.
// It loads the CA certificate into ClientCAs, loads the server certificate and
// key, requires and verifies a client certificate, and enforces TLS 1.3.
func ServerTLSConfig(caCertPath, serverCertPath, serverKeyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, &pemError{path: caCertPath}
	}

	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds a *tls.Config for a mutual-TLS client.
// It loads the CA certificate into RootCAs.  If clientCertPath and
// clientKeyPath are both non-empty, the client certificate and key are loaded
// for mTLS; otherwise only the CA pool is configured (bootstrap phase).
// TLS 1.3 is enforced.
func ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, &pemError{path: caCertPath}
	}

	cfg := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	}

	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}
