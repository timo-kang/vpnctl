// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	nodeIdentityScheme = "vpnctl"
	nodeIdentityHost   = "node"
	maxNodeIdentityLen = 255
)

// NodeIdentityURI returns the URI SAN used to bind a client certificate to a
// controller-assigned node identity.
func NodeIdentityURI(nodeID string) (*url.URL, error) {
	if err := validateNodeIdentity(nodeID); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: nodeIdentityScheme,
		Host:   nodeIdentityHost,
		Path:   "/" + nodeID,
	}, nil
}

// CertificateNodeIdentity extracts the node identity from a verified client
// certificate. New certificates use a vpnctl://node/<id> URI SAN. Certificates
// issued before URI identities were introduced fall back to Common Name and are
// marked legacy so callers can surface the migration requirement.
func CertificateNodeIdentity(cert *x509.Certificate) (nodeID string, legacy bool, err error) {
	if cert == nil {
		return "", false, fmt.Errorf("client certificate is required")
	}

	for _, uri := range cert.URIs {
		if uri == nil || uri.Scheme != nodeIdentityScheme || uri.Host != nodeIdentityHost {
			continue
		}
		if uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || !strings.HasPrefix(uri.Path, "/") {
			return "", false, fmt.Errorf("invalid node identity URI")
		}
		candidate := strings.TrimPrefix(uri.Path, "/")
		if err := validateNodeIdentity(candidate); err != nil {
			return "", false, fmt.Errorf("invalid node identity URI: %w", err)
		}
		if nodeID != "" {
			return "", false, fmt.Errorf("multiple node identity URIs")
		}
		nodeID = candidate
	}

	if nodeID != "" {
		if cert.Subject.CommonName != "" && cert.Subject.CommonName != nodeID {
			return "", false, fmt.Errorf("node identity URI and common name disagree")
		}
		return nodeID, false, nil
	}

	nodeID = cert.Subject.CommonName
	if err := validateNodeIdentity(nodeID); err != nil {
		return "", false, fmt.Errorf("certificate has no usable node identity: %w", err)
	}
	return nodeID, true, nil
}

func validateNodeIdentity(nodeID string) error {
	if nodeID == "" {
		return fmt.Errorf("node identity is empty")
	}
	if nodeID != strings.TrimSpace(nodeID) {
		return fmt.Errorf("node identity has surrounding whitespace")
	}
	if len(nodeID) > maxNodeIdentityLen {
		return fmt.Errorf("node identity exceeds %d bytes", maxNodeIdentityLen)
	}
	if !utf8.ValidString(nodeID) {
		return fmt.Errorf("node identity is not valid UTF-8")
	}
	for _, r := range nodeID {
		if unicode.IsControl(r) {
			return fmt.Errorf("node identity contains control characters")
		}
	}
	return nil
}
