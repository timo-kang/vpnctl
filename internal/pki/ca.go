// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

// randomSerial generates a cryptographically random certificate serial number.
func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// writeKeyPEM writes an ECDSA private key as PEM to path with mode 0600.
func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// writeCertPEM writes a DER-encoded certificate as PEM to path with mode 0644.
func writeCertPEM(path string, derBytes []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// GenerateCA generates an ECDSA P-256 CA keypair and self-signed certificate,
// writing the key (0600) and cert (0644) PEM files to keyPath and certPath.
func GenerateCA(keyPath, certPath string, expiry time.Duration) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "vpnctl-ca",
		},
		NotBefore:             now,
		NotAfter:              now.Add(expiry),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	if err := writeKeyPEM(keyPath, key); err != nil {
		return err
	}
	return writeCertPEM(certPath, der)
}

// LoadCA reads and parses the CA certificate and private key from PEM files.
func LoadCA(keyPath, certPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEMData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEMData)
	if block == nil {
		return nil, nil, &pemError{path: certPath}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyPEMData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEMData)
	if keyBlock == nil {
		return nil, nil, &pemError{path: keyPath}
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// LoadCert reads and parses a certificate from a PEM file.
func LoadCert(certPath string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &pemError{path: certPath}
	}
	return x509.ParseCertificate(block.Bytes)
}

// CertSANs returns the IP and DNS SANs from a certificate as a single sorted slice.
func CertSANs(cert *x509.Certificate) []string {
	var sans []string
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.DNSNames...)
	return sans
}

// pemError is returned when PEM decoding fails.
type pemError struct {
	path string
}

func (e *pemError) Error() string {
	return "pki: failed to decode PEM from " + e.path
}

// GenerateServerCert generates an ECDSA P-256 server certificate signed by the
// given CA. SANs that parse as IP addresses are added to IPAddresses; others
// are added to DNSNames. The key (0600) and cert (0644) PEM files are written
// to keyPath and certPath.
func GenerateServerCert(ca, caKey, keyPath, certPath string, sans []string, expiry time.Duration) error {
	caCert, caPrivKey, err := LoadCA(caKey, ca)
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	var ipAddresses []net.IP
	var dnsNames []string
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "vpnctl-controller",
		},
		NotBefore:   now,
		NotAfter:    now.Add(expiry),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ipAddresses,
		DNSNames:    dnsNames,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	if err := writeKeyPEM(keyPath, key); err != nil {
		return err
	}
	return writeCertPEM(certPath, der)
}

// GenerateCSR generates an ECDSA P-256 keypair and a Certificate Signing
// Request with the given Common Name. It returns the PEM-encoded CSR and key.
func GenerateCSR(cn string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return csrPEM, keyPEM, nil
}

// SignCSR parses and verifies the PEM-encoded CSR, then signs it with the CA,
// preserving the CSR subject for legacy callers.
func SignCSR(ca *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM []byte, expiry time.Duration) ([]byte, error) {
	return signCSR(ca, caKey, csrPEM, "", nil, expiry)
}

// SignNodeCSR signs a CSR while replacing its requested subject with the
// controller-assigned node identity. The identity is encoded in both the URI
// SAN and Common Name; the CSR still proves possession of the private key.
func SignNodeCSR(ca *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM []byte, nodeID string, expiry time.Duration) ([]byte, error) {
	identityURI, err := NodeIdentityURI(nodeID)
	if err != nil {
		return nil, err
	}
	return signCSR(ca, caKey, csrPEM, nodeID, []*url.URL{identityURI}, expiry)
}

func signCSR(ca *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM []byte, nodeID string, uris []*url.URL, expiry time.Duration) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, &pemError{path: "<csr>"}
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	subject := csr.Subject
	if nodeID != "" {
		subject = pkix.Name{CommonName: nodeID}
	}

	now := time.Now()
	expires := now.Add(expiry)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	if nodeID != "" && (expiry <= 0 || !expires.After(now.Add(time.Second))) {
		return nil, fmt.Errorf("invalid lifetime or signing CA expires within one second")
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         uris,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
