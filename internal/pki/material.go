// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"vpnctl/internal/atomicfile"
)

// Material is stored only in owner-readable state, never in public status.
type Material struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func ParseCertificate(value string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("expected one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func Fingerprint(cert *x509.Certificate) string { return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)) }

func parseCA(m Material) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	pair, err := tls.X509KeyPair([]byte(m.Cert), []byte(m.Key))
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("invalid ECDSA signing CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func newMaterial(template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return Material{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Material{}, err
	}
	return Material{Cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))}, nil
}

func newCA(lifetime time.Duration) (Material, error) {
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	now := time.Now().UTC()
	return newMaterial(&x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "vpnctl-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true}, nil, nil)
}

func newServer(ca Material, sans []string, lifetime time.Duration) (Material, error) {
	cert, key, err := parseCA(ca)
	if err != nil {
		return Material{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(lifetime)
	if cert.NotAfter.Before(expires) {
		expires = cert.NotAfter
	}
	if !expires.After(now.Add(time.Second)) {
		return Material{}, fmt.Errorf("%w: signing CA expires within one second", ErrCARenewalRequired)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "vpnctl-controller"}, NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	return newMaterial(template, cert, key)
}

// WriteAtomic keeps the old file on pre-rename failure, and fsyncs the parent
// after replacement. An fsync failure after rename is an indeterminate commit.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	return atomicfile.Write(path, data, mode)
}

// ValidateCSR checks proof of possession before allocating any registry state.
func ValidateCSR(value []byte) error {
	block, rest := pem.Decode(value)
	if block == nil || len(rest) != 0 {
		return fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}
