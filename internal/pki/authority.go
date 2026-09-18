// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnctl/internal/atomicfile"
)

// Policy uses a third of each certificate's configured lifetime as the default
// renewal window. The interval must leave time to renew before expiration.
type Policy struct {
	CALifetime, ServerLifetime, ClientLifetime                     time.Duration
	ServerRenewBefore, ClientRenewBefore, CheckInterval, CAOverlap time.Duration
	SANs                                                           []string
}

func (p *Policy) Defaults() error {
	if p.CALifetime == 0 {
		p.CALifetime = 10 * 365 * 24 * time.Hour
	}
	if p.ServerLifetime == 0 {
		p.ServerLifetime = 365 * 24 * time.Hour
	}
	if p.ClientLifetime == 0 {
		p.ClientLifetime = 365 * 24 * time.Hour
	}
	if p.ServerRenewBefore == 0 {
		p.ServerRenewBefore = p.ServerLifetime / 3
	}
	if p.ClientRenewBefore == 0 {
		p.ClientRenewBefore = p.ClientLifetime / 3
	}
	if p.CheckInterval == 0 {
		p.CheckInterval = min(time.Minute, p.ServerRenewBefore/3, p.ClientRenewBefore/3)
	}
	if p.CAOverlap == 0 {
		p.CAOverlap = 24 * time.Hour
	}
	if p.CALifetime < 3*time.Second || p.ServerLifetime < 3*time.Second || p.ClientLifetime < 3*time.Second || p.ServerRenewBefore < time.Second || p.ClientRenewBefore < time.Second || p.ServerRenewBefore >= p.ServerLifetime || p.ClientRenewBefore >= p.ClientLifetime || p.CheckInterval < 10*time.Millisecond || p.CheckInterval >= min(p.ServerRenewBefore, p.ClientRenewBefore) || p.CAOverlap < time.Second {
		return fmt.Errorf("invalid PKI lifetimes, renewal windows, check interval or CA overlap")
	}
	return nil
}

type CertificateRecord struct {
	NodeID      string    `json:"node_id"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	Issuer      string    `json:"issuer"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RevokedAt   time.Time `json:"revoked_at"`
	Status      string    `json:"status,omitempty"`
}

type TrustAck struct {
	Generation  uint64    `json:"generation"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

type renewalRecord struct {
	CSRHash     string `json:"csr_hash"`
	Certificate string `json:"certificate"`
}

type authorityState struct {
	Renewals     map[string]renewalRecord     `json:"renewals,omitempty"`
	Version      int                          `json:"version"`
	Generation   uint64                       `json:"generation"`
	Active       string                       `json:"active"`
	Previous     string                       `json:"previous,omitempty"`
	Pending      string                       `json:"pending,omitempty"`
	Phase        string                       `json:"phase"`
	OverlapUntil time.Time                    `json:"overlap_until"`
	CAs          map[string]Material          `json:"cas"`
	Server       Material                     `json:"server"`
	Certificates map[string]CertificateRecord `json:"certificates"`
	Acks         map[string]TrustAck          `json:"acks"`
}

// Authority commits keys, trust, revocations and issuance metadata as one file.
// Controller ownership must already be held; callers serialize registry changes.
type Authority struct {
	mu        sync.Mutex // serializes writers; never held by committed readers
	published atomic.Pointer[authorityState]
	path      string
	state     authorityState
	policy    Policy
	write     func(string, []byte, os.FileMode) error
}

type AuthorityStatus struct {
	Generation         uint64              `json:"generation"`
	Phase              string              `json:"phase"`
	Active             string              `json:"active"`
	Previous           string              `json:"previous,omitempty"`
	Pending            string              `json:"pending,omitempty"`
	OverlapUntil       time.Time           `json:"overlap_until"`
	CACert             string              `json:"ca_cert"`
	Server             CertificateRecord   `json:"server"`
	CAs                []CertificateRecord `json:"cas"`
	Certificates       []CertificateRecord `json:"certificates"`
	Acks               map[string]TrustAck `json:"acks"`
	RenewBeforeSeconds float64             `json:"renew_before_seconds"`
}

func OpenAuthority(dir string, policy Policy) (*Authority, error) {
	if err := policy.Defaults(); err != nil {
		return nil, err
	}
	if err := atomicfile.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	a := &Authority{path: filepath.Join(dir, "authority.json"), policy: policy, write: WriteAtomic}
	data, err := os.ReadFile(a.path)
	if err == nil {
		if err := json.Unmarshal(data, &a.state); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		if _, markerErr := os.Stat(filepath.Join(dir, "authority.initialized")); !os.IsNotExist(markerErr) {
			return nil, fmt.Errorf("authority state is missing; restore a complete PKI backup")
		}
		ca, err := loadLegacyMaterial(dir, "ca")
		if os.IsNotExist(err) {
			// A lone legacy key must never silently trigger replacement of its CA.
			_, certErr := os.Stat(filepath.Join(dir, "ca.crt"))
			if _, keyErr := os.Stat(filepath.Join(dir, "ca.key")); !os.IsNotExist(keyErr) || !os.IsNotExist(certErr) {
				return nil, fmt.Errorf("incomplete legacy CA; restore its certificate")
			}
			ca, err = newCA(policy.CALifetime)
		}
		if err != nil {
			return nil, err
		}
		cert, _, err := parseCA(ca)
		if err != nil {
			return nil, err
		}
		id := Fingerprint(cert)
		server, err := loadLegacyMaterial(dir, "server")
		if os.IsNotExist(err) {
			server, err = newServer(ca, policy.SANs, policy.ServerLifetime)
		}
		if err != nil {
			return nil, err
		}
		a.state = authorityState{Version: 1, Generation: 1, Phase: "stable", Active: id, CAs: map[string]Material{id: ca}, Server: server, Certificates: map[string]CertificateRecord{}, Acks: map[string]TrustAck{}}
		if err := validateAuthority(a.state); err != nil {
			return nil, err
		}
		if err := a.commit(a.state); err != nil {
			return nil, err
		}
	}
	if err := validateAuthority(a.state); err != nil {
		return nil, err
	}
	a.publish(a.state)
	if _, err := a.MaintainServer(); err != nil && !errors.Is(err, ErrCARenewalRequired) {
		return nil, err
	}
	if err := WriteAtomic(filepath.Join(dir, "authority.initialized"), []byte("1"), 0600); err != nil {
		return nil, err
	}
	return a, nil
}

func loadLegacyMaterial(dir, name string) (Material, error) {
	cert, err := os.ReadFile(filepath.Join(dir, name+".crt"))
	if err != nil {
		return Material{}, err
	}
	key, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		return Material{}, fmt.Errorf("legacy %s key: %w", name, err)
	}
	return Material{Cert: string(cert), Key: string(key)}, nil
}

func validateAuthority(s authorityState) error {
	if s.Version != 1 || s.Generation == 0 || s.Certificates == nil || s.Acks == nil {
		return fmt.Errorf("invalid authority state")
	}
	ids := []string{s.Active}
	switch s.Phase {
	case "stable":
		if s.Pending != "" || s.Previous != "" {
			return fmt.Errorf("invalid stable authority")
		}
	case "prepared":
		if s.Pending == "" || s.Previous != "" {
			return fmt.Errorf("invalid prepared authority")
		}
		ids = append(ids, s.Pending)
	case "overlap", "rollback":
		if s.Previous == "" || s.Pending != "" || s.OverlapUntil.IsZero() {
			return fmt.Errorf("invalid overlap authority")
		}
		ids = append(ids, s.Previous)
	default:
		return fmt.Errorf("unknown CA phase")
	}
	if len(s.CAs) != len(ids) {
		return fmt.Errorf("unexpected CA entries")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		m, ok := s.CAs[id]
		if !ok || seen[id] {
			return fmt.Errorf("missing or duplicated CA")
		}
		seen[id] = true
		cert, _, err := parseCA(m)
		if err != nil {
			return err
		}
		if Fingerprint(cert) != id {
			return fmt.Errorf("CA fingerprint mismatch")
		}
	}
	pair, err := tls.X509KeyPair([]byte(s.Server.Cert), []byte(s.Server.Key))
	if err != nil {
		return err
	}
	server, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	ca, _, _ := parseCA(s.CAs[s.Active])
	if err := server.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("server issuer differs from active CA: %w", err)
	}
	serverUsage := false
	for _, usage := range server.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverUsage = true
		}
	}
	if !serverUsage || !server.NotAfter.After(server.NotBefore) {
		return fmt.Errorf("invalid server certificate usage or validity")
	}
	validHash := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32
	}
	for key, record := range s.Certificates {
		if key != record.Fingerprint || !validHash(key) || !validHash(record.Issuer) || record.Serial == "" || !record.ExpiresAt.After(record.IssuedAt) {
			return fmt.Errorf("invalid certificate record")
		}
		if _, err := NodeIdentityURI(record.NodeID); err != nil {
			return err
		}
	}
	for key, cached := range s.Renewals {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || !validHash(parts[0]) || !validHash(parts[1]) || !validHash(cached.CSRHash) {
			return fmt.Errorf("invalid renewal cache key")
		}
		cert, err := ParseCertificate(cached.Certificate)
		if err != nil {
			return err
		}
		child, ok := s.Certificates[Fingerprint(cert)]
		parent, parentOK := s.Certificates[parts[0]]
		if !ok || !parentOK || child.NodeID != parent.NodeID || child.Issuer != parts[1] {
			return fmt.Errorf("inconsistent renewal cache")
		}
		identity, _, err := CertificateNodeIdentity(cert)
		if err != nil || identity != child.NodeID {
			return fmt.Errorf("renewal cache identity mismatch")
		}
	}
	for id, ack := range s.Acks {
		record, ok := s.Certificates[ack.Fingerprint]
		if !ok || record.NodeID != id || ack.Generation == 0 || ack.Generation > s.Generation || ack.At.IsZero() {
			return fmt.Errorf("invalid trust acknowledgement")
		}
	}
	return nil
}

func (a *Authority) clone() authorityState {
	data, _ := json.Marshal(a.state)
	var next authorityState
	_ = json.Unmarshal(data, &next)
	return next
}

func (a *Authority) commit(next authorityState) error {
	defer observeAuthority("persist", time.Now())
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := a.write(a.path, data, 0600); err != nil {
		// Rename may have committed before directory fsync failed. Reload the exact
		// committed bytes so memory never keeps an older revocation/trust decision.
		if disk, readErr := os.ReadFile(a.path); readErr == nil && string(disk) == string(data) {
			a.publish(next)
		}
		return err
	}
	a.publish(next)
	return nil
}

// publish runs under the writer lock (or during construction). Writers only
// mutate clones, so maps referenced by an older published generation stay immutable.
func (a *Authority) publish(next authorityState) {
	a.state = next
	a.published.Store(&next)
}

func trustBundle(s authorityState) string {
	ids := make([]string, 0, len(s.CAs))
	for id := range s.CAs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var bundle string
	for _, id := range ids {
		bundle += s.CAs[id].Cert
	}
	return bundle
}

func certRecord(cert *x509.Certificate, id, issuer string) CertificateRecord {
	return CertificateRecord{NodeID: id, Serial: cert.SerialNumber.Text(16), Fingerprint: Fingerprint(cert), Issuer: issuer, IssuedAt: cert.NotBefore, ExpiresAt: cert.NotAfter}
}

func (a *Authority) Status() AuthorityStatus {
	defer observeAuthority("status", time.Now())
	s := *a.published.Load()
	out := AuthorityStatus{Generation: s.Generation, Phase: s.Phase, Active: s.Active, Previous: s.Previous, Pending: s.Pending, OverlapUntil: s.OverlapUntil, CACert: trustBundle(s), RenewBeforeSeconds: a.policy.ClientRenewBefore.Seconds(), Acks: map[string]TrustAck{}}
	server, _ := ParseCertificate(s.Server.Cert)
	out.Server = certRecord(server, "controller", s.Active)
	for id, m := range s.CAs {
		cert, _, _ := parseCA(m)
		out.CAs = append(out.CAs, certRecord(cert, "ca", id))
	}
	for _, r := range s.Certificates {
		r.Status = "active"
		if !r.RevokedAt.IsZero() {
			r.Status = "revoked"
		} else if !time.Now().Before(r.ExpiresAt) {
			r.Status = "expired"
		} else if _, ok := s.CAs[r.Issuer]; !ok {
			r.Status = "retired_ca"
		}
		out.Certificates = append(out.Certificates, r)
	}
	sort.Slice(out.CAs, func(i, j int) bool { return out.CAs[i].Fingerprint < out.CAs[j].Fingerprint })
	sort.Slice(out.Certificates, func(i, j int) bool { return out.Certificates[i].Fingerprint < out.Certificates[j].Fingerprint })
	for id, ack := range s.Acks {
		out.Acks[id] = ack
	}
	return out
}

func (a *Authority) TLSConfig() (*tls.Config, error) {
	defer observeAuthority("tls_snapshot", time.Now())
	s := *a.published.Load()
	pair, err := tls.X509KeyPair([]byte(s.Server.Cert), []byte(s.Server.Key))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(trustBundle(s)))
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots, Certificates: []tls.Certificate{pair}, SessionTicketsDisabled: true}, nil
}

// DynamicTLSConfig chooses an immutable snapshot at every new handshake.
func (a *Authority) DynamicTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return a.TLSConfig() }}
}

var ErrRenewalBlocked = errors.New("certificate renewal blocked")

var ErrCARenewalRequired = errors.New("active CA must be rotated")

var ErrTransitionBlocked = errors.New("CA transition blocked")

var ErrCertificateDenied = errors.New("certificate revoked, expired or issued by an untrusted CA")

func (a *Authority) validate(cert *x509.Certificate) (string, error) {
	return validateAuthorityCertificate(a.state, cert)
}

func validateAuthorityCertificate(s authorityState, cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrCertificateDenied
	}
	if record, ok := s.Certificates[Fingerprint(cert)]; ok && !record.RevokedAt.IsZero() {
		return "", ErrCertificateDenied
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(trustBundle(s)))
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 {
		return "", ErrCertificateDenied
	}
	return Fingerprint(chains[0][len(chains[0])-1]), nil
}

// CertificateObserved classifies first-use persistence without authorizing the
// certificate. Records are retained across revocation/retirement, so a known
// record cannot become an unobserved writer. Callers must still call Observe.
func (a *Authority) CertificateObserved(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	_, ok := a.published.Load().Certificates[Fingerprint(cert)]
	return ok
}

// Observe checks even established TLS connections against current trust, expiry
// and revocations. Legacy certificates acquire persisted metadata on first use.
func (a *Authority) Observe(cert *x509.Certificate, nodeID string) error {
	defer observeAuthority("authorize", time.Now())
	s := *a.published.Load()
	if _, err := validateAuthorityCertificate(s, cert); err != nil {
		return err
	}
	fp := Fingerprint(cert)
	if record, ok := s.Certificates[fp]; ok {
		if record.NodeID != nodeID {
			return ErrCertificateDenied
		}
		return nil
	}
	// Legacy first-use metadata still requires a durable write. Recheck under
	// the writer lock: revocation/rotation or another first use may have won.
	unlock := a.lockWriter()
	defer unlock()
	issuer, err := a.validate(cert)
	if err != nil {
		return err
	}
	if record, ok := a.state.Certificates[fp]; ok {
		if record.NodeID != nodeID {
			return ErrCertificateDenied
		}
		return nil
	}
	next := a.clone()
	next.Certificates[fp] = certRecord(cert, nodeID, issuer)
	return a.commit(next)
}

func (a *Authority) Issue(csr []byte, nodeID string) (string, AuthorityStatus, error) {
	unlock := a.lockWriter()
	ca, key, err := parseCA(a.state.CAs[a.state.Active])
	var signed []byte
	if err == nil {
		signed, err = SignNodeCSR(ca, key, csr, nodeID, a.policy.ClientLifetime)
	}
	if err == nil {
		cert, parseErr := ParseCertificate(string(signed))
		err = parseErr
		if err == nil {
			next := a.clone()
			next.Certificates[Fingerprint(cert)] = certRecord(cert, nodeID, next.Active)
			err = a.commit(next)
		}
	}
	unlock()
	if err != nil {
		return "", AuthorityStatus{}, err
	}
	return string(signed), a.Status(), nil
}

func (a *Authority) Revoke(fingerprint string) error {
	unlock := a.lockWriter()
	defer unlock()
	record, ok := a.state.Certificates[fingerprint]
	if !ok {
		return fmt.Errorf("unknown certificate fingerprint")
	}
	if !record.RevokedAt.IsZero() {
		return nil
	}
	next := a.clone()
	record.RevokedAt = time.Now().UTC()
	next.Certificates[fingerprint] = record
	return a.commit(next)
}

func (a *Authority) Acknowledge(nodeID string, cert *x509.Certificate, generation uint64) error {
	unlock := a.lockWriter()
	defer unlock()
	if generation != a.state.Generation {
		return fmt.Errorf("trust generation changed; refresh and retry")
	}
	if _, err := a.validate(cert); err != nil {
		return err
	}
	id, _, err := CertificateNodeIdentity(cert)
	if err != nil || id != nodeID {
		return ErrCertificateDenied
	}
	next := a.clone()
	ack := TrustAck{Generation: generation, Fingerprint: Fingerprint(cert), At: time.Now().UTC()}
	if prev, ok := next.Acks[nodeID]; ok && prev.Generation == generation && prev.Fingerprint == ack.Fingerprint {
		return nil
	}
	next.Acks[nodeID] = ack
	return a.commit(next)
}

func (a *Authority) MaintainServer() (bool, error) {
	unlock := a.lockWriter()
	defer unlock()
	cert, err := ParseCertificate(a.state.Server.Cert)
	if err != nil {
		return false, err
	}
	sameSANs := func() bool {
		have := CertSANs(cert)
		want := append([]string(nil), a.policy.SANs...)
		sort.Strings(have)
		sort.Strings(want)
		if len(have) != len(want) {
			return false
		}
		for i := range have {
			if have[i] != want[i] {
				return false
			}
		}
		return true
	}
	if time.Until(cert.NotAfter) > a.policy.ServerRenewBefore && sameSANs() {
		return false, nil
	}
	server, err := newServer(a.state.CAs[a.state.Active], a.policy.SANs, a.policy.ServerLifetime)
	if err != nil {
		return false, err
	}
	candidate, parseErr := ParseCertificate(server.Cert)
	if parseErr != nil {
		return false, parseErr
	}
	if sameSANs() && !candidate.NotAfter.After(cert.NotAfter) {
		return false, fmt.Errorf("%w: server lifetime cannot be extended", ErrCARenewalRequired)
	}
	next := a.clone()
	next.Server = server
	if err := a.commit(next); err != nil {
		return false, err
	}
	return true, nil
}

// CheckRotation rejects impossible transitions without asking the controller to
// drain all admitted requests. This is advisory: Rotate repeats every check
// under its write lock with the controller's freshly collected identity set.
func (a *Authority) CheckRotation(operation string, nodeIDs []string) error {
	return checkRotation(*a.published.Load(), a.policy, operation, nodeIDs)
}

func (a *Authority) checkRotation(operation string, nodeIDs []string) error {
	return checkRotation(a.state, a.policy, operation, nodeIDs)
}

func checkRotation(s authorityState, policy Policy, operation string, nodeIDs []string) error {
	if s.Generation == ^uint64(0) {
		return fmt.Errorf("%w: trust generation exhausted", ErrTransitionBlocked)
	}
	switch operation {
	case "prepare":
		if s.Phase != "stable" {
			return fmt.Errorf("%w: CA rotation already in progress", ErrTransitionBlocked)
		}
	case "activate":
		if s.Phase != "prepared" {
			return fmt.Errorf("%w: prepare CA rotation first", ErrTransitionBlocked)
		}
		return checkAcks(s, policy, nodeIDs, false)
	case "rollback":
		if s.Phase != "prepared" && s.Phase != "overlap" {
			return fmt.Errorf("%w: no reversible CA transition", ErrTransitionBlocked)
		}
	case "retire":
		if s.Phase != "overlap" && s.Phase != "rollback" {
			return fmt.Errorf("%w: no CA overlap to finish", ErrTransitionBlocked)
		}
		if time.Now().Before(s.OverlapUntil) {
			return fmt.Errorf("%w: minimum CA overlap has not elapsed", ErrTransitionBlocked)
		}
		return checkAcks(s, policy, nodeIDs, true)
	default:
		return fmt.Errorf("%w: unknown CA operation", ErrTransitionBlocked)
	}
	return nil
}

func (a *Authority) Rotate(operation string, nodeIDs []string) error {
	unlock := a.lockWriter()
	defer unlock()
	if err := a.checkRotation(operation, nodeIDs); err != nil {
		return err
	}
	next := a.clone()
	switch operation {
	case "prepare":
		ca, err := newCA(a.policy.CALifetime)
		if err != nil {
			return err
		}
		cert, _, _ := parseCA(ca)
		next.Pending = Fingerprint(cert)
		next.CAs[next.Pending] = ca
		next.Phase = "prepared"
	case "activate":
		next.Previous, next.Active, next.Pending = next.Active, next.Pending, ""
		next.Phase = "overlap"
		next.OverlapUntil = time.Now().UTC().Add(a.policy.CAOverlap)
	case "rollback":
		switch next.Phase {
		case "prepared":
			delete(next.CAs, next.Pending)
			next.Pending = ""
			next.Phase = "stable"
		case "overlap":
			next.Active, next.Previous = next.Previous, next.Active
			next.Phase = "rollback"
			next.OverlapUntil = time.Now().UTC().Add(a.policy.CAOverlap)
		default:
			return fmt.Errorf("%w: no reversible CA transition", ErrTransitionBlocked)
		}
	case "retire":
		delete(next.CAs, next.Previous)
		next.Previous = ""
		next.Phase = "stable"
		next.OverlapUntil = time.Time{}
	default:
		return fmt.Errorf("%w: unknown CA operation", ErrTransitionBlocked)
	}
	if next.Active != a.state.Active {
		server, err := newServer(next.CAs[next.Active], a.policy.SANs, a.policy.ServerLifetime)
		if err != nil {
			return err
		}
		next.Server = server
	}
	next.Generation++
	return a.commit(next)
}

func checkAcks(s authorityState, policy Policy, nodeIDs []string, needActive bool) error {
	for _, id := range nodeIDs {
		ack, ok := s.Acks[id]
		record, known := s.Certificates[ack.Fingerprint]
		if !ok || !known || ack.Generation != s.Generation || record.NodeID != id || !record.RevokedAt.IsZero() || !time.Now().Add(min(2*policy.CheckInterval, policy.ClientRenewBefore)).Before(record.ExpiresAt) || (needActive && record.Issuer != s.Active) {
			return fmt.Errorf("%w: node %q has not acknowledged current trust/certificate", ErrTransitionBlocked, id)
		}
	}
	return nil
}

func (a *Authority) Snapshot() ([]byte, error) {
	return json.Marshal(a.published.Load())
}
func ValidateAuthoritySnapshot(data []byte) error {
	var state authorityState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	return validateAuthority(state)
}
func (a *Authority) CheckInterval() time.Duration { return a.policy.CheckInterval }

// Renew allows one CSR per authenticated parent certificate and signing CA.
// The durable response makes retries idempotent without issuing unlimited leaves.
func (a *Authority) Renew(csr []byte, nodeID string, parent *x509.Certificate) (string, AuthorityStatus, error) {
	unlock := a.lockWriter()
	signed, err := a.renewLocked(csr, nodeID, parent)
	unlock()
	if err != nil {
		return "", AuthorityStatus{}, err
	}
	return signed, a.Status(), nil
}

func (a *Authority) renewLocked(csr []byte, nodeID string, parent *x509.Certificate) (string, error) {
	issuer, err := a.validate(parent)
	if err != nil {
		return "", err
	}
	identity, _, err := CertificateNodeIdentity(parent)
	if err != nil || identity != nodeID {
		return "", ErrCertificateDenied
	}
	key := Fingerprint(parent) + ":" + a.state.Active
	hash := fmt.Sprintf("%x", sha256.Sum256(csr))
	if cached, ok := a.state.Renewals[key]; ok {
		if cached.CSRHash != hash {
			return "", fmt.Errorf("%w: retry with the original pending CSR", ErrRenewalBlocked)
		}
		cert, err := ParseCertificate(cached.Certificate)
		if err != nil {
			return "", err
		}
		if _, err := a.validate(cert); err != nil {
			return "", err
		}
		return cached.Certificate, nil
	}
	ca, caKey, err := parseCA(a.state.CAs[a.state.Active])
	if err != nil {
		return "", err
	}
	if issuer == a.state.Active {
		if time.Until(parent.NotAfter) > a.policy.ClientRenewBefore {
			return "", fmt.Errorf("%w: certificate is outside its renewal window", ErrRenewalBlocked)
		}
		if !parent.NotAfter.Before(ca.NotAfter) {
			return "", ErrCARenewalRequired
		}
	}
	signed, err := SignNodeCSR(ca, caKey, csr, nodeID, a.policy.ClientLifetime)
	if err != nil {
		return "", err
	}
	cert, err := ParseCertificate(string(signed))
	if err != nil {
		return "", err
	}
	next := a.clone()
	next.Certificates[Fingerprint(cert)] = certRecord(cert, nodeID, next.Active)
	if next.Renewals == nil {
		next.Renewals = map[string]renewalRecord{}
	}
	next.Renewals[key] = renewalRecord{CSRHash: hash, Certificate: string(signed)}
	if err := a.commit(next); err != nil {
		return "", err
	}
	return string(signed), nil
}
