// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testAuthority(t *testing.T) *Authority {
	t.Helper()
	a, err := OpenAuthority(t.TempDir(), Policy{CALifetime: time.Hour, ClientLifetime: time.Minute, ServerLifetime: time.Minute, CAOverlap: time.Second, SANs: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func issueTestCert(t *testing.T, a *Authority, id string) *x509.Certificate {
	t.Helper()
	csr, _, err := GenerateCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := a.Issue(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAuthorityRotationGatesRollbackAndRestart(t *testing.T) {
	a := testAuthority(t)
	first := a.Status().Active
	old := issueTestCert(t, a, "a")
	if err := a.Rotate("activate", []string{"a"}); err == nil {
		t.Fatal("activated before prepare")
	}
	if err := a.Rotate("prepare", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	prepared := a.Status()
	if len(prepared.CAs) != 2 || prepared.Active != first {
		t.Fatal("prepare changed signer")
	}
	if err := a.Rotate("activate", []string{"a"}); err == nil {
		t.Fatal("ignored missing acknowledgement")
	}
	if err := a.Acknowledge("a", old, prepared.Generation-1); err == nil {
		t.Fatal("accepted stale acknowledgement")
	}
	if err := a.Acknowledge("a", old, prepared.Generation); err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate("activate", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	active := a.Status()
	if active.Active == first || active.Previous != first {
		t.Fatal("activation did not change signer")
	}
	newer := issueTestCert(t, a, "a")
	if err := a.Observe(old, "a"); err != nil {
		t.Fatal("old certificate rejected in overlap", err)
	}
	if err := a.Observe(newer, "a"); err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate("retire", []string{"a"}); err == nil {
		t.Fatal("retired before minimum overlap")
	}
	if err := a.Rotate("rollback", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	rollback := a.Status()
	if rollback.Active != first || len(rollback.CAs) != 2 || rollback.Phase != "rollback" {
		t.Fatal("rollback dropped new clients")
	}
	if err := a.Rotate("rollback", []string{"a"}); err == nil {
		t.Fatal("repeated rollback toggled signer")
	}
	if err := a.Observe(newer, "a"); err != nil {
		t.Fatal("rollback rejected new certificate", err)
	}
	reloaded, err := OpenAuthority(filepath.Dir(a.path), a.policy)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status().Phase != "rollback" {
		t.Fatal("rotation state lost on restart")
	}
	rolled := issueTestCert(t, reloaded, "a")
	// Move only the test's overlap clock; accelerated network tests use real time.
	reloaded.state.OverlapUntil = time.Now().Add(-time.Second)
	if err := reloaded.Rotate("retire", []string{"a"}); err == nil {
		t.Fatal("retired without new certificate acknowledgement")
	}
	if err := reloaded.Acknowledge("a", newer, rollback.Generation); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Rotate("retire", []string{"a"}); err == nil {
		t.Fatal("retired while node still uses unwanted issuer")
	}
	if err := reloaded.Acknowledge("a", rolled, rollback.Generation); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Rotate("retire", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Observe(newer, "a"); !errors.Is(err, ErrCertificateDenied) {
		t.Fatal("retired root still accepted", err)
	}
	if err := reloaded.Observe(rolled, "a"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityFailuresPreserveCommittedState(t *testing.T) {
	for _, operation := range []string{"issue", "revoke", "prepare", "server"} {
		t.Run(operation, func(t *testing.T) {
			a := testAuthority(t)
			cert := issueTestCert(t, a, "a")
			before, err := a.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			a.write = func(string, []byte, os.FileMode) error { return syscall.ENOSPC }
			switch operation {
			case "issue":
				csr, _, _ := GenerateCSR("b")
				_, _, err = a.Issue(csr, "b")
			case "revoke":
				err = a.Revoke(Fingerprint(cert))
			case "prepare":
				err = a.Rotate("prepare", nil)
			case "server":
				a.policy.SANs = []string{"changed.example"}
				_, err = a.MaintainServer()
			}
			if err == nil {
				t.Fatal("failed persistence reported success")
			}
			after, _ := a.Snapshot()
			disk, _ := os.ReadFile(a.path)
			if !bytes.Equal(before, after) || !bytes.Equal(before, disk) {
				t.Fatal("failed operation changed authority")
			}
			if err := a.Observe(cert, "a"); err != nil {
				t.Fatal("failed revocation took effect", err)
			}
			a.write = WriteAtomic
			if err := a.Revoke(Fingerprint(cert)); err != nil {
				t.Fatal(err)
			}
			if err := a.Observe(cert, "a"); !errors.Is(err, ErrCertificateDenied) {
				t.Fatal("committed revocation ignored", err)
			}
		})
	}
}

func TestAuthorityPostRenameFailureReloadsRevocation(t *testing.T) {
	a := testAuthority(t)
	cert := issueTestCert(t, a, "a")
	a.write = func(path string, data []byte, mode os.FileMode) error {
		if err := WriteAtomic(path, data, mode); err != nil {
			return err
		}
		return syscall.EIO
	}
	if err := a.Revoke(Fingerprint(cert)); err == nil {
		t.Fatal("indeterminate durability reported success")
	}
	if err := a.Observe(cert, "a"); !errors.Is(err, ErrCertificateDenied) {
		t.Fatal("memory reverted a committed revoke")
	}
}

func TestAuthorityConcurrentIssuanceAndRevocation(t *testing.T) {
	a := testAuthority(t)
	csr, _, _ := GenerateCSR("a")
	var wg sync.WaitGroup
	for n := 0; n < 64; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, _, err := a.Issue(csr, "a")
			if err != nil {
				t.Error(err)
				return
			}
			cert, err := ParseCertificate(raw)
			if err != nil {
				t.Error(err)
				return
			}
			if err := a.Revoke(Fingerprint(cert)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	restarted, err := OpenAuthority(filepath.Dir(a.path), a.policy)
	if err != nil {
		t.Fatal(err)
	}
	records := restarted.Status().Certificates
	if len(records) != 64 {
		t.Fatalf("lost records: %d", len(records))
	}
	for _, r := range records {
		if r.Status != "revoked" {
			t.Fatal("lost revocation")
		}
	}
}

func TestAuthorityRejectsIncompleteLegacyCAAndCorruptState(t *testing.T) {
	for _, missing := range []string{"ca.key", "ca.crt"} {
		t.Run(missing, func(t *testing.T) {
			dir := t.TempDir()
			if err := GenerateCA(filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt"), time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, missing)); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAuthority(dir, Policy{}); err == nil {
				t.Fatal("silently replaced incomplete CA")
			}
		})
	}
	a := testAuthority(t)
	snapshot, _ := a.Snapshot()
	var s authorityState
	if err := json.Unmarshal(snapshot, &s); err != nil {
		t.Fatal(err)
	}
	s.Server.Key = s.CAs[s.Active].Key
	broken, _ := json.Marshal(s)
	if err := ValidateAuthoritySnapshot(broken); err == nil {
		t.Fatal("accepted mismatched server key")
	}
}

func TestCredentialsAtomicPersistenceAndCAS(t *testing.T) {
	a := testAuthority(t)
	dir := t.TempDir()
	csr, key, _ := GenerateCSR("a")
	cert, status, err := a.Issue(csr, "a")
	if err != nil {
		t.Fatal(err)
	}
	original := Credentials{Version: 1, Generation: status.Generation, CACert: status.CACert, ClientCert: cert, ClientKey: string(key)}
	if err := original.ValidateForInstall("other"); err == nil {
		t.Fatal("wrong identity installed")
	}
	if err := SaveCredentials(dir, original, ""); err != nil {
		t.Fatal(err)
	}
	bad := original
	bad.ClientKey = "broken"
	if err := SaveCredentials(dir, bad, original.Digest()); err == nil {
		t.Fatal("torn pair accepted")
	}
	changed := original
	changed.Generation++
	if err := SaveCredentials(dir, changed, original.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := SaveCredentials(dir, original, original.Digest()); err == nil {
		t.Fatal("stale writer overwrote newer generation")
	}
	loaded, err := LoadCredentials(dir)
	if err != nil || loaded.Digest() != changed.Digest() {
		t.Fatal("credentials were damaged")
	}
	info, err := os.Stat(filepath.Join(dir, "credentials.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credentials permissions")
	}
	for name, value := range map[string]string{"ca.crt": original.CACert, "client.crt": original.ClientCert, "client.key": original.ClientKey} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(dir); err == nil {
		t.Fatal("missing current state fell back to stale legacy credentials")
	}
}

func TestMissingAuthorityNeverReinitializesSigningKeys(t *testing.T) {
	a := testAuthority(t)
	if err := os.Remove(a.path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuthority(filepath.Dir(a.path), a.policy); err == nil {
		t.Fatal("missing authority silently initialized")
	}
	if _, err := os.Stat(a.path); !os.IsNotExist(err) {
		t.Fatal("recreated authority after loss")
	}
}

func TestCAExpiryCapsCertificatesWithoutRenewalChurn(t *testing.T) {
	policy := Policy{CALifetime: 5 * time.Second, ClientLifetime: time.Hour, ServerLifetime: time.Hour, SANs: []string{"127.0.0.1"}}
	a, err := OpenAuthority(t.TempDir(), policy)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := a.Snapshot()
	for i := 0; i < 5; i++ {
		if changed, err := a.MaintainServer(); changed || !errors.Is(err, ErrCARenewalRequired) {
			t.Fatal("CA-capped renewal", changed, err)
		}
	}
	after, _ := a.Snapshot()
	if !bytes.Equal(before, after) {
		t.Fatal("capped renewal churned keys/state")
	}
	// Restart must keep local administration available so the operator can rotate.
	if _, err := OpenAuthority(filepath.Dir(a.path), policy); err != nil {
		t.Fatal("near-expiry CA blocked administrative recovery", err)
	}
	cert := issueTestCert(t, a, "a")
	ca := a.Status().CAs[0]
	if cert.NotAfter.After(ca.ExpiresAt) {
		t.Fatal("client lifetime exceeds its CA")
	}
}

func TestRenewalRetryIsIdempotentAndRejectsCSRChurn(t *testing.T) {
	a := testAuthority(t)
	parent := issueTestCert(t, a, "a")
	csr, _, _ := GenerateCSR("a")
	if _, _, err := a.Renew(csr, "a", parent); !errors.Is(err, ErrRenewalBlocked) {
		t.Fatal("unnecessary early renewal accepted", err)
	}
	// A changed signing CA permits immediate renewal regardless of the window.
	if err := a.Rotate("prepare", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate("activate", nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan string, 64)
	for n := 0; n < 64; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, _, err := a.Renew(csr, "a", parent)
			if err != nil {
				t.Error(err)
				return
			}
			results <- cert
		}()
	}
	wg.Wait()
	close(results)
	var first string
	for cert := range results {
		if first == "" {
			first = cert
		} else if cert != first {
			t.Fatal("retry issued another certificate")
		}
	}
	if len(a.Status().Certificates) != 2 {
		t.Fatal("renewal retry created extra certificate records")
	}
	otherCSR, _, _ := GenerateCSR("a")
	for n := 0; n < 50; n++ {
		if _, _, err := a.Renew(otherCSR, "a", parent); !errors.Is(err, ErrRenewalBlocked) {
			t.Fatal("parent certificate could create unlimited children", err)
		}
	}
	reopened, err := OpenAuthority(filepath.Dir(a.path), a.policy)
	if err != nil {
		t.Fatal(err)
	}
	repeated, _, err := reopened.Renew(csr, "a", parent)
	if err != nil || repeated != first {
		t.Fatal("lost idempotency on restart", err)
	}
	child, _ := ParseCertificate(first)
	if err := reopened.Revoke(Fingerprint(child)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.Renew(csr, "a", parent); !errors.Is(err, ErrCertificateDenied) {
		t.Fatal("cached response replayed revoked child", err)
	}
}

func FuzzValidateAuthoritySnapshot(f *testing.F) {
	a, err := OpenAuthority(f.TempDir(), Policy{SANs: []string{"localhost"}})
	if err != nil {
		f.Fatal(err)
	}
	seed, err := a.Snapshot()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128*1024 {
			t.Skip()
		}
		if err := ValidateAuthoritySnapshot(data); err == nil {
			var state authorityState
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			// Accepted snapshots must also be safe to expose through redacted status.
			a := &Authority{}
			a.publish(state)
			status := a.Status()
			if status.Active == "" || status.CACert == "" {
				t.Fatal("accepted unusable authority")
			}
		}
	})
}
