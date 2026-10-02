// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestAuthorityCopyDoesNotMutateCommittedGeneration(t *testing.T) {
	a := testAuthority(t)
	cert := issueTestCert(t, a, "robot")
	if err := a.Acknowledge("robot", cert, a.Status().Generation); err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate("prepare", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate("activate", nil); err != nil {
		t.Fatal(err)
	}
	csr, _, err := GenerateCSR("robot")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Renew(csr, "robot", cert); err != nil {
		t.Fatal(err)
	}
	before, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	next := a.clone()
	if !reflect.DeepEqual(next, a.state) {
		t.Fatal("copy changed persisted state")
	}
	for key := range next.CAs {
		next.CAs[key] = Material{Cert: "changed", Key: "changed"}
	}
	for key, record := range next.Certificates {
		record.RevokedAt = time.Now()
		next.Certificates[key] = record
	}
	for key := range next.Acks {
		delete(next.Acks, key)
	}
	for key := range next.Renewals {
		next.Renewals[key] = renewalRecord{CSRHash: "changed", Certificate: "changed"}
	}
	next.Server.Cert = "changed"
	after, err := a.Snapshot()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("uncommitted candidate changed published state", err)
	}
	if err := a.Observe(cert, "robot"); err != nil {
		t.Fatal("copy changed live authorization", err)
	}
}

func TestAcknowledgementNoOpRetainsAuthorizationChecks(t *testing.T) {
	a := testAuthority(t)
	cert := issueTestCert(t, a, "robot")
	generation := a.Status().Generation
	if err := a.Acknowledge("robot", cert, generation); err != nil {
		t.Fatal(err)
	}
	before, _ := a.Snapshot()
	original := a.write
	a.write = func(string, []byte, os.FileMode) error {
		t.Error("duplicate ACK attempted persistence")
		return errors.New("unexpected write")
	}
	for i := 0; i < 32; i++ {
		if err := a.Acknowledge("robot", cert, generation); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Acknowledge("other", cert, generation); err == nil {
		t.Fatal("wrong node accepted")
	}
	if err := a.Acknowledge("robot", cert, generation+1); err == nil {
		t.Fatal("wrong generation accepted")
	}
	after, _ := a.Snapshot()
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate/rejected ACK changed durable state")
	}
	a.write = original
	if err := a.Revoke(Fingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	if err := a.Acknowledge("robot", cert, generation); !errors.Is(err, ErrCertificateDenied) {
		t.Fatal("duplicate ACK bypassed revocation", err)
	}
}

var authorityCopySink authorityState

// The population models retained metadata and PEM renewal responses. Benchmark
// the existing operation unchanged on both the baseline and candidate binaries.
func BenchmarkAuthorityCopyHistory(b *testing.B) {
	for _, size := range []int{32, 320, 3200} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			a, err := OpenAuthority(b.TempDir(), Policy{})
			if err != nil {
				b.Fatal(err)
			}
			a.state.Renewals = make(map[string]renewalRecord, size)
			now := time.Now().UTC()
			for i := 0; i < size; i++ {
				fp := fmt.Sprintf("%064x", i+1)
				id := fmt.Sprintf("node-%d", i%32)
				a.state.Certificates[fp] = CertificateRecord{NodeID: id, Serial: fmt.Sprint(i), Fingerprint: fp, Issuer: a.state.Active, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
				a.state.Renewals[fp+":"+a.state.Active] = renewalRecord{CSRHash: fp, Certificate: a.state.Server.Cert}
				a.state.Acks[id] = TrustAck{Generation: 1, Fingerprint: fp, At: now}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				authorityCopySink = a.clone()
			}
		})
	}
}
