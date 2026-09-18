// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
)

func admissionIdentity(t *testing.T, s *Server) *x509.Certificate {
	t.Helper()
	if _, err := s.registerNode(nodeRegistration{Name: "writer-node", PubKey: "pub-writer-node"}, false); err != nil {
		t.Fatal(err)
	}
	csr, _, err := pki.GenerateCSR("writer-node")
	if err != nil {
		t.Fatal(err)
	}
	pem, _, err := s.authority.Issue(csr, "writer-node")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(pem)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func admissionRequest(cert *x509.Certificate, path string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}

// Holding a PKI handler models an admitted slow write. Other writer requests
// and a destructive transition must wait outside the shared API drain barrier.
func TestPKIWriterBacklogDoesNotBlockFleetReaders(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	cert := admissionIdentity(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		s.requireClientCert(func(http.ResponseWriter, *http.Request) { close(entered); <-release })(httptest.NewRecorder(), admissionRequest(cert, "/pki/renew"))
	}()
	<-entered
	var writers sync.WaitGroup
	for i := 0; i < 32; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			s.requireClientCert(func(http.ResponseWriter, *http.Request) { <-release })(httptest.NewRecorder(), admissionRequest(cert, "/pki/ack"))
		}()
	}
	transition := make(chan error, 1)
	go func() {
		_, err := s.adminPKI(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)})
		transition <- err
	}()
	// Give a pending exclusive transition an opportunity to queue behind the
	// held request; keep that request held for the entire fleet read deadline.
	time.Sleep(25 * time.Millisecond)
	results := make(chan int, 32)
	for i := 0; i < 32; i++ {
		go func() {
			w := httptest.NewRecorder()
			r := admissionRequest(cert, "/fleet/status")
			r.Method = http.MethodGet
			s.requireClientCert(s.handleFleetStatus)(w, r)
			results <- w.Code
		}()
	}
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	failed := false
	for i := 0; i < 32; i++ {
		select {
		case status := <-results:
			if status != 200 {
				t.Errorf("read status %d", status)
			}
		case <-timeout.C:
			failed = true
			i = 32
		}
	}
	unblock()
	<-firstDone
	writers.Wait()
	if err := <-transition; err != nil {
		t.Fatal(err)
	}
	if failed {
		t.Fatal("PKI writer backlog blocked fleet readers beyond 1s")
	}
	w := httptest.NewRecorder()
	s.requireClientCert(func(http.ResponseWriter, *http.Request) { t.Error("revoked request executed") })(w, admissionRequest(cert, "/pki/renew"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked certificate status=%d", w.Code)
	}
}

func TestQueuedPKIRequestCancellationAndReauthorization(t *testing.T) {
	for _, mode := range []string{"cancel", "revoke", "remove"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testAdminServer(t, t.TempDir())
			cert := admissionIdentity(t, s)
			release, err := s.pkiAdmission.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			unlock := func() { once.Do(release) }
			defer unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := admissionRequest(cert, "/pki/renew").WithContext(ctx)
			done := make(chan int, 1)
			go func() {
				w := httptest.NewRecorder()
				s.requireClientCert(func(http.ResponseWriter, *http.Request) { t.Error("queued invalid request executed") })(w, r)
				done <- w.Code
			}()
			select {
			case <-done:
				t.Fatal("request bypassed occupied writer gate")
			case <-time.After(20 * time.Millisecond):
			}
			want := http.StatusForbidden
			switch mode {
			case "cancel":
				cancel()
				want = http.StatusRequestTimeout
			case "revoke":
				if err := s.authority.Revoke(pki.Fingerprint(cert)); err != nil {
					t.Fatal(err)
				}
			case "remove":
				// Model the published identity state while this test owns the same outer
				// gate as removeNode. The separate removal regressions exercise its commit.
				s.mu.Lock()
				s.reg.RemovedNodes["writer-node"] = time.Now()
				s.reg.Nodes = nil
				s.mu.Unlock()
			}
			if mode == "cancel" {
				select {
				case got := <-done:
					if got != want {
						t.Fatalf("status=%d", got)
					}
				case <-time.After(time.Second):
					t.Fatal("canceled waiter retained until writer released")
				}
				unlock()
				return
			}
			unlock()
			select {
			case got := <-done:
				if got != want {
					t.Fatalf("status=%d", got)
				}
			case <-time.After(time.Second):
				t.Fatal("waiter did not finish")
			}
		})
	}
}

func TestPKIMaintenanceShutdownWhileQueued(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	release, err := s.pkiAdmission.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	stop := s.startPKIMaintenance()
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance cancellation retained by writer queue")
	}
}
