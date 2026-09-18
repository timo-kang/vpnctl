// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
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
	for _, path := range []string{"/pki/renew", "/register"} {
		t.Run(path, func(t *testing.T) { testWriterBacklogDoesNotBlockFleetReaders(t, path) })
	}
}
func testWriterBacklogDoesNotBlockFleetReaders(t *testing.T, path string) {
	s, _ := testAdminServer(t, t.TempDir())
	cert := admissionIdentity(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		s.requireClientCert(func(http.ResponseWriter, *http.Request) { close(entered); <-release })(httptest.NewRecorder(), admissionRequest(cert, path))
	}()
	<-entered
	var writers sync.WaitGroup
	for i := 0; i < 32; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			s.requireClientCert(func(http.ResponseWriter, *http.Request) { <-release })(httptest.NewRecorder(), admissionRequest(cert, path))
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
	s.requireClientCert(func(http.ResponseWriter, *http.Request) { t.Error("revoked request executed") })(w, admissionRequest(cert, path))
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

func TestPKIAdmissionAlternatesAdminAndRenewalBacklogs(t *testing.T) {
	var gate writerAdmission
	release, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	type grant struct {
		priority bool
		release  func()
	}
	granted := make(chan grant, 6)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workers sync.WaitGroup
	for _, priority := range []bool{false, false, false, true, true, true} {
		workers.Add(1)
		go func(priority bool) {
			defer workers.Done()
			release, err := gate.wait(ctx, priority)
			if err == nil {
				granted <- grant{priority, release}
			}
		}(priority)
	}
	waitPKI(t, time.Second, func() bool {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		return len(gate.normal) == 3 && len(gate.priority) == 3
	})
	release()
	for i := 0; i < 6; i++ {
		select {
		case g := <-granted:
			if g.priority != (i%2 == 0) {
				t.Errorf("grant %d priority=%v; backlog class starved", i, g.priority)
			}
			g.release()
		case <-time.After(time.Second):
			t.Fatal("writer queue stopped")
		}
	}
	workers.Wait()
}

func TestRevokedRenewalDoesNotWaitForPKIWriter(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	cert := admissionIdentity(t, s)
	if err := s.authority.Revoke(pki.Fingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	release, err := s.pkiAdmission.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.requireClientCert(func(http.ResponseWriter, *http.Request) { t.Error("revoked request executed") })(w, admissionRequest(cert, "/pki/renew"))
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusForbidden {
			t.Fatalf("status=%d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("known revoked certificate waited for PKI writer")
	}
}

func TestCanceledMutationDoesNotExecuteAfterDrain(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	cert := admissionIdentity(t, s)
	s.mutationAdmission.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.requireClientCert(func(http.ResponseWriter, *http.Request) { t.Error("canceled mutation executed") })(w, admissionRequest(cert, "/register").WithContext(ctx))
		done <- w.Code
	}()
	cancel()
	s.mutationAdmission.Unlock()
	select {
	case code := <-done:
		if code != http.StatusRequestTimeout {
			t.Fatalf("status=%d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled mutation did not finish")
	}
}

func TestRegistryStallDoesNotSerializePKIRenewal(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	cert := admissionIdentity(t, s)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.requireClientCert(func(http.ResponseWriter, *http.Request) { close(held); <-release })(httptest.NewRecorder(), admissionRequest(cert, "/register"))
	}()
	<-held
	renewal := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })(w, admissionRequest(cert, "/pki/renew"))
		renewal <- w.Code
	}()
	select {
	case code := <-renewal:
		if code != http.StatusNoContent {
			t.Fatalf("status=%d", code)
		}
	case <-time.After(time.Second):
		t.Error("registry stall blocked independent PKI handler")
	}
	unblock()
	<-done
}

func TestSlowPKIBodyDoesNotReserveWriter(t *testing.T) {
	for _, path := range []string{"/pki/renew", "/register", "/bootstrap"} {
		t.Run(path, func(t *testing.T) {
			s, _ := testAdminServer(t, t.TempDir())
			cert := admissionIdentity(t, s)
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			r := admissionRequest(cert, path)
			r.Body = reader
			done := make(chan struct{})
			go func() {
				defer close(done)
				w := httptest.NewRecorder()
				if path == "/bootstrap" {
					s.handleBootstrap(w, r)
				} else {
					s.requireClientCert(func(http.ResponseWriter, *http.Request) {})(w, r)
				}
			}()
			// This returns only after the handler has started receiving the body;
			// leave the rest of the upload stalled while another writer must progress.
			if _, err := writer.Write([]byte("{")); err != nil {
				t.Fatal(err)
			}
			progressed := make(chan int, 1)
			go func() {
				w := httptest.NewRecorder()
				s.requireClientCert(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })(w, admissionRequest(cert, "/pki/renew"))
				progressed <- w.Code
			}()
			select {
			case code := <-progressed:
				if code != http.StatusNoContent {
					t.Fatalf("status=%d", code)
				}
			case <-time.After(time.Second):
				t.Error("slow upload reserved writer")
			}
			writer.Close()
			<-done
		})
	}
}
