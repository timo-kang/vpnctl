package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestCommittedReadsDuringBlockedAuthorityWrite(t *testing.T) {
	for _, operation := range []string{"prepare", "issue", "renew", "ack", "server", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			a := testAuthority(t)
			cert := issueTestCert(t, a, "robot")
			other := issueTestCert(t, a, "other")
			if operation == "renew" {
				if err := a.Rotate("prepare", nil); err != nil {
					t.Fatal(err)
				}
				if err := a.Rotate("activate", nil); err != nil {
					t.Fatal(err)
				}
			}
			if operation == "server" {
				a.policy.SANs = []string{"new.example"}
			}
			generation := a.Status().Generation
			before, err := a.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			original := a.write
			a.write = func(path string, raw []byte, mode os.FileMode) error {
				close(entered)
				<-release
				return original(path, raw, mode)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "prepare":
					err = a.Rotate("prepare", nil)
				case "issue":
					csr, _, e := GenerateCSR("new")
					err = e
					if err == nil {
						_, _, err = a.Issue(csr, "new")
					}
				case "renew":
					csr, _, e := GenerateCSR("robot")
					err = e
					if err == nil {
						_, _, err = a.Renew(csr, "robot", cert)
					}
				case "ack":
					err = a.Acknowledge("robot", cert, generation)
				case "server":
					_, err = a.MaintainServer()
				case "revoke":
					err = a.Revoke(Fingerprint(cert))
				}
				done <- err
			}()
			<-entered
			readers := make(chan error, 32)
			var readerWG sync.WaitGroup
			for i := 0; i < 32; i++ {
				readerWG.Add(1)
				go func() {
					defer readerWG.Done()
					if _, err := a.TLSConfig(); err != nil {
						readers <- err
						return
					}
					if err := a.Observe(other, "other"); err != nil {
						readers <- err
						return
					}
					if a.Status().Generation == 0 {
						readers <- fmt.Errorf("missing status")
						return
					}
					snapshot, err := a.Snapshot()
					if err == nil && !bytes.Equal(snapshot, before) {
						err = fmt.Errorf("uncommitted state published")
					}
					readers <- err
				}()
			}
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			failed := false
			for i := 0; i < 32; i++ {
				select {
				case err := <-readers:
					if err != nil {
						t.Error(err)
					}
				case <-timer.C:
					failed = true
					i = 32
				}
			}
			unblock()
			readerWG.Wait()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if failed {
				t.Fatal("committed reads waited for blocked persistence")
			}
			after, _ := a.Snapshot()
			if bytes.Equal(after, before) {
				t.Fatal("completed write not published")
			}
			if operation == "revoke" && a.Observe(cert, "robot") == nil {
				t.Fatal("published revoke ignored")
			}
		})
	}
}

func TestTLSAndAuthorizationDuringSlowPKIPersistence(t *testing.T) {
	a := testAuthority(t)
	cert := issueTestCert(t, a, "robot")
	// Sign a client whose private key is retained for actual TLS handshakes.
	csr, key, err := GenerateCSR("reader")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := a.Issue(csr, "reader")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(raw), key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(a.Status().CACert))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || a.Observe(r.TLS.VerifiedChains[0][0], "reader") != nil {
			http.Error(w, "denied", 403)
			return
		}
		w.WriteHeader(204)
	}))
	server.TLS = a.DynamicTLSConfig()
	server.StartTLS()
	defer server.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	original := a.write
	a.write = func(path string, raw []byte, mode os.FileMode) error {
		close(entered)
		<-release
		return original(path, raw, mode)
	}
	done := make(chan error, 1)
	go func() { done <- a.Acknowledge("robot", cert, a.Status().Generation) }()
	<-entered
	for _, size := range []int{1, 3, 8, 32} {
		errors := make(chan error, size)
		for i := 0; i < size; i++ {
			go func() {
				transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
				response, e := (&http.Client{Transport: transport}).Do(req)
				if e == nil {
					response.Body.Close()
					if response.StatusCode != 204 {
						e = fmt.Errorf("status %d", response.StatusCode)
					}
				}
				errors <- e
			}()
		}
		for i := 0; i < size; i++ {
			if e := <-errors; e != nil {
				t.Errorf("clients=%d: %v", size, e)
			}
		}
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLegacyFirstUsePublishesOnceAndBindsIdentity(t *testing.T) {
	a := testAuthority(t)
	cert := issueTestCert(t, a, "legacy")
	// Imported certificates have no record until their first authorized request.
	next := a.clone()
	delete(next.Certificates, Fingerprint(cert))
	if err := a.commit(next); err != nil {
		t.Fatal(err)
	}
	writes := 0
	original := a.write
	a.write = func(path string, raw []byte, mode os.FileMode) error {
		writes++ // serialized by the authority writer lock
		return original(path, raw, mode)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Observe(cert, "legacy"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if writes != 1 {
		t.Fatalf("first use persisted %d times", writes)
	}
	if err := a.Observe(cert, "different"); !errors.Is(err, ErrCertificateDenied) {
		t.Fatal("published identity binding bypassed", err)
	}
	if err := a.Revoke(Fingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	if err := a.Observe(cert, "legacy"); !errors.Is(err, ErrCertificateDenied) {
		t.Fatal("revoked imported certificate accepted", err)
	}
}

func TestPublishedAuthorityDoesNotAliasReturnedValues(t *testing.T) {
	a := testAuthority(t)
	cert := issueTestCert(t, a, "robot")
	if err := a.Acknowledge("robot", cert, a.Status().Generation); err != nil {
		t.Fatal(err)
	}
	before, _ := a.Snapshot()
	status := a.Status()
	delete(status.Acks, "robot")
	status.Certificates[0].NodeID = "tampered"
	status.CAs[0].NodeID = "tampered"
	config, err := a.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.Certificates[0].Certificate[0][0] ^= 0xff
	config.ClientCAs = x509.NewCertPool()
	after, _ := a.Snapshot()
	if !bytes.Equal(before, after) {
		t.Fatal("caller mutated published authority")
	}
	if err := a.Observe(cert, "robot"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.TLSConfig(); err != nil {
		t.Fatal("caller damaged subsequent TLS config", err)
	}
}
