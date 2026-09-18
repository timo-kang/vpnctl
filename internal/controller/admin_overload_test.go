// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"vpnctl/internal/pki"

	"vpnctl/internal/api"
)

func TestAdminAdmissionBoundedCancellation(t *testing.T) {
	var gate adminAdmission
	release, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(release) }
	defer unblock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queued := make(chan error, adminQueueLimit)
	for i := 0; i < adminQueueLimit; i++ {
		go func() {
			unlock, err := gate.acquire(ctx)
			if unlock != nil {
				unlock()
			}
			queued <- err
		}()
	}
	waitPKI(t, time.Second, func() bool { return len(gate.slots) == adminQueueLimit+1 })
	if unlock, err := gate.acquire(context.Background()); !errors.Is(err, errAdminOverloaded) {
		if unlock != nil {
			unlock()
		}
		t.Fatal("queue overflow admitted", err)
	}
	cancel()
	for i := 0; i < adminQueueLimit; i++ {
		if err := <-queued; !errors.Is(err, context.Canceled) {
			t.Fatal("queued cancellation executed", err)
		}
	}
	if len(gate.slots) != 1 {
		t.Fatal("canceled queue leaked capacity")
	}
	start := time.Now()
	if unlock, err := gate.acquire(context.Background()); !errors.Is(err, errAdminOverloaded) {
		if unlock != nil {
			unlock()
		}
		t.Fatal("queue wait unbounded", err)
	}
	if time.Since(start) > adminQueueWait+time.Second {
		t.Fatal("queue deadline exceeded")
	}
	unblock()
	unlock, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func TestAdminTokenAcceptedDisconnectAndQueuedCancellation(t *testing.T) {
	dir := t.TempDir()
	s, stop := testAdminServer(t, dir)
	initialize, err := s.adminAdmission.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	initialize()
	initial, err := s.tokenStore.Records()
	if err != nil {
		t.Fatal(err)
	}
	// An external store lock holds a real accepted write, without holding the
	// controller's identity/PKI locks. This models slow durable token persistence.
	lock, err := os.OpenFile(filepath.Join(s.pkiDir, "bootstrap-tokens.json.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }) }
	defer unblock()
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first := make(chan error, 1)
	go func() {
		_, err := api.Admin(firstCtx, dir, api.AdminRequest{Operation: "token.create", RequestID: "accepted", TTL: "1h", SingleUse: true})
		first <- err
	}()
	waitPKI(t, time.Second, func() bool { return len(s.adminAdmission.active) == 1 })
	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	defer cancelQueued()
	queued := make(chan error, 1)
	go func() {
		_, err := api.Admin(queuedCtx, dir, api.AdminRequest{Operation: "token.create", RequestID: "canceled", TTL: "1h"})
		queued <- err
	}()
	waitPKI(t, time.Second, func() bool { return len(s.adminAdmission.slots) == 2 })
	cancelQueued()
	if err := <-queued; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	waitPKI(t, time.Second, func() bool { return len(s.adminAdmission.slots) == 1 })
	cancelFirst()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unblock()
	// Retrying shares the original durable record even if disconnect preceded
	// completion. The canceled waiter must never create a record afterwards.
	result, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.create", RequestID: "accepted", TTL: "1h", SingleUse: true})
	if err != nil {
		t.Fatal(err)
	}
	records, err := s.tokenStore.Records()
	if err != nil || len(records) != len(initial)+1 {
		t.Fatal("unexpected token writes", err, len(records))
	}
	for _, record := range records {
		if record.RequestID == "canceled" {
			t.Fatal("canceled queued operation executed")
		}
	}
	stop()
	_, _ = testAdminServer(t, dir)
	recovered, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.result", RequestID: "accepted"})
	if err != nil || recovered.TokenRecord == nil || recovered.TokenRecord.Token != result.Token {
		t.Fatal("lost durable creation result", err)
	}
}

func TestAdminOverloadVariableConcurrency(t *testing.T) {
	for _, size := range []int{1, 8, 32, 253} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dir := t.TempDir()
			s, _ := testAdminServer(t, dir)
			before, err := s.tokenStore.Records()
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			type result struct {
				elapsed time.Duration
				err     error
			}
			results := make(chan result, size)
			began := time.Now()
			for i := 0; i < size; i++ {
				go func() {
					<-start
					at := time.Now()
					_, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.create", RequestID: fmt.Sprintf("burst-%d", i), TTL: "1h"})
					results <- result{time.Since(at), err}
				}()
			}
			close(start)
			accepted, rejected := 0, 0
			var durations []time.Duration
			for i := 0; i < size; i++ {
				r := <-results
				durations = append(durations, r.elapsed)
				if r.err == nil {
					accepted++
					continue
				}
				var status *api.HTTPError
				if errors.As(r.err, &status) && status.StatusCode == 503 {
					rejected++
				} else {
					t.Error(r.err)
				}
			}
			records, err := s.tokenStore.Records()
			if err != nil || len(records) != len(before)+accepted {
				t.Fatalf("accepted writes do not match committed records: %d %d %v", accepted, len(records)-len(before), err)
			}
			sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
			t.Logf("concurrency=%d accepted=%d explicit_overload=%d elapsed=%s p95=%s max=%s", size, accepted, rejected, time.Since(began), durations[(len(durations)-1)*95/100], durations[len(durations)-1])
			if accepted+rejected != size {
				t.Fatal("unaccounted requests")
			}
		})
	}
}

func TestAdminTokenOverloadPreservesFleetHeartbeatAndRenewal(t *testing.T) {
	dir := t.TempDir()
	s, _ := testAdminServer(t, dir)
	records, err := s.tokenStore.Records()
	if err != nil {
		t.Fatal(err)
	}
	h, bootstrap, config := testTLSAPI(t, s)
	client, _, nodeTLS := enrollTestClient(t, h, bootstrap, config, records[0].Token, "robot")
	defer client.CloseIdleConnections()
	// Make the certificate eligible for renewal without relying on a wall clock.
	if err := s.authority.Rotate("prepare", nil); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(s.authority.Status().CACert))
	nodeTLS = nodeTLS.Clone()
	nodeTLS.RootCAs = roots
	nodeTLS.MinVersion = tls.VersionTLS13
	if err := s.authority.Rotate("activate", nil); err != nil {
		t.Fatal(err)
	}
	client = api.NewTLSClient(h.URL, nodeTLS)
	defer client.CloseIdleConnections()
	initialize, err := s.adminAdmission.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	initialize()
	lock, err := os.OpenFile(filepath.Join(s.pkiDir, "bootstrap-tokens.json.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }) }
	defer unblock()
	writer := make(chan error, 1)
	go func() {
		_, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.create", RequestID: "held", TTL: "1h"})
		writer <- err
	}()
	waitPKI(t, time.Second, func() bool { return len(s.adminAdmission.active) == 1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiters := make(chan error, adminQueueLimit)
	for i := 0; i < adminQueueLimit; i++ {
		go func() {
			_, err := api.Admin(ctx, dir, api.AdminRequest{Operation: "token.create", RequestID: fmt.Sprintf("wait-%d", i), TTL: "1h"})
			waiters <- err
		}()
	}
	waitPKI(t, time.Second, func() bool { return len(s.adminAdmission.slots) == adminQueueLimit+1 })
	// Explicit overload is immediate and cannot turn into a later write.
	for i := 0; i < 32; i++ {
		_, err := api.Admin(context.Background(), dir, api.AdminRequest{Operation: "token.create", RequestID: fmt.Sprintf("rejected-%d", i)})
		var status *api.HTTPError
		if !errors.As(err, &status) || status.StatusCode != 503 {
			t.Fatalf("overload response: %v", err)
		}
	}
	results := make(chan error, 34)
	for i := 0; i < 32; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := client.FleetStatus(ctx)
			results <- err
		}()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := client.Register(ctx, api.RegisterRequest{Name: "robot", PubKey: "pub-robot"})
		results <- err
	}()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		csr, _, err := pki.GenerateCSR("robot")
		if err == nil {
			_, err = client.Renew(ctx, string(csr))
		}
		results <- err
	}()
	for i := 0; i < 34; i++ {
		if err := <-results; err != nil {
			t.Error("admin overload blocked fleet/heartbeat/renewal", err)
		}
	}
	cancel()
	for i := 0; i < adminQueueLimit; i++ {
		<-waiters
	}
	waitPKI(t, time.Second, func() bool { return len(s.adminAdmission.slots) == 1 })
	unblock()
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	after, err := s.tokenStore.Records()
	if err != nil || len(after) != len(records)+1 {
		t.Fatal("rejected requests mutated token state", err)
	}
}

func TestAdminQueueDeadlineHTTPIsExplicitAndDoesNotExecute(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	before, err := s.tokenStore.Records()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := s.adminAdmission.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for _, cancelEarly := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), adminActorKey{}, "uid:test"))
		if cancelEarly {
			cancel()
		}
		req := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(`{"operation":"token.create","request_id":"never-started"}`)).WithContext(ctx)
		rec := httptest.NewRecorder()
		s.handleAdmin(rec, req)
		cancel()
		expected := http.StatusServiceUnavailable
		if cancelEarly {
			expected = http.StatusRequestTimeout
		}
		if rec.Code != expected || !strings.Contains(rec.Body.String(), "operation not started") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !cancelEarly && rec.Header().Get("Retry-After") != "1" {
			t.Fatal("missing backpressure retry hint")
		}
	}
	after, err := s.tokenStore.Records()
	if err != nil || len(before) != len(after) {
		t.Fatal("unadmitted request mutated storage", err)
	}
}
