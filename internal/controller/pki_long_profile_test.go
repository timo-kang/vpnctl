// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/pki"
)

// A short certificate accelerates MaintainCredentials and hides the real idle
// interval. Keep one-hour credentials and the actual worker/timers in this test.
func TestPKILongLivedAutomaticCARotation(t *testing.T) {
	if os.Getenv("VPNCTL_PKI_LONG_PROFILE") != "1" {
		t.Skip("dedicated real-time PKI profile")
	}
	s, _ := lifecycleServer(t, "1h", "24h", "40m")
	var seen sync.Map
	var tracking atomic.Bool
	handler := s.httpHandler()
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if tracking.Load() && r.URL.Path == "/pki/ack" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if id, _, e := pki.CertificateNodeIdentity(r.TLS.PeerCertificates[0]); e == nil {
				seen.Store(id, true)
			}
		}
	}))
	h.TLS = s.authority.DynamicTLSConfig()
	h.StartTLS()
	t.Cleanup(h.Close)
	const size = 3
	clients := make([]*api.Client, size)
	dirs := make([]string, size)
	for n := range clients {
		clients[n], dirs[n] = lifecycleNode(t, s, h, fmt.Sprintf("n-%d", n))
	}
	initial := s.authority.Status()
	tracking.Store(true)
	for n, c := range clients {
		startNodePKI(t, c, dirs[n], fmt.Sprintf("n-%d", n))
	}
	waitPKI(t, 5*time.Second, func() bool {
		for n := 0; n < size; n++ {
			if _, ok := seen.Load(fmt.Sprintf("n-%d", n)); !ok {
				return false
			}
		}
		return true
	})
	admin := func(op string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, e := api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: op})
		return e
	}
	verifyAPI := func() {
		t.Helper()
		for _, c := range clients {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, e := c.FleetStatus(ctx)
			cancel()
			if e != nil {
				t.Fatal("CA transition interrupted API", e)
			}
		}
	}
	converge := func(op string) {
		t.Helper()
		started := time.Now()
		deadline := started.Add(api.CredentialSyncMaxDelay + time.Minute)
		var last error
		for time.Now().Before(deadline) {
			if last = admin(op); last == nil {
				t.Logf("%s converged after %s", op, time.Since(started))
				return
			}
			verifyAPI()
			time.Sleep(time.Second)
		}
		t.Fatalf("%s did not converge: %v", op, last)
	}
	requireIssuer := func(issuer string) {
		t.Helper()
		waitPKI(t, api.CredentialSyncMaxDelay+time.Minute, func() bool {
			status := s.authority.Status()
			for id, ack := range status.Acks {
				if ack.Generation != status.Generation {
					return false
				}
				found := false
				for _, cert := range status.Certificates {
					if cert.Fingerprint == ack.Fingerprint && cert.NodeID == id && cert.Issuer == issuer {
						found = true
					}
				}
				if !found {
					return false
				}
			}
			return len(status.Acks) == size
		})
		for n := range clients {
			cred, e := pki.LoadCredentials(dirs[n])
			if e != nil {
				t.Fatal(e)
			}
			if e = cred.ValidateForInstall(fmt.Sprintf("n-%d", n)); e != nil {
				t.Fatal(e)
			}
		}
		verifyAPI()
	}
	if e := admin("ca.prepare"); e != nil {
		t.Fatal(e)
	}
	// Reproduce the old test deadline: a healthy worker may still be asleep.
	time.Sleep(30 * time.Second)
	if e := admin("ca.activate"); e == nil {
		t.Fatal("30s unexpectedly sufficed; long polling boundary was not exercised")
	} else {
		var response *api.HTTPError
		if !errors.As(e, &response) || response.StatusCode != 409 {
			t.Fatal("expected missing-ACK conflict", e)
		}
	}
	verifyAPI()
	converge("ca.activate")
	active := s.authority.Status().Active
	if active == initial.Active {
		t.Fatal("issuer did not change")
	}
	requireIssuer(active)
	converge("ca.retire")
	if e := admin("ca.prepare"); e != nil {
		t.Fatal(e)
	}
	converge("ca.activate")
	rolledFrom := s.authority.Status().Active
	if rolledFrom == active {
		t.Fatal("second issuer did not change")
	}
	requireIssuer(rolledFrom)
	if e := admin("ca.rollback"); e != nil {
		t.Fatal(e)
	}
	requireIssuer(active)
	converge("ca.retire")
	if status := s.authority.Status(); status.Phase != "stable" || len(status.CAs) != 1 || status.Active != active {
		t.Fatal("rollback/retirement incomplete")
	}
	verifyAPI()
}
