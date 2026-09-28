// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
)

func TestStorageHealthMTLSAndUnknownMetrics(t *testing.T) {
	s, h := lifecycleServer(t, "10m", "30m")
	client, dir := lifecycleNode(t, s, h, "robot")
	monitorRegister(t, client, "robot", wireGuardTestKey(1))
	ctx := context.Background()
	r, e := client.FleetStorage(ctx)
	if e != nil || r.Validity != "unknown" || r.Values != nil {
		t.Fatal(r, e)
	}
	st := s.history.(storageHealthSource)
	now := time.Now().UTC()
	if e = st.RefreshStorageHealth(ctx, now); e != nil {
		t.Fatal(e)
	}
	r, e = client.FleetStorage(ctx)
	if e != nil || r.Validity != "observed" || r.Values == nil {
		t.Fatal(r, e)
	}
	reg := prometheus.NewRegistry()
	at := now
	reg.MustRegister(newStorageHealthCollector(func() history.StorageHealth { return s.storageHealth(at) }))
	for _, stale := range []bool{false, true} {
		if stale {
			at = now.Add(history.HealthStaleAfter)
		}
		families, e := reg.Gather()
		if e != nil {
			t.Fatal(e)
		}
		for _, f := range families {
			value := f.Metric[0].GetGauge().GetValue()
			if f.GetName() == "vpnctl_history_storage_database_bytes" && math.IsNaN(value) != stale {
				t.Fatal(stale, value)
			}
			if f.GetName() == "vpnctl_history_storage_collection_valid" && ((value == 1) == stale) {
				t.Fatal(stale, value)
			}
			if f.GetName() == "vpnctl_history_storage_wireguard_rows" && !math.IsNaN(value) {
				t.Fatal("unenabled WireGuard storage reported as measured zero", value)
			}
			if len(f.Metric) != 1 || len(f.Metric[0].Label) != 0 {
				t.Fatal("unbounded labels", f)
			}
		}
	}
	creds, e := pki.LoadCredentials(dir)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := pki.ParseCertificate(creds.ClientCert)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.adminPKI(api.AdminRequest{Operation: "pki.revoke", Fingerprint: pki.Fingerprint(cert)}); e != nil {
		t.Fatal(e)
	}
	_, e = client.FleetStorage(ctx)
	expectMonitorCode(t, e, 403)
}

type waitingHealthStore struct {
	history.Storage
	entered chan struct{}
	stopped chan struct{}
}

func (s *waitingHealthStore) StorageHealth(time.Time) history.StorageHealth {
	return history.UnknownStorageHealth("not_collected")
}
func (s *waitingHealthStore) RefreshStorageHealth(ctx context.Context, _ time.Time) error {
	close(s.entered)
	<-ctx.Done()
	close(s.stopped)
	return ctx.Err()
}
func TestStorageHealthShutdownCancelsCollection(t *testing.T) {
	s := newIdentityTestServer(t)
	w := &waitingHealthStore{Storage: s.history, entered: make(chan struct{}), stopped: make(chan struct{})}
	s.history = w
	stop := s.startStorageHealth()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collection not drained")
	}
	select {
	case <-w.stopped:
	default:
		t.Fatal("reader leaked")
	}
}

func TestStorageHealthPageUsesCachedUnknownState(t *testing.T) {
	s := newIdentityTestServer(t)
	if d := s.statusPageData(); d.Storage.Values != nil || d.Storage.Validity != "unknown" {
		t.Fatal(d.Storage)
	}
	st := s.history.(storageHealthSource)
	if e := st.RefreshStorageHealth(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if d := s.statusPageData(); d.Storage.Values == nil || d.Storage.Validity != "observed" {
		t.Fatal(d.Storage)
	}
}
