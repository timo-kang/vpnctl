// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSingleUseConcurrentAdmissionAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.CreateWithOptions(time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 64; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, err := OpenTokenStore(path)
			if err != nil {
				t.Error(err)
				return
			}
			err = other.Use(token, "node-a", func() error { success.Add(1); return nil })
			if err != nil && !errors.Is(err, ErrInvalidToken) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("admissions=%d", success.Load())
	}
	reopened, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := reopened.Validate(token); err != nil || valid {
		t.Fatalf("consumed token valid=%v err=%v", valid, err)
	}
	records, err := reopened.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].UseCount != 1 || records[0].LastUsedBy != "node-a" || records[0].LastUsedAt.IsZero() {
		t.Fatalf("history=%+v", records)
	}
}

func TestTokenExpiryLegacyMigrationAndFailedAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte(`["legacy"]`), 0600); err != nil {
		t.Fatal(err)
	}
	ts, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Use("legacy", "old-node", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := migrated.Records()
	if err != nil {
		t.Fatal(err)
	}
	if records[0].UseCount != 1 || !records[0].ExpiresAt.IsZero() {
		t.Fatalf("migration=%+v", records)
	}
	token, err := ts.CreateWithOptions(time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("registry unavailable")
	if err := ts.Use(token, "node-a", func() error { return injected }); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if valid, _ := ts.Validate(token); valid {
		t.Fatal("failed single-use admission may be replayed")
	}
	expired, err := ts.CreateWithOptions(time.Nanosecond, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Use(expired, "node-b", func() error { t.Fatal("expired token callback"); return nil }); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expiry=%v", err)
	}
	if _, err := ts.CreateWithOptions(-time.Second, false); err == nil {
		t.Fatal("negative TTL accepted")
	}
}

func TestRevokeWaitsForAdmittedUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.Create()
	if err != nil {
		t.Fatal(err)
	}
	other, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	admitted, release := make(chan struct{}), make(chan struct{})
	used, revoked := make(chan error, 1), make(chan error, 1)
	go func() { used <- ts.Use(token, "node-a", func() error { close(admitted); <-release; return nil }) }()
	<-admitted
	go func() { revoked <- other.Revoke(token) }()
	select {
	case err := <-revoked:
		t.Fatalf("revoke passed pending admission: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-used; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := ts.Use(token, "node-a", func() error { t.Fatal("revoked token admitted"); return nil }); !errors.Is(err, ErrInvalidToken) {
		t.Fatal(err)
	}
}

func TestUsePersistenceFailureDoesNotRunCallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.Create()
	if err != nil {
		t.Fatal(err)
	}
	// An unavailable store directory must fail before enrollment is admitted.
	dir := filepath.Dir(path)
	moved := dir + "-unavailable"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(moved, dir)
	if err := ts.Use(token, "node-a", func() error { t.Fatal("callback after storage failure"); return nil }); err == nil {
		t.Fatal("missing persistence error")
	}
}

func TestTokenAdmissionAndRevokeFailOnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged filesystem permissions")
	}
	dir := t.TempDir()
	ts, err := OpenTokenStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.CreateWithOptions(time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	// Existing token and lock remain readable/writable, but CreateTemp must fail.
	if err := ts.Use(token, "a", func() error { t.Fatal("admitted without persisting consumption"); return nil }); err == nil {
		t.Fatal("write failure accepted")
	}
	if err := ts.Revoke(token); err == nil {
		t.Fatal("revoke reported success without persistence")
	}
	records, err := ts.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].UseCount != 0 || !records[0].RevokedAt.IsZero() {
		t.Fatal("failed write changed stored history")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ts.Use(token, "a", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
