// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestTokenCreationRetryAcrossInstancesAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	var wg sync.WaitGroup
	results := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts, err := OpenTokenStore(path)
			if err != nil {
				t.Error(err)
				return
			}
			token, err := ts.CreateIdempotent(time.Hour, true, "retry-1")
			if err != nil {
				t.Error(err)
				return
			}
			results <- token
		}()
	}
	wg.Wait()
	close(results)
	var original string
	for token := range results {
		if original != "" && original != token {
			t.Fatal("duplicate credential on retry")
		}
		original = token
	}
	ts, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := ts.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if _, err := ts.CreateIdempotent(time.Minute, true, "retry-1"); !errors.Is(err, ErrRequestIDConflict) {
		t.Fatal("changed TTL not rejected", err)
	}
	if _, err := ts.CreateIdempotent(time.Hour, false, "retry-1"); !errors.Is(err, ErrRequestIDConflict) {
		t.Fatal("changed policy not rejected", err)
	}
	if err := ts.Use(original, "robot", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := ts.Revoke(original); err != nil {
		t.Fatal(err)
	}
	ts, err = OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.CreateIdempotent(time.Hour, true, "retry-1")
	if err != nil || token != original {
		t.Fatal("inactive token replaced on retry", err)
	}
	record, err := ts.CreationResult("retry-1")
	if err != nil || record.UseCount != 1 || record.RevokedAt.IsZero() {
		t.Fatal("lost creation result", err)
	}
	if _, err := ts.CreationResult("unknown"); !errors.Is(err, ErrRequestNotFound) {
		t.Fatal(err)
	}
}

func TestTokenCreationRetryAfterWriteErrors(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_replace", true: "after_replace"}[replaced], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tokens.json")
			ts, err := OpenTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			original := ts.write
			ts.write = func(path string, raw []byte, mode os.FileMode) error {
				if replaced {
					if err := original(path, raw, mode); err != nil {
						return err
					}
				}
				return syscall.EIO
			}
			if _, err := ts.CreateIdempotent(time.Hour, false, "retry"); err == nil {
				t.Fatal("uncertain write reported success")
			}
			// Reload is authoritative even for an unclassified post-rename error.
			var committed string
			if record, err := ts.CreationResult("retry"); err == nil {
				committed = record.Token
			} else if replaced || !errors.Is(err, ErrRequestNotFound) {
				t.Fatal(err)
			}
			ts, err = OpenTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			token, err := ts.CreateIdempotent(time.Hour, false, "retry")
			if err != nil {
				t.Fatal(err)
			}
			if replaced && token != committed {
				t.Fatal("post-rename retry issued a second credential")
			}
			records, err := ts.Records()
			if err != nil || len(records) != 1 {
				t.Fatal("creation history inconsistent", err)
			}
		})
	}
}

func TestTokenRequestValidation(t *testing.T) {
	for _, id := range []string{"", "bad\nline", "has space", string(make([]byte, 129))} {
		if ValidateRequestID(id) == nil {
			t.Fatalf("accepted request ID %q", id)
		}
	}
	ts, err := OpenTokenStore(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.CreateIdempotent(time.Second, true, "valid"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ts.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTokenSnapshot(raw); err != nil {
		t.Fatal(err)
	}
}

func TestTokenSnapshotRejectsConflictingCreationMetadata(t *testing.T) {
	now := time.Now().UTC()
	valid := TokenRecord{Token: "token-a", RequestID: "request-a", RequestedTTL: time.Hour, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	for _, fault := range []string{"duplicate-id", "changed-options", "invalid-id"} {
		t.Run(fault, func(t *testing.T) {
			records := []TokenRecord{valid}
			switch fault {
			case "duplicate-id":
				next := valid
				next.Token = "token-b"
				records = append(records, next)
			case "changed-options":
				records[0].RequestedTTL = time.Minute
			case "invalid-id":
				records[0].RequestID = "bad id"
			}
			raw, err := json.Marshal(struct {
				Version int           `json:"version"`
				Tokens  []TokenRecord `json:"tokens"`
			}{1, records})
			if err != nil {
				t.Fatal(err)
			}
			if ValidateTokenSnapshot(raw) == nil {
				t.Fatal("corrupt request metadata accepted")
			}
		})
	}
}
