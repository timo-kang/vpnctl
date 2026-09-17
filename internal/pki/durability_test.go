// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"vpnctl/internal/atomicfile"
)

func TestTokenUncertainCommitNeverAdmitsAndRetainsState(t *testing.T) {
	for _, operation := range []string{"use", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tokens.json")
			ts, err := OpenTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			token, err := ts.CreateWithOptions(time.Hour, true)
			if err != nil {
				t.Fatal(err)
			}
			ts.write = func(p string, b []byte, m os.FileMode) error {
				if err := WriteAtomic(p, b, m); err != nil {
					return err
				}
				return &atomicfile.CommitError{Err: syscall.EIO}
			}
			called := false
			if operation == "use" {
				err = ts.Use(token, "node", func() error { called = true; return nil })
			} else {
				err = ts.Revoke(token)
			}
			if !atomicfile.Replaced(err) || !errors.Is(err, syscall.EIO) || called {
				t.Fatalf("err=%v callback=%v", err, called)
			}
			if ts.tokens[token].active(time.Now()) {
				t.Fatal("memory reverted to active token")
			}
			restarted, err := OpenTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := restarted.Validate(token); err != nil || ok {
				t.Fatalf("restart admitted token: %v %v", ok, err)
			}
			if err := restarted.Use(token, "node", func() error { t.Fatal("replayed token"); return nil }); !errors.Is(err, ErrInvalidToken) {
				t.Fatal(err)
			}
			if err := restarted.Revoke(token); err != nil {
				t.Fatal(err)
			}
		})
	}
}
