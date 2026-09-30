// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyKeyRequiresCurrentApproval(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "denied", "uncertain", "refreshing", "wrong-controller", "wrong-generation", "wrong-public", "disabled", "draining", "retired"} {
		t.Run(mode, func(t *testing.T) {
			s := openCache(t, privateTempDir(t))
			f := newController(t)
			r := ready(t, s, f)
			controller, generation, pub := r.ControllerID, r.ObservedGeneration, r.Paths[0].PublicKey
			switch mode {
			case "expired":
				s.now = func() time.Time { return f.state.ExpiresAt.Add(time.Second) }
			case "denied":
				s.state.BlockedReason = "identity_denied"
			case "uncertain":
				s.uncertain = true
			case "refreshing":
				s.state.Refresh.Result = "in_progress"
			case "wrong-controller":
				controller = "other"
			case "wrong-generation":
				generation++
			case "wrong-public":
				pub = testPublic("other")
			case "disabled":
				s.state.Catalog.Spec.Paths[0].Disabled = true
			case "draining":
				s.state.Catalog.Spec.Paths[0].Drain = true
			case "retired":
				s.state.Keys[0].Retired = true
			}
			called := false
			err := s.WithPathKey(controller, generation, "p1", pub, func(key string) error {
				called = true
				if key == "" {
					t.Fatal("empty key")
				}
				return nil
			})
			if (err == nil) != (mode == "valid") || called != (mode == "valid") {
				t.Fatal("unapproved key exposed", mode, err)
			}
		})
	}
}
func TestApplyJournalFileProtection(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "public-mode", "oversize", "deleted", "dir-sync"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateTempDir(t)
			s := openCache(t, dir)
			if err := s.SaveApplyJournal([]byte(`{"test":true}`)); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "apply.json")
			switch mode {
			case "symlink":
				os.Rename(p, filepath.Join(dir, "target"))
				if err := os.Symlink("target", p); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "public-mode":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(p, make([]byte, (128<<10)+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "deleted":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			case "dir-sync":
				s.syncDir = func() error { return errors.New("sync failure") }
				if err := s.SaveApplyJournal([]byte(`{"test":false}`)); err == nil || !s.uncertain {
					t.Fatal("sync uncertainty hidden")
				}
			}
			if _, err := s.ApplyJournal(); err == nil {
				t.Fatal("unsafe journal accepted", mode)
			}
		})
	}
}
