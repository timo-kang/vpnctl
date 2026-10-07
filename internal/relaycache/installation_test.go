// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInstallationConsentLifecycle(t *testing.T) {
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	revision := strings.Repeat("a", 32)
	if ok, err := s.InstallationConsent("p0", revision); err != nil || ok {
		t.Fatal(ok, err)
	}
	if err := s.AllowInstallation("p0", revision); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.InstallationConsent("p0", revision); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := s.InstallationConsent("p0", strings.Repeat("b", 32)); err != nil || ok {
		t.Fatal("stale revision authorized", ok, err)
	}
	if err := s.RevokeInstallation("p0"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInstallation("p0"); err != nil {
		t.Fatal("repeat opt-out not idempotent", err)
	}
	s.Close()
	s = openDeployment(t, dir)
	if ok, err := s.InstallationConsent("p0", revision); err != nil || ok {
		t.Fatal("revocation lost on reopen", ok, err)
	}
}

func TestInstallationConsentRejectsUnsafeAndUncertain(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "public", "corrupt", "sync"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			rev := strings.Repeat("a", 32)
			if err := s.AllowInstallation("p0", rev); err != nil {
				t.Fatal(err)
			}
			name, _ := installationFile("p0")
			p := filepath.Join(dir, name)
			switch mode {
			case "symlink":
				if err := os.Rename(p, p+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(name+"-original", p); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p, p+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(p, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "sync":
				s.syncDir = func() error { return syscall.ENOSPC }
				if err := s.RevokeInstallation("p0"); !errors.Is(err, syscall.ENOSPC) {
					t.Fatal(err)
				}
			}
			if ok, err := s.InstallationConsent("p0", rev); err == nil || ok {
				t.Fatal("unsafe consent authorized", ok, err)
			}
			if mode != "corrupt" && mode != "sync" {
				if err := s.RevokeInstallation("p0"); !errors.Is(err, ErrUnsafe) {
					t.Fatal("foreign file deleted", err)
				}
			}
		})
	}
}
