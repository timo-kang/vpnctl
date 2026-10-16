// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketOwnershipAndStaleRecovery(t *testing.T) {
	dir := testRuntime(t)
	uid := uint32(os.Geteuid())
	l, err := listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if second, err := listen(dir); err == nil {
		second.Close()
		t.Fatal("live listener replaced")
	}
	c, err := Dial(context.Background(), dir, uid)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c, err := Dial(context.Background(), dir, uid+1); err == nil {
		c.Close()
		t.Fatal("wrong server identity trusted")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, socketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	if err := os.Chmod(filepath.Join(dir, socketName), 0660); err != nil {
		t.Fatal(err)
	}
	l, err = listen(dir)
	if err != nil {
		t.Fatal("stale socket not recovered", err)
	}
	l.Close()
}

func TestSocketRejectsUnsafePathsAndPreservesReplacements(t *testing.T) {
	for _, fault := range []string{"symlink-dir", "writable-dir", "file", "symlink-socket", "symlink-lock"} {
		t.Run(fault, func(t *testing.T) {
			dir := testRuntime(t)
			switch fault {
			case "symlink-dir":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "writable-dir":
				os.Chmod(dir, 0777)
			case "file":
				os.WriteFile(filepath.Join(dir, socketName), []byte("preserve"), 0600)
			case "symlink-socket":
				os.Symlink("missing", filepath.Join(dir, socketName))
			case "symlink-lock":
				os.Symlink("missing", filepath.Join(dir, lockName))
			}
			if l, err := listen(dir); err == nil {
				l.Close()
				t.Fatal("unsafe path accepted")
			}
		})
	}
	dir := testRuntime(t)
	l, err := listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, socketName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if b, err := os.ReadFile(path); err != nil || string(b) != "replacement" {
		t.Fatal("shutdown removed replacement")
	}
}

func testRuntime(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	return dir
}
