// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

type faultFile struct {
	*os.File
	fault  string
	events *[]string
}

func (f faultFile) Chmod(m os.FileMode) error {
	if f.fault == "chmod" {
		return syscall.EIO
	}
	return f.File.Chmod(m)
}
func (f faultFile) Write(b []byte) (int, error) {
	if f.fault == "write" {
		return 0, syscall.ENOSPC
	}
	if f.fault == "short" {
		return 0, nil
	}
	return f.File.Write(b)
}
func (f faultFile) Sync() error {
	*f.events = append(*f.events, "file-sync")
	if f.fault == "file-sync" {
		return syscall.EIO
	}
	return f.File.Sync()
}
func (f faultFile) Close() error {
	err := f.File.Close()
	if f.fault == "close" {
		return syscall.EIO
	}
	return err
}
func TestReplacementFaultBoundaries(t *testing.T) {
	for _, fault := range []string{"", "create", "chmod", "write", "short", "file-sync", "close", "rename", "dir-sync"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state")
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			var events []string
			ops := operations{
				create: func(d, p string) (tempFile, error) {
					if fault == "create" {
						return nil, syscall.EIO
					}
					f, err := os.CreateTemp(d, p)
					return faultFile{f, fault, &events}, err
				},
				rename: func(a, b string) error {
					events = append(events, "rename")
					if fault == "rename" {
						return syscall.EIO
					}
					return os.Rename(a, b)
				},
				syncDir: func(d string) error {
					events = append(events, "dir-sync")
					if fault == "dir-sync" {
						return syscall.EIO
					}
					return SyncDir(d)
				},
			}
			err := write(path, []byte("new"), 0600, ops)
			if (err == nil) != (fault == "") {
				t.Fatalf("fault=%s error=%v", fault, err)
			}
			if Replaced(err) != (fault == "dir-sync") {
				t.Fatalf("commit classification: %v", err)
			}
			if fault == "dir-sync" && !errors.Is(err, syscall.EIO) {
				t.Fatal("cause lost")
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := "old"
			if fault == "" || fault == "dir-sync" {
				want = "new"
			}
			if string(got) != want {
				t.Fatalf("visible=%q want=%q", got, want)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatalf("temporary files leaked: %v", entries)
			}
			if fault == "" && !reflect.DeepEqual(events, []string{"file-sync", "rename", "dir-sync"}) {
				t.Fatal(events)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatal("mode changed")
			}
		})
	}
}
func TestDurableDirectoryCreation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a", "b")
	if err := MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(path, "state"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(filepath.Join(path, "state"), 0700); err == nil {
		t.Fatal("accepted regular file")
	}
}

func TestDirectoryRetrySyncsExistingAncestors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "nested")
	parent := filepath.Dir(path)
	err := mkdirAll(path, 0700, func(p string) error {
		if p == parent {
			return syscall.EIO
		}
		return SyncDir(p)
	})
	if !errors.Is(err, syscall.EIO) {
		t.Fatal(err)
	}
	synced := map[string]bool{}
	if err := mkdirAll(path, 0700, func(p string) error { synced[p] = true; return SyncDir(p) }); err != nil {
		t.Fatal(err)
	}
	if !synced[parent] || !synced[filepath.Dir(parent)] {
		t.Fatal("retry assumed existing ancestors were durable")
	}
}
