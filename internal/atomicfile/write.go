// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package atomicfile replaces files durably and distinguishes an unsuccessful
// replacement from one that is visible but whose crash durability is uncertain.
package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type CommitError struct{ Err error }

func (e *CommitError) Error() string {
	return "file replaced but directory sync failed: " + e.Err.Error()
}
func (e *CommitError) Unwrap() error { return e.Err }
func Replaced(err error) bool        { var e *CommitError; return errors.As(err, &e) }

func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// MkdirAll persists directory entries through the existing ancestor chain too.
// A previous failed call may have created a directory without syncing its parent;
// merely seeing that directory on retry is not proof of crash durability.
func MkdirAll(path string, mode os.FileMode) error {
	return mkdirAll(path, mode, SyncDir)
}
func mkdirAll(path string, mode os.FileMode, syncDir func(string) error) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absolute, mode); err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		if err := syncDir(current); err != nil {
			return err
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

type tempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}
type operations struct {
	create  func(string, string) (tempFile, error)
	rename  func(string, string) error
	syncDir func(string) error
}

func Write(path string, data []byte, mode os.FileMode) error {
	return write(path, data, mode, operations{
		create: func(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) },
		rename: os.Rename, syncDir: SyncDir,
	})
}
func write(path string, data []byte, mode os.FileMode, ops operations) error {
	dir := filepath.Dir(path)
	f, err := ops.create(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if n, writeErr := f.Write(data); writeErr != nil || n != len(data) {
		f.Close()
		if writeErr != nil {
			return writeErr
		}
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = ops.rename(f.Name(), path); err != nil {
		return err
	}
	if err = ops.syncDir(dir); err != nil {
		return &CommitError{Err: err}
	}
	return nil
}
