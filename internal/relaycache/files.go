// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"vpnctl/internal/atomicfile"
)

var (
	ErrBusy      = errors.New("relay cache is busy; another refresh or process owns it")
	ErrMissing   = errors.New("relay cache is not initialized")
	ErrUnsafe    = errors.New("relay cache requires private, owned regular files and a trusted directory")
	ErrCorrupt   = errors.New("relay cache is inconsistent; restore the complete node cache or approve new path identities")
	ErrUncertain = errors.New("relay cache durability is uncertain; reopen or refresh to verify storage")
)

const stateFile = "state.json"
const markerFile = "initialized"
const maxStateBytes = 2 << 20

// Root-relative operations retain the opened directory across renames. Reject
// symlinks and writable ancestors before entering them. Root and the current UID
// are trusted; other UIDs may create names only in root-owned sticky ancestors.
func openDirectory(path string, create bool) (*os.Root, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	root, e := os.OpenRoot("/")
	if e != nil {
		return nil, e
	}
	failed := true
	defer func() {
		if failed {
			root.Close()
		}
	}()
	components := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	for i, name := range components {
		if name == "" {
			return nil, ErrUnsafe
		}
		parent, e := root.Stat(".")
		if e != nil {
			return nil, e
		}
		st, ok := parent.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || parent.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && parent.Mode()&os.ModeSticky != 0) {
			return nil, fmt.Errorf("%w: untrusted ancestor %s (mode %s)", ErrUnsafe, root.Name(), parent.Mode())
		}
		info, e := root.Lstat(name)
		if os.IsNotExist(e) && create {
			if e = root.Mkdir(name, 0700); e != nil && !os.IsExist(e) {
				return nil, e
			}
			info, e = root.Lstat(name)
		}
		if os.IsNotExist(e) {
			return nil, ErrMissing
		}
		if e != nil {
			return nil, e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafe
		}
		if e = syncRoot(root); e != nil {
			return nil, e
		}
		child, e := root.OpenRoot(name)
		if e != nil {
			return nil, e
		}
		actual, e := child.Stat(".")
		if e != nil || !os.SameFile(info, actual) {
			child.Close()
			return nil, fmt.Errorf("%w: directory changed while opening %s", ErrUnsafe, name)
		}
		root.Close()
		root = child
		if i == len(components)-1 && !privateDirectory(actual) {
			return nil, fmt.Errorf("%w: cache directory mode %s", ErrUnsafe, actual.Mode())
		}
	}
	if e = syncRoot(root); e != nil {
		return nil, e
	}
	failed = false
	return root, nil
}
func privateDirectory(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.IsDir() && info.Mode().Perm() == 0700
}
func privateFile(f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return ErrUnsafe
	}
	return nil
}
func syncRoot(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *Store) openFile(name string, flags int) (*os.File, error) {
	info, e := s.root.Stat(".")
	if e != nil {
		return nil, e
	}
	if !privateDirectory(info) {
		return nil, ErrUnsafe
	}
	// os.Root resolves in-root symlinks itself on some platforms, even when
	// OpenFile receives O_NOFOLLOW. Inspect the directory entry as well.
	entry, entryErr := s.root.Lstat(name)
	if entryErr != nil && !os.IsNotExist(entryErr) {
		return nil, entryErr
	}
	if entryErr == nil && !entry.Mode().IsRegular() {
		return nil, ErrUnsafe
	}
	f, e := s.root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	if e = privateFile(f); e != nil {
		f.Close()
		return nil, e
	}
	actual, e := f.Stat()
	current, entryErr := s.root.Lstat(name)
	if e != nil || entryErr != nil || !current.Mode().IsRegular() || !os.SameFile(current, actual) || (entry != nil && !os.SameFile(entry, actual)) {
		f.Close()
		return nil, ErrUnsafe
	}
	return f, nil
}
func (s *Store) readFile(name string) ([]byte, error) {
	f, e := s.openFile(name, os.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > maxStateBytes {
		return nil, ErrCorrupt
	}
	return b, nil
}
func (s *Store) writeFile(name string, data []byte) error {
	if len(data) > maxStateBytes {
		return ErrCorrupt
	}
	f, e := s.openFile(name, os.O_RDONLY)
	if e == nil {
		f.Close()
	} else if !os.IsNotExist(e) {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	temp := ".pending-" + hex.EncodeToString(nonce[:])
	f, e = s.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer s.root.Remove(temp)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if n, err := f.Write(data); err != nil || n != len(data) {
		f.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = s.root.Rename(temp, name); e != nil {
		return e
	}
	if e = s.syncDir(); e != nil {
		return &atomicfile.CommitError{Err: e}
	}
	return nil
}
func storageError(e error) error { return fmt.Errorf("relay cache storage: %w", e) }
