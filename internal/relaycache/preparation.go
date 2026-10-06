// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

func preparationFile(path string) (string, error) {
	if path == "" || len(path) > 64 {
		return "", ErrCorrupt
	}
	h := sha256.Sum256([]byte(path))
	return "prepare-" + hex.EncodeToString(h[:]), nil
}

// PreparationConsent is a local opt-in, never controller authority. Missing
// consent disables rebuilding even if an older apply journal still has intent.
func (s *Store) PreparationConsent(path, revision string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, osClosed()
	}
	if s.uncertain {
		return false, ErrUncertain
	}
	name, err := preparationFile(path)
	if err != nil {
		return false, err
	}
	b, err := s.readFile(name)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(b) != 32 {
		return false, ErrCorrupt
	}
	if _, err = hex.DecodeString(string(b)); err != nil {
		return false, ErrCorrupt
	}
	return string(b) == revision, nil
}

// AllowPreparation follows the durable journal write. An interrupted opt-in
// cannot create resources from a consent file alone.
func (s *Store) AllowPreparation(path, revision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return osClosed()
	}
	if s.uncertain {
		return ErrUncertain
	}
	name, err := preparationFile(path)
	if err != nil {
		return err
	}
	if len(revision) != 32 {
		return ErrCorrupt
	}
	if _, err = hex.DecodeString(revision); err != nil {
		return ErrCorrupt
	}
	if err = s.writeFile(name, []byte(revision)); err != nil {
		s.uncertain = true
		return storageError(err)
	}
	return nil
}

// RevokePreparation unlinks and syncs consent BEFORE rewriting the journal or
// removing kernel objects. It allocates no replacement file, so a later ENOSPC
// journal failure cannot resurrect an accepted opt-out after process restart.
// A failed unlink/directory sync is reported as an uncommitted release.
func (s *Store) RevokePreparation(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return osClosed()
	}
	if s.uncertain {
		return ErrUncertain
	}
	name, err := preparationFile(path)
	if err != nil {
		return err
	}
	f, err := s.openFile(name, os.O_RDONLY)
	if err == nil {
		if err = f.Close(); err == nil {
			err = s.root.Remove(name)
		}
	}
	if os.IsNotExist(err) {
		err = nil
	}
	if err == nil {
		err = s.syncDir()
	}
	if err != nil {
		s.uncertain = true
		return storageError(err)
	}
	return nil
}
