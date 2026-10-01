// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"os"
	"path/filepath"
)

// DeploymentJournal is protected by the same directory and process lock as
// the approval. It contains public resource ownership only, never private keys.
func (s *DeploymentStore) DeploymentJournal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, osClosed()
	}
	if s.uncertain {
		return nil, ErrUncertain
	}
	b, err := s.readFile("peers.json")
	marker, markerErr := s.readFile("peers-initialized")
	if markerErr != nil && !os.IsNotExist(markerErr) || markerErr == nil && string(marker) != "1" {
		return nil, ErrCorrupt
	}
	if os.IsNotExist(err) {
		if !os.IsNotExist(markerErr) {
			return nil, ErrCorrupt
		}
		return nil, nil
	}
	return b, err
}

func (s *DeploymentStore) SaveDeploymentJournal(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return osClosed()
	}
	if s.uncertain {
		return ErrUncertain
	}
	if len(b) == 0 || len(b) > maxStateBytes {
		return ErrCorrupt
	}
	marker, err := s.readFile("peers-initialized")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if string(marker) != "1" {
			return ErrCorrupt
		}
		if _, e := s.readFile("peers.json"); e != nil {
			return ErrCorrupt
		}
	}
	if e := s.writeFile("peers.json", b); e != nil {
		s.uncertain = true
		return storageError(e)
	}
	if os.IsNotExist(err) {
		if e := s.writeFile("peers-initialized", []byte("1")); e != nil {
			s.uncertain = true
			return storageError(e)
		}
	}
	return nil
}

// ReadDeploymentKey reads an external operator-owned key, without importing it
// into the approval cache. The containing directory must be private and owned.
// All error messages deliberately omit the path and file contents.
func ReadDeploymentKey(path string) ([]byte, error) {
	root, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, errors.New("private relay key directory unavailable or unsafe")
	}
	defer root.Close()
	f := files{root: root}
	b, err := f.readFile(filepath.Base(path))
	if err != nil || len(b) > 45 {
		return nil, errors.New("private relay key file unavailable or unsafe")
	}
	return b, nil
}
