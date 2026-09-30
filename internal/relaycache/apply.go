// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"os"
)

// ApplyJournal uses the same pinned directory, ownership checks and process
// lock as the approval cache. No path supplied by a caller is opened here.
func (s *Store) ApplyJournal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, osClosed()
	}
	if s.uncertain {
		return nil, ErrUncertain
	}
	b, e := s.readFile("apply.json")
	if os.IsNotExist(e) {
		if _, markerErr := s.readFile("apply-initialized"); !os.IsNotExist(markerErr) {
			return nil, ErrCorrupt
		}
		return nil, nil
	}
	if e == nil && len(b) > 128<<10 {
		return nil, ErrCorrupt
	}
	return b, e
}

func (s *Store) SaveApplyJournal(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return osClosed()
	}
	if s.uncertain {
		return ErrUncertain
	}
	if len(b) == 0 || len(b) > 128<<10 {
		return ErrCorrupt
	}
	marker, markerErr := s.readFile("apply-initialized")
	if markerErr != nil && !os.IsNotExist(markerErr) {
		return markerErr
	}
	if markerErr == nil {
		if string(marker) != "1" {
			return ErrCorrupt
		}
		if _, e := s.readFile("apply.json"); e != nil {
			return ErrCorrupt
		}
	}
	if e := s.writeFile("apply.json", b); e != nil {
		s.uncertain = true
		return storageError(e)
	}
	if os.IsNotExist(markerErr) {
		if e := s.writeFile("apply-initialized", []byte("1")); e != nil {
			s.uncertain = true
			return storageError(e)
		}
	}
	return nil
}

// WithPathKey checks current approval under the cache lock. The key must only
// be passed to a protected kernel configuration channel, never an argument,
// journal, error or public report. The callback must not reenter Store methods.
func (s *Store) WithPathKey(controller string, generation uint64, path, public string, use func(string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return osClosed()
	}
	r := s.report()
	if !r.UsableCache || r.Validity != "valid" || r.ControllerID != controller || r.ObservedGeneration != generation {
		return errors.New("path approval unavailable")
	}
	for _, p := range r.Paths {
		if p.PathID == path && p.State == "bound" && p.PublicKey == public {
			k, ok := s.key(path)
			if ok && !k.Retired {
				return use(k.PrivateKey)
			}
		}
	}
	return errors.New("path key is not currently approved")
}
