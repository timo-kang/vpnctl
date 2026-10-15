// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"os"
	"sync"
)

// ObservationScope pins filesystem identity, not approval or ownership. Its
// separate read-only descriptors hold no flock and cannot retain FIFO admission.
// It is process-local and must be closed after a bounded observation handoff.
type ObservationScope struct {
	mu              sync.Mutex
	origin          *Store
	directory, lock *os.File
}

func (s *Store) PinObservationScope() (*ObservationScope, error) {
	if !s.mu.TryLock() {
		return nil, ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed || s.uncertain {
		return nil, ErrUncertain
	}
	directory, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	// Never dup s.lock: dup would preserve its flock after Store.Close.
	lock, err := s.openFile("cache.lock", os.O_RDONLY)
	if err != nil {
		directory.Close()
		return nil, err
	}
	pin := &ObservationScope{origin: s, directory: directory, lock: lock}
	if !pin.matchesLocked(s) {
		pin.Close()
		return nil, ErrUnsafe
	}
	return pin, nil
}

func (p *ObservationScope) Matches(s *Store) bool {
	if p == nil || s == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// A new Engine over the same live Store is not a handoff: it has neither
	// released FIFO/flock ownership nor reloaded persisted cache state.
	if p.origin == nil || p.origin == s || !p.origin.mu.TryLock() {
		return false
	}
	closed := p.origin.closed
	p.origin.mu.Unlock()
	if !closed {
		return false
	}
	if !s.mu.TryLock() {
		return false
	}
	defer s.mu.Unlock()
	return p.matchesLocked(s)
}

// Caller owns the Store and pin locks (or the pin is not yet published).
func (p *ObservationScope) matchesLocked(s *Store) bool {
	if p.directory == nil || p.lock == nil || s.closed || s.uncertain || s.root == nil || s.lock == nil {
		return false
	}
	directory, err := p.directory.Stat()
	if err != nil {
		return false
	}
	current, err := s.root.Stat(".")
	if err != nil || !privateDirectory(current) || !os.SameFile(directory, current) {
		return false
	}
	pinned, err := p.lock.Stat()
	if err != nil || privateFile(p.lock) != nil || privateFile(s.lock) != nil {
		return false
	}
	held, err := s.lock.Stat()
	if err != nil || !os.SameFile(pinned, held) {
		return false
	}
	named, err := s.root.Lstat("cache.lock")
	return err == nil && named.Mode().IsRegular() && os.SameFile(held, named)
}

func (p *ObservationScope) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if p.directory != nil {
		err = p.directory.Close()
		p.directory = nil
	}
	if p.lock != nil {
		err = errors.Join(err, p.lock.Close())
		p.lock = nil
	}
	return err
}
