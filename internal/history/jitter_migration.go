// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"fmt"
)

func (s *Store) JitterEnabled() bool { return s.jitterEnabled.Load() }

// EnableJitter is an offline, one-way format opt-in. The CLI owns the controller
// lock and creates a checked backup first. v6 -> v8 and v7 -> v9 retain the
// reclamation setting; existing v1 rollups remain explicitly unordered.
func (s *Store) EnableJitter(ctx context.Context) error {
	if err := acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	if s.JitterEnabled() {
		return nil
	}
	if !s.Tiered() {
		return fmt.Errorf("enable tiered history before archived jitter")
	}
	if err := Check(ctx, s.path); err != nil {
		return err
	}
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	version := 8
	if s.ReclamationEnabled() {
		version = 9
	}
	if _, err = db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		return err
	}
	s.jitterEnabled.Store(true)
	return nil
}
