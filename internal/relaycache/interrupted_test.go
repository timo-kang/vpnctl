// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"io"
	"syscall"
	"testing"

	"vpnctl/internal/api"
)

// Receiving a denial and then losing the local write must not permit an old
// node approval to become usable merely because the next request times out.
func TestNodeInterruptedDenialRemainsBlockedAcrossOutage(t *testing.T) {
	dir := privateTempDir(t)
	s := openCache(t, dir)
	f := newController(t)
	ready(t, s, f)
	write, calls := s.writeState, 0
	s.writeState = func(b []byte) error {
		calls++
		if calls == 2 {
			return syscall.ENOSPC
		}
		return write(b)
	}
	f.getError = &api.HTTPError{StatusCode: 403}
	r, e := s.Refresh(context.Background(), f)
	if e == nil || r.UsableCache || r.Validity != "uncertain" {
		t.Fatal("denial write did not fail", e)
	}
	s.Close()
	s = openCache(t, dir)
	r, e = s.Status()
	if e != nil || r.UsableCache || r.Refresh.Result != "in_progress" {
		t.Fatal("lost interrupted marker", e)
	}
	f.getError = io.EOF
	r, e = s.Refresh(context.Background(), f)
	if e == nil || r.UsableCache || r.BlockedReason == "" {
		t.Fatal("outage resurrected approval after lost denial")
	}
	f.getError = nil
	ready(t, s, f)
}
