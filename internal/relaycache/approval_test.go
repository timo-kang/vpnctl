// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

func TestNodeApprovalWitnessRestartReplayAndClock(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "cache")
	s := openCache(t, dir)
	f := newController(t)
	at := f.now
	boot := uint64(time.Hour)
	domain := "test-boot:ns"
	clock := func() approvalStamp { return approvalStamp{at, boot, domain} }
	s.now = func() time.Time { return at }
	s.stamp = clock
	ready(t, s, f)
	w, fresh, freshBoot, err := s.LeaseApproval()
	if err != nil || fresh.IsZero() || freshBoot != boot || w.UntilBootNS != boot+uint64(time.Hour) {
		t.Fatal(w, fresh, err)
	}
	s = reopenApprovalCache(t, s, dir, clock)
	w2, fresh, freshBoot, err := s.LeaseApproval()
	if err != nil || w != w2 || !fresh.IsZero() || freshBoot != 0 {
		t.Fatal("restart manufactured fresh evidence", w2, fresh, err)
	}
	// Wall rollback while BOOTTIME advances: same response retains its first
	// immutable deadline, while a real request may supply new short rearm proof.
	boot += uint64(10 * time.Second)
	at = at.Add(-time.Second)
	ready(t, s, f)
	w2, fresh, freshBoot, err = s.LeaseApproval()
	if err != nil || w2 != w || freshBoot != boot || !fresh.Equal(at) {
		t.Fatal("replay changed lifetime", w2, err)
	}
	// A new policy/binding generation with the same expiry is not a renewal
	// of the authority's lifetime either.
	next, err := relaycatalog.Apply(f.state, relaycatalog.Update{ControllerID: f.state.ControllerID, ExpectedGeneration: f.state.Generation, TTLSeconds: 3600, Spec: f.state.Spec}, env(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.state = next
	ready(t, s, f)
	w, _, _, err = s.LeaseApproval()
	if err != nil || w.UntilBootNS != w2.UntilBootNS {
		t.Fatal("generation change extended unchanged expiry", w, err)
	}
	// An outage may continue an existing lease but supplies no rearm evidence.
	f.getError = io.EOF
	if _, err := s.Refresh(context.Background(), f); err == nil {
		t.Fatal("missing transport failure")
	}
	w2, fresh, freshBoot, err = s.LeaseApproval()
	if err != nil || w2 != w || !fresh.IsZero() || freshBoot != 0 {
		t.Fatal("offline evidence", w2, err)
	}
	// A suspended interval cannot be hidden by the unchanged wall clock.
	boot = w.UntilBootNS
	if _, _, _, err = s.LeaseApproval(); err == nil {
		t.Fatal("BOOTTIME expiration ignored")
	}
	f.getError = nil
	ready(t, s, f)
	if _, _, _, err = s.LeaseApproval(); err == nil {
		t.Fatal("same generation resurrected expired authority")
	}
	// Different domains cannot use the witness until a new authenticated RPC.
	boot = uint64(time.Hour)
	domain = "new-boot:ns"
	if _, _, _, err = s.LeaseApproval(); err == nil {
		t.Fatal("cross-domain evidence accepted")
	}
	ready(t, s, f)
	if w3, _, _, err := s.LeaseApproval(); err != nil || w3.Domain != domain {
		t.Fatal(w3, err)
	}
}
func reopenApprovalCache(t *testing.T, s *Store, dir string, clock func() approvalStamp) *Store {
	t.Helper()
	s.Close()
	s = openCache(t, dir)
	s.stamp = clock
	s.now = func() time.Time { return clock().at }
	return s
}

func TestNodeApprovalWitnessStartsBeforeRequestAndDenial(t *testing.T) {
	s := openCache(t, filepath.Join(privateTempDir(t), "cache"))
	f := newController(t)
	ready(t, s, f)
	at := f.now
	boot := uint64(time.Hour)
	s.now = func() time.Time { return at }
	s.stamp = func() approvalStamp { return approvalStamp{at, boot, "test"} }
	f.get = func(context.Context) (relaycatalog.View, error) {
		at = at.Add(6 * time.Second)
		boot += uint64(6 * time.Second)
		return f.state.NodeView("robot"), nil
	}
	ready(t, s, f)
	w, fresh, freshBoot, err := s.LeaseApproval()
	if err != nil || at.Sub(fresh) != 6*time.Second || boot-freshBoot != uint64(6*time.Second) || w.RequestBootNS != freshBoot {
		t.Fatal("response completion used as request start", w, fresh, err)
	}
	f.get = nil
	f.getError = &api.HTTPError{StatusCode: 403}
	if _, err := s.Refresh(context.Background(), f); err == nil {
		t.Fatal("denial accepted")
	}
	if _, _, _, err := s.LeaseApproval(); err == nil {
		t.Fatal("denial retained usable witness")
	}
	f.getError = io.EOF
	s.Refresh(context.Background(), f)
	if _, _, _, err := s.LeaseApproval(); err == nil {
		t.Fatal("outage undid denial")
	}
}

func TestNodeApprovalOldCacheCannotInventWitness(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "cache")
	s := openCache(t, dir)
	f := newController(t)
	ready(t, s, f)
	n := cloneState(s.state)
	n.Approval = nil
	if err := s.save(n); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = openCache(t, dir)
	if _, _, _, err := s.LeaseApproval(); err == nil {
		t.Fatal("old cache became fresh")
	}
	ready(t, s, f)
	if _, _, _, err := s.LeaseApproval(); err != nil {
		t.Fatal(err)
	}
}

func TestNodeApprovalLateSuccessfulResponseCannotKeepOldAuthority(t *testing.T) {
	s := openCache(t, filepath.Join(privateTempDir(t), "cache"))
	f := newController(t)
	ready(t, s, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.get = func(context.Context) (relaycatalog.View, error) { cancel(); return f.state.NodeView("robot"), nil }
	r, err := s.Refresh(ctx, f)
	if err == nil || r.UsableCache || r.BlockedReason != "response_after_deadline" {
		t.Fatal(r, err)
	}
	if _, _, _, err := s.LeaseApproval(); err == nil {
		t.Fatal("late response supplied authority")
	}
}
