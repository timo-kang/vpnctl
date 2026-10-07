// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func statusCheckpointFixture(t testing.TB) (*Store, *fakeController, string) {
	t.Helper()
	spec := testSpec()
	spec.Paths = nil
	for relay := 0; relay < 2; relay++ {
		for underlay := 0; underlay < 4; underlay++ {
			spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p%d%d", relay, underlay), NodeID: "robot", RelayID: fmt.Sprint("r", relay+1), EndpointID: "e", UnderlayID: fmt.Sprint("lan", underlay), TargetIDs: []string{"app"}})
		}
	}
	now := time.Now().UTC()
	state, err := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: spec}, env(), now)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeController{state: state, now: now}
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "cache")
	s, err := Open(dir, Options{NodeID: "robot", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if r, err := s.Refresh(context.Background(), f); err != nil || !r.UsableCache || len(r.Paths) != 8 {
		t.Fatal("fixture population", err)
	}
	return s, f, dir
}

// Real durable writes remain enabled. This measures the high-frequency status
// path independently of kernel scheduling; it is not an application SLO.
func BenchmarkNodeStatusEightPaths(b *testing.B) {
	s, _, _ := statusCheckpointFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r, err := s.Status(); err != nil || !r.UsableCache {
			b.Fatal(err)
		}
	}
}

func TestStatusCatalogCopiesAllNestedSlices(t *testing.T) {
	s, _, _ := statusCheckpointFixture(t)
	first, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	before := cloneState(s.state) // Independent serialization oracle.
	v := first.Catalog
	v.Spec.ReservedIPs = append(v.Spec.ReservedIPs, "203.0.113.255")
	v.Spec.Relays[0].Endpoints[0].Address = "203.0.113.254:9"
	v.Spec.Relays[0].ID = "edited"
	v.Spec.Targets[0].Prefixes[0] = "203.0.113.0/24"
	v.Spec.Targets[0].ID = "edited"
	v.Spec.Paths[0].TargetIDs[0] = "edited"
	v.Spec.Paths[0].Disabled = true
	v.Bindings[0].PublicKey = testPublic("report mutation")
	second, err := s.Status()
	if err != nil || !second.UsableCache || !reflect.DeepEqual(second.Catalog, before.Catalog) {
		t.Fatal("public mutation changed subsequent authority", err)
	}
	if !same(s.state.Catalog, before.Catalog) {
		t.Fatal("public mutation reached stored authority")
	}
}

func TestStatusCheckpointOnlyAdvancesClockAndDoesNotExposeState(t *testing.T) {
	s, _, dir := statusCheckpointFixture(t)
	before := cloneState(s.state)
	beforeFresh := s.fresh
	now := before.ObservedAt.Add(time.Second)
	s.now = func() time.Time { return now }
	writes, write := 0, s.writeState
	s.writeState = func(b []byte) error { writes++; return write(b) }
	for i := 0; i < 3; i++ {
		report, err := s.Status()
		if err != nil || !report.UsableCache {
			t.Fatal(err)
		}
		// Public results must not alias the state reused by the next checkpoint.
		report.Catalog.Spec.Paths[0].Disabled = true
		report.Catalog.Spec.Targets[0].Prefixes[0] = "203.0.113.0/24"
		report.Catalog.Bindings[0].PublicKey = testPublic("untrusted report edit")
		now = now.Add(time.Millisecond)
	}
	if writes != 3 || s.fresh != beforeFresh {
		t.Fatal("checkpoint skipped durability or manufactured fresh approval", writes)
	}
	after := cloneState(s.state)
	if !after.ObservedAt.After(before.ObservedAt) {
		t.Fatal("clock did not advance")
	}
	after.ObservedAt = before.ObservedAt
	if !same(before, after) {
		t.Fatal("status changed authority, keys or bindings")
	}
	committed := s.state.ObservedAt
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.state.ObservedAt.Equal(committed) {
		t.Fatal("clock checkpoint not durable")
	}
	if !reopened.fresh.at.IsZero() {
		t.Fatal("reopen manufactured fresh approval")
	}
}

func TestStatusCheckpointExpiryRemainsExpiredAfterReopenAndRollback(t *testing.T) {
	s, f, dir := statusCheckpointFixture(t)
	expired := f.state.ExpiresAt.Add(time.Second)
	s.now = func() time.Time { return expired }
	if r, err := s.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("expiry not observed", r.Validity, err)
	}
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, backwards := range []time.Duration{2 * time.Second, time.Hour} {
		reopened.now = func() time.Time { return expired.Add(-backwards) }
		r, err := reopened.Status()
		if err != nil || r.UsableCache || r.Validity != "expired" && r.Validity != "clock_skew" {
			t.Fatal("rollback resurrected authority", r.Validity, err)
		}
	}
}

func TestStatusCheckpointWriteFailureRemainsUncertain(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(fmt.Sprint(afterRename), func(t *testing.T) {
			s, _, dir := statusCheckpointFixture(t)
			committed := s.state.ObservedAt
			next := committed.Add(time.Second)
			s.now = func() time.Time { return next }
			write := s.writeState
			s.writeState = func(b []byte) error {
				if !afterRename {
					return syscall.ENOSPC
				}
				sync := s.syncDir
				s.syncDir = func() error { return syscall.EIO }
				defer func() { s.syncDir = sync }()
				return write(b)
			}
			if r, err := s.Status(); err == nil || r.UsableCache || !s.uncertain {
				t.Fatal("failed clock write authorized use", err)
			}
			if r, err := s.Status(); !errors.Is(err, ErrUncertain) || r.UsableCache {
				t.Fatal("uncertainty lost", err)
			}
			s.Close()
			reopened, err := Open(dir, Options{NodeID: "robot"})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			want := committed
			if afterRename {
				want = next
			}
			if !reopened.state.ObservedAt.Equal(want) {
				t.Fatal("incorrect pre/post-rename recovery")
			}
		})
	}
}

func TestStatusCheckpointRejectsUnsafeOrMissingStateFile(t *testing.T) {
	for _, fault := range []string{"missing", "public", "symlink", "hardlink"} {
		t.Run(fault, func(t *testing.T) {
			s, _, dir := statusCheckpointFixture(t)
			path := filepath.Join(dir, stateFile)
			other := filepath.Join(dir, "retained-state")
			var err error
			switch fault {
			case "missing":
				err = os.Remove(path)
			case "public":
				err = os.Chmod(path, 0644)
			case "hardlink":
				err = os.Link(path, other)
			case "symlink":
				err = os.Rename(path, other)
				if err == nil {
					err = os.Symlink(other, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if r, err := s.Status(); err == nil || r.UsableCache || !s.uncertain {
				t.Fatal("unsafe checkpoint accepted", fault, err)
			}
		})
	}
}
