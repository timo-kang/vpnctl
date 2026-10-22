// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

func TestNodeExpiryCheckpointFailureRetainsCommitBoundary(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(fmt.Sprint(afterRename), func(t *testing.T) {
			s, f, dir := statusCheckpointFixture(t)
			expiry := f.state.ExpiresAt
			before := expiry.Add(-time.Millisecond)
			now := before
			s.now = func() time.Time { return now }
			fresh := s.fresh
			writes, write := 0, s.writeState
			s.writeState = func(b []byte) error {
				writes++
				if writes == 1 {
					err := write(b)
					now = expiry
					return err
				}
				if !afterRename {
					return syscall.ENOSPC
				}
				sync := s.syncDir
				s.syncDir = func() error { return syscall.EIO }
				defer func() { s.syncDir = sync }()
				return write(b)
			}
			wantErr := error(syscall.ENOSPC)
			wantObserved := before
			if afterRename {
				wantErr, wantObserved = syscall.EIO, expiry
			}
			if r, err := s.Status(); !errors.Is(err, wantErr) || r.UsableCache || r.Validity != "uncertain" {
				t.Fatal("expiry checkpoint failure was not blocked/reported", r.Validity, err)
			}
			now = before
			if r, err := s.Status(); !errors.Is(err, ErrUncertain) || r.UsableCache {
				t.Fatal("failed checkpoint uncertainty was lost", r.Validity, err)
			}
			if writes != 2 || s.fresh != fresh {
				t.Fatal("unexpected retry or new approval", writes)
			}
			s.Close()
			reopened, err := Open(dir, Options{NodeID: "robot"})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			// A failed pre-rename write never claims to have persisted expiry;
			// a post-rename sync error must retain the new watermark on reopen.
			if !reopened.state.ObservedAt.Equal(wantObserved) {
				t.Fatal("incorrect recovery at rename boundary")
			}
		})
	}
}

func TestRelayExpiryCheckpointFailureRetainsCommitBoundary(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(fmt.Sprint(afterRename), func(t *testing.T) {
			v := deploymentFixture(t)
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			approveDeployment(t, s, v)
			before := v.ExpiresAt.Add(-time.Millisecond)
			now := before
			s.now = func() time.Time { return now }
			writes, write := 0, s.writeState
			s.writeState = func(b []byte) error {
				writes++
				if writes == 1 {
					err := write(b)
					now = v.ExpiresAt
					return err
				}
				if !afterRename {
					return syscall.ENOSPC
				}
				sync := s.syncDir
				s.syncDir = func() error { return syscall.EIO }
				defer func() { s.syncDir = sync }()
				return write(b)
			}
			wantErr := error(syscall.ENOSPC)
			wantObserved := before
			if afterRename {
				wantErr, wantObserved = syscall.EIO, v.ExpiresAt
			}
			if r, err := s.Status(); !errors.Is(err, wantErr) || r.ApprovalValid || r.Validity != "uncertain" {
				t.Fatal("expiry checkpoint failure was not blocked/reported", r.Validity, err)
			}
			now = before
			if r, err := s.Status(); !errors.Is(err, ErrUncertain) || r.ApprovalValid {
				t.Fatal("failed checkpoint uncertainty was lost", r.Validity, err)
			}
			if writes != 2 {
				t.Fatal("unexpected retry", writes)
			}
			s.Close()
			reopened, err := OpenDeployment(dir, DeploymentOptions{PrincipalID: "robot", RelayID: "r1"})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if !reopened.state.ObservedAt.Equal(wantObserved) {
				t.Fatal("incorrect recovery at rename boundary")
			}
		})
	}
}
