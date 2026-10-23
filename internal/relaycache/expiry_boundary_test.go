// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestNodeExpiryDuringStatusWriteSurvivesRollback(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		name := "same_process"
		if reopen {
			name = "reopen"
		}
		t.Run(name, func(t *testing.T) {
			s, f, dir := statusCheckpointFixture(t)
			expiry := f.state.ExpiresAt
			now := expiry.Add(-time.Millisecond)
			s.now = func() time.Time { return now }
			write := s.writeState
			s.writeState = func(b []byte) error {
				err := write(b)
				now = expiry
				return err
			}
			if r, err := s.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
				t.Fatal("expiry during write was not reported", r.Validity, err)
			}
			s.writeState = write
			if reopen {
				s.Close()
				var err error
				s, err = Open(dir, Options{NodeID: "robot"})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
			}
			now = expiry.Add(-time.Millisecond)
			s.now = func() time.Time { return now }
			if r, err := s.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
				t.Fatal("rollback resurrected expiry observed after write", r.Validity, err)
			}
		})
	}
}

func TestNodeApprovalReadersPreserveObservedExpiry(t *testing.T) {
	for _, reader := range []string{"path_key", "lease"} {
		t.Run(reader, func(t *testing.T) {
			s, f, dir := statusCheckpointFixture(t)
			now := f.state.ExpiresAt
			s.now = func() time.Time { return now }
			var err error
			if reader == "lease" {
				_, _, _, err = s.LeaseApproval()
			} else {
				err = s.WithPathKey(s.state.ControllerID, s.state.Generation, s.state.Keys[0].PathID, s.state.Keys[0].PublicKey, func(string) error {
					t.Fatal("expired approval exposed private key")
					return nil
				})
			}
			if err == nil {
				t.Fatal("expired approval accepted")
			}
			s.Close()
			reopened, err := Open(dir, Options{NodeID: "robot"})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			reopened.now = func() time.Time { return now.Add(-time.Millisecond) }
			if r, err := reopened.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
				t.Fatal("approval reader did not preserve observed expiry", r.Validity, err)
			}
		})
	}
}

func TestNodeExpiryDuringRefreshWriteSurvivesRollback(t *testing.T) {
	s, f, dir := statusCheckpointFixture(t)
	now := f.state.ExpiresAt.Add(-time.Millisecond)
	s.now = func() time.Time { return now }
	write := s.writeState
	s.writeState = func(b []byte) error {
		var state diskState
		if err := json.Unmarshal(b, &state); err != nil {
			t.Fatal(err)
		}
		err := write(b)
		if state.Refresh.Result == "success" {
			now = f.state.ExpiresAt
		}
		return err
	}
	if r, err := s.Refresh(context.Background(), f); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("expiry during refresh not reported", r.Validity, err)
	}
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return f.state.ExpiresAt.Add(-time.Millisecond) }
	if r, err := reopened.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("refresh did not preserve observed expiry", r.Validity, err)
	}
}

func TestRelayExpiryDuringRefreshWriteSurvivesRollback(t *testing.T) {
	v := deploymentFixture(t)
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	approveDeployment(t, s, v)
	now := v.ExpiresAt.Add(-time.Millisecond)
	s.now = func() time.Time { return now }
	write := s.writeState
	s.writeState = func(b []byte) error {
		var state deploymentState
		if err := json.Unmarshal(b, &state); err != nil {
			t.Fatal(err)
		}
		err := write(b)
		if state.Refresh.Result == "success" {
			now = v.ExpiresAt
		}
		return err
	}
	if r, err := s.Refresh(context.Background(), deploymentResponse(v, nil)); err != nil || r.ApprovalValid || r.Validity != "expired" {
		t.Fatal("expiry during refresh not reported", r.Validity, err)
	}
	s.Close()
	reopened, err := OpenDeployment(dir, DeploymentOptions{PrincipalID: "robot", RelayID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return v.ExpiresAt.Add(-time.Millisecond) }
	if r, err := reopened.Status(); err != nil || r.ApprovalValid || r.Validity != "expired" {
		t.Fatal("refresh did not preserve observed expiry", r.Validity, err)
	}
}

func TestRelayExpiryDuringStatusWriteSurvivesRollback(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		name := "same_process"
		if reopen {
			name = "reopen"
		}
		t.Run(name, func(t *testing.T) {
			v := deploymentFixture(t)
			dir := privateTempDir(t)
			s := openDeployment(t, dir)
			approveDeployment(t, s, v)
			now := v.ExpiresAt.Add(-time.Millisecond)
			s.now = func() time.Time { return now }
			write := s.writeState
			s.writeState = func(b []byte) error {
				err := write(b)
				now = v.ExpiresAt
				return err
			}
			if r, err := s.Status(); err != nil || r.ApprovalValid || r.Validity != "expired" {
				t.Fatal("expiry during write was not reported", r.Validity, err)
			}
			s.writeState = write
			if reopen {
				s.Close()
				var err error
				s, err = OpenDeployment(dir, DeploymentOptions{PrincipalID: "robot", RelayID: "r1"})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
			}
			now = v.ExpiresAt.Add(-time.Millisecond)
			s.now = func() time.Time { return now }
			if r, err := s.Status(); err != nil || r.ApprovalValid || r.Validity != "expired" {
				t.Fatal("rollback resurrected expiry observed after write", r.Validity, err)
			}
		})
	}
}
