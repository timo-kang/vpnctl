// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"testing"
	"time"
)

func TestNodeExpiryReportPersistsItsClockSample(t *testing.T) {
	s, f, dir := statusCheckpointFixture(t)
	expiry := f.state.ExpiresAt
	now := expiry.Add(-time.Millisecond)
	s.now = func() time.Time {
		sampled := now
		// Roll back immediately after the report samples expiry, before its
		// corrective write. Resampling must not lose the observed expiry.
		if now.Equal(expiry) {
			now = expiry.Add(-time.Millisecond)
		}
		return sampled
	}
	writes, write := 0, s.writeState
	s.writeState = func(b []byte) error {
		writes++
		err := write(b)
		if writes == 1 {
			now = expiry
		}
		return err
	}
	if r, err := s.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("expiry sample was lost", r.Validity, err)
	}
	if writes != 2 {
		t.Fatal("expected one bounded corrective checkpoint", writes)
	}
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return now }
	if r, err := reopened.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("sampled expiry was not durable", r.Validity, err)
	}
}

func TestRelayExpiryReportPersistsItsClockSample(t *testing.T) {
	v := deploymentFixture(t)
	dir := privateTempDir(t)
	s := openDeployment(t, dir)
	approveDeployment(t, s, v)
	now := v.ExpiresAt.Add(-time.Millisecond)
	s.now = func() time.Time {
		sampled := now
		if now.Equal(v.ExpiresAt) {
			now = v.ExpiresAt.Add(-time.Millisecond)
		}
		return sampled
	}
	writes, write := 0, s.writeState
	s.writeState = func(b []byte) error {
		writes++
		err := write(b)
		if writes == 1 {
			now = v.ExpiresAt
		}
		return err
	}
	if r, err := s.Status(); err != nil || r.ApprovalValid || r.Validity != "expired" {
		t.Fatal("expiry sample was lost", r.Validity, err)
	}
	if writes != 2 {
		t.Fatal("expected one bounded corrective checkpoint", writes)
	}
	s.Close()
	reopened, err := OpenDeployment(dir, DeploymentOptions{PrincipalID: "robot", RelayID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return now }
	if r, err := reopened.Status(); err != nil || r.ApprovalValid || r.Validity != "expired" {
		t.Fatal("sampled expiry was not durable", r.Validity, err)
	}
}

func TestNodeLeaseStampExpiryRemainsExpiredAfterRollback(t *testing.T) {
	s, f, dir := statusCheckpointFixture(t)
	expiry := f.state.ExpiresAt
	s.now = func() time.Time { return expiry.Add(-time.Millisecond) }
	stamp := s.stamp
	s.stamp = func() approvalStamp {
		v := stamp()
		v.at = expiry
		return v
	}
	if _, _, _, err := s.LeaseApproval(); err == nil {
		t.Fatal("expired lease stamp accepted")
	}
	s.Close()
	reopened, err := Open(dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return expiry.Add(-time.Millisecond) }
	if r, err := reopened.Status(); err != nil || r.UsableCache || r.Validity != "expired" {
		t.Fatal("lease stamp expiry was not durable", r.Validity, err)
	}
}
