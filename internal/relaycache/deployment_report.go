// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"errors"
	"time"

	"vpnctl/internal/relaycatalog"
)

// ApprovalValid is metadata validity only. It proves neither possession of the
// relay private key, applied peers, forwarding policy nor end-to-end health.
type DeploymentReport struct {
	SchemaVersion      int                          `json:"schema_version"`
	PrincipalID        string                       `json:"principal_id"`
	RelayID            string                       `json:"relay_id"`
	ControllerID       string                       `json:"controller_id,omitempty"`
	ObservedGeneration uint64                       `json:"observed_generation"`
	Validity           string                       `json:"validity"`
	ApprovalValid      bool                         `json:"approval_valid"`
	BlockedReason      string                       `json:"blocked_reason,omitempty"`
	Refresh            refreshState                 `json:"refresh"`
	Deployment         *relaycatalog.DeploymentView `json:"deployment,omitempty"`
}

func MissingDeploymentReport(principal, relay string) DeploymentReport {
	return DeploymentReport{SchemaVersion: 1, PrincipalID: principal, RelayID: relay, Validity: "missing", Refresh: refreshState{Result: "never"}}
}
func (s *DeploymentStore) currentTime() time.Time {
	now := s.now()
	if now.Before(s.state.ObservedAt) {
		return s.state.ObservedAt
	}
	return now
}
func (s *DeploymentStore) clockRegressed() bool {
	return s.now().Add(30 * time.Second).Before(s.state.ObservedAt)
}
func (s *DeploymentStore) Status() (DeploymentReport, error) {
	if !s.mu.TryLock() {
		return s.busyReport(), ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return DeploymentReport{}, osClosed()
	}
	if s.uncertain {
		return s.report(ErrUncertain)
	}
	if e := s.save(s.state); e != nil {
		return s.report(e)
	}
	return s.report(nil)
}
func (s *DeploymentStore) busyReport() DeploymentReport {
	r := MissingDeploymentReport(s.principal, s.relay)
	r.Validity = "busy"
	return r
}
func (s *DeploymentStore) report(cause error) (DeploymentReport, error) {
	// A save can finish after expiry even though its watermark predates it.
	// Persist the clock sample used for this decision before publishing expiry.
	now := s.now()
	if d := s.state.Deployment; !s.uncertain && d != nil && !now.Before(d.ExpiresAt) && s.state.ObservedAt.Before(d.ExpiresAt) {
		next := s.state
		next.ObservedAt = now.UTC()
		if err := s.save(next); err != nil {
			s.uncertain = true
			cause = errors.Join(cause, err)
		}
	}
	r := MissingDeploymentReport(s.principal, s.relay)
	r.ControllerID, r.ObservedGeneration = s.state.ControllerID, s.state.Generation
	r.Refresh, r.BlockedReason = s.state.Refresh, s.state.BlockedReason
	if d := s.state.Deployment; d != nil {
		copy := copyDeployment(*d)
		r.Deployment = &copy
		r.Validity = "valid"
		if now.Add(30*time.Second).Before(s.state.ObservedAt) || d.IssuedAt.After(now.Add(30*time.Second)) {
			r.Validity = "clock_skew"
		} else if !now.Before(d.ExpiresAt) || !s.state.ObservedAt.Before(d.ExpiresAt) {
			r.Validity = "expired"
		}
	}
	if s.state.Refresh.Result == "in_progress" && r.BlockedReason == "" {
		r.BlockedReason = "refresh_interrupted"
	}
	if s.uncertain {
		r.Validity = "uncertain"
	}
	r.ApprovalValid = r.Validity == "valid" && r.BlockedReason == ""
	return r, cause
}
