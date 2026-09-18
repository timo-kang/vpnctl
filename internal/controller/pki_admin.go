// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"vpnctl/internal/api"
)

func (s *Server) adminPKI(req api.AdminRequest) (api.AdminResponse, error) {
	var out api.AdminResponse
	if strings.HasPrefix(req.Operation, "ca.") && s.authority != nil {
		if err := s.authority.CheckRotation(strings.TrimPrefix(req.Operation, "ca."), s.caNodeIDs()); err != nil {
			s.recordPKIResult(req.Operation, "controller", err)
			return out, err
		}
	}
	// Once an admin mutation is admitted it finishes even after disconnect.
	// Queue before stateMu so waiting for PKI work never drains healthy reads.
	if req.Operation != "pki.status" {
		release, _ := s.pkiAdmission.acquirePriority(context.Background())
		defer release()
	}
	if req.Operation != "pki.status" {
		drainStart := time.Now()
		if req.Operation == "ca.prepare" {
			s.mutationAdmission.RLock()
			defer s.mutationAdmission.RUnlock()
		} else {
			s.mutationAdmission.Lock()
			defer s.mutationAdmission.Unlock()
		}
		observeStage("pki_transition", "mutation_drain", drainStart)
	}
	// Preparing only adds trust; it cannot invalidate an admitted identity.
	// Activation/retirement/rollback/revocation retain the exclusive barrier.
	admissionStart := time.Now()
	if req.Operation == "pki.status" || req.Operation == "ca.prepare" {
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
	} else {
		s.stateMu.Lock()
		observeStage("pki_transition", "admission_wait", admissionStart)
		held := time.Now()
		defer func() { s.stateMu.Unlock(); observeStage("pki_transition", "exclusive_hold", held) }()
	}
	if s.authority == nil {
		return out, fmt.Errorf("PKI disabled")
	}
	var err error
	switch req.Operation {
	case "pki.status":
	case "pki.revoke":
		decoded, decodeErr := hex.DecodeString(req.Fingerprint)
		if decodeErr != nil || len(decoded) != 32 {
			return out, fmt.Errorf("SHA-256 certificate fingerprint required")
		}
		err = s.authority.Revoke(strings.ToLower(req.Fingerprint))
	case "ca.prepare", "ca.activate", "ca.retire", "ca.rollback":
		// Revalidate against the latest committed state. Destructive transitions
		// also recollect nodes after draining; preflight never authorizes a mutation.
		err = s.authority.Rotate(strings.TrimPrefix(req.Operation, "ca."), s.caNodeIDs())
	case "pki.backup":
		out.Backup, err = s.backupLocked()
	default:
		err = fmt.Errorf("unknown PKI operation")
	}
	if req.Operation == "pki.revoke" || strings.HasPrefix(req.Operation, "ca.") {
		target := "controller"
		if req.Operation == "pki.revoke" {
			target = strings.ToLower(req.Fingerprint)
		}
		detail := ""
		if err == nil {
			state := s.authority.Status()
			detail = fmt.Sprintf("generation=%d phase=%s active=%s pending=%s previous=%s", state.Generation, state.Phase, state.Active, state.Pending, state.Previous)
		}
		s.recordPKIResult(req.Operation, target, err, detail)
	}
	if err != nil {
		return out, err
	}
	status := s.authority.Status()
	if strings.HasPrefix(req.Operation, "ca.") {
		slog.Info("CA transition committed", "operation", req.Operation, "generation", status.Generation, "phase", status.Phase, "active", status.Active, "previous", status.Previous, "pending", status.Pending)
	}
	s.mu.Lock()
	for i := range status.Certificates {
		if _, removed := s.reg.RemovedNodes[status.Certificates[i].NodeID]; removed {
			status.Certificates[i].Status = "identity_removed"
		}
	}
	s.mu.Unlock()
	out.PKI = &status
	s.updatePKIMetrics()
	return out, nil
}

func (s *Server) caNodeIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.reg.Nodes))
	for _, node := range s.reg.Nodes {
		if !node.EnrollmentPending {
			ids = append(ids, node.ID)
		}
	}
	sort.Strings(ids)
	return ids
}
