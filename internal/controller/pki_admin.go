// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"vpnctl/internal/api"
)

func (s *Server) adminPKI(req api.AdminRequest) (api.AdminResponse, error) {
	var out api.AdminResponse
	if req.Operation == "pki.status" {
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
	} else {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
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
		s.mu.Lock()
		ids := make([]string, 0, len(s.reg.Nodes))
		for _, node := range s.reg.Nodes {
			if !node.EnrollmentPending {
				ids = append(ids, node.ID)
			}
		}
		s.mu.Unlock()
		sort.Strings(ids)
		err = s.authority.Rotate(strings.TrimPrefix(req.Operation, "ca."), ids)
	case "pki.backup":
		out.Backup, err = s.backupLocked()
	default:
		err = fmt.Errorf("unknown PKI operation")
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
