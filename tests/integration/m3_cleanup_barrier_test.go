//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
)

// A completed supervisor cycle is the cleanup barrier. An empty CLI list while
// links are changing cannot prove cleanup, and stopping then cancels removal.
func m3InterruptedCleanupComplete(log []byte, after time.Time) error {
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	var report m3SupervisorReport
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &report); err != nil {
		return fmt.Errorf("cleanup cycle report incomplete")
	}
	if !report.ObservedAt.After(after) || report.ApprovalValid || report.ApprovalBlockedReason != "refresh_interrupted" {
		return fmt.Errorf("no current interrupted-approval cycle")
	}
	kernel := report.Kernel
	if kernel == nil || kernel.SchemaVersion != 1 || kernel.State != "blocked" || kernel.Reason != "approval_unavailable" || kernel.KernelReady || len(kernel.Endpoints) != 0 {
		return fmt.Errorf("cleanup cycle has not removed all endpoints")
	}
	return nil
}

func TestM3InterruptedCleanupBarrier(t *testing.T) {
	after := time.Now()
	complete := m3SupervisorReport{
		ObservedAt: after.Add(time.Second), ApprovalBlockedReason: "refresh_interrupted",
		Kernel: &relayapply.DeploymentResult{SchemaVersion: 1, State: "blocked", Reason: "approval_unavailable"},
	}
	encode := func(r m3SupervisorReport) []byte {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return append(b, '\n')
	}
	good := encode(complete)
	if err := m3InterruptedCleanupComplete(good, after); err != nil {
		t.Fatal("completed cleanup rejected", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*m3SupervisorReport)
	}{
		{"retained endpoints", func(r *m3SupervisorReport) {
			r.Kernel.Endpoints = []relayapply.DeploymentEndpointResult{{EndpointID: "ep0", Phase: "applied"}, {EndpointID: "ep1", Phase: "releasing"}}
		}},
		{"failed cleanup", func(r *m3SupervisorReport) { r.Kernel.Reason = "lease_renewal_failed" }},
		{"missing kernel report", func(r *m3SupervisorReport) { r.Kernel = nil }},
		{"invalid schema", func(r *m3SupervisorReport) { r.Kernel.SchemaVersion = 0 }},
		{"wrong kernel state", func(r *m3SupervisorReport) { r.Kernel.State = "applied" }},
		{"ready kernel", func(r *m3SupervisorReport) { r.Kernel.KernelReady = true }},
		{"stale cycle", func(r *m3SupervisorReport) { r.ObservedAt = after }},
		{"valid approval", func(r *m3SupervisorReport) { r.ApprovalValid = true }},
		{"different rejection", func(r *m3SupervisorReport) { r.ApprovalBlockedReason = "expired" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := complete
			kernel := *complete.Kernel
			r.Kernel = &kernel
			tc.edit(&r)
			// A prior completed report must not hide the latest incomplete one.
			log := append(append([]byte(nil), good...), encode(r)...)
			if m3InterruptedCleanupComplete(log, after) == nil {
				t.Fatal("incomplete cleanup admitted")
			}
		})
	}
	for _, log := range [][]byte{nil, []byte("{}\n"), append(append([]byte(nil), good...), []byte(`{"observed_at":`)...)} {
		if m3InterruptedCleanupComplete(log, after) == nil {
			t.Fatal("missing or partial report admitted")
		}
	}
}
