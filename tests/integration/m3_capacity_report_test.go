//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// Register first so Fatal/Skip during resource or network preparation still
// produces an identifiable case. Cleanup runs last, after fixture diagnostics
// and teardown failures. Measured fields are added only where work completes.
func newApplicationCapacityReport(t *testing.T, healthy int, rebuild bool, paths int, robotCPU, layout string) (string, map[string]any) {
	t.Helper()
	results, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-authority-")
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"healthy_index": healthy,
		"requested_profile": map[string]any{
			"paths": paths, "robot_cpus": robotCPU, "cpu_layout": layout, "automatic_rebuild": rebuild,
		},
		"phase": "resources", "preparation_completed": false,
		"sampled_contract_version": 2, "sampled_qualification_status": "not_started",
		"publication_continuity": map[string]any{"contract_version": 2, "status": "not_started"},
	}
	t.Cleanup(func() {
		outcome := "passed"
		switch {
		case t.Failed():
			outcome = "failed"
		case t.Skipped():
			outcome = "skipped"
		}
		report["test_outcome"] = outcome
		report["completed"] = outcome == "passed" && report["phase"] == "completed"
		writeM3Report(t, filepath.Join(results, "application-mixed-candidates.json"), report)
	})
	return results, report
}
