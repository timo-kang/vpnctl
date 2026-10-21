//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Subprocesses preserve testing.T's real Fatal/Skip/Cleanup semantics without
// marking the parent regression test failed. The fixture callback always exits
// before any namespace, subprocess producer, or network preparation can start.
func TestApplicationCapacityReportPreparationFatal(t *testing.T) {
	capacityPreparationReport(t, "fatal", 1, "failed", "preparation", false, false)
}

func TestApplicationCapacityReportCleanupFatal(t *testing.T) {
	// Skip alone is not a failure. A subsequent fatal cleanup must still make
	// the report failed, so its writer must run after fixture-owned cleanups.
	capacityPreparationReport(t, "cleanup-fatal", 1, "failed", "preparation", true, false)
}

func TestApplicationCapacityReportPreparationSkipped(t *testing.T) {
	capacityPreparationReport(t, "skip", 0, "skipped", "preparation", false, false)
}

func TestApplicationCapacityReportCompleted(t *testing.T) {
	capacityPreparationReport(t, "completed", 0, "passed", "completed", false, true)
}

func TestApplicationCapacityReportCompletedCleanupFatal(t *testing.T) {
	capacityPreparationReport(t, "completed-cleanup-fatal", 1, "failed", "completed", true, false)
}

func capacityPreparationReport(t *testing.T, mode string, wantExit int, wantOutcome, wantPhase string, wantCleanup, wantCompleted bool) {
	t.Helper()
	artifacts := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate regression test executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestApplicationCapacityReportPreparationWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		"VPNCTL_CAPACITY_PREPARATION_REPORT_WORKER="+mode,
		"VPNCTL_ARTIFACT_DIR="+artifacts,
		"VPNCTL_INTEGRATION=0", "GOMAXPROCS=2")
	// Child output can contain fixture diagnostics. Assert on structured local
	// artifacts and exit status instead of echoing arbitrary worker output.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("preparation regression worker exceeded its bound")
	}
	gotExit := 0
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatal("preparation regression worker did not start")
		}
		gotExit = exited.ExitCode()
	}
	if gotExit != wantExit {
		t.Fatalf("preparation worker exit=%d, want=%d", gotExit, wantExit)
	}
	if _, err := os.Stat(filepath.Join(artifacts, "callback-entered")); err != nil {
		t.Fatal("fixture callback did not reach the reserved results directory")
	}
	_, cleanupErr := os.Stat(filepath.Join(artifacts, "cleanup-entered"))
	if (cleanupErr == nil) != wantCleanup {
		t.Fatal("cleanup failure scenario was not exercised as requested")
	}
	var reports []string
	err = filepath.WalkDir(artifacts, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "application-mixed-candidates.json" {
			reports = append(reports, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal("cannot inspect preparation artifacts")
	}
	if len(reports) != 1 {
		t.Fatalf("preparation must preserve exactly one capacity report, got=%d", len(reports))
	}
	if _, err := os.Stat(filepath.Join(artifacts, "reservation-valid")); err != nil {
		t.Fatal("private results directory was not reserved before preparation")
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(reports[0])), "m3-authority-") {
		t.Fatal("capacity report is outside the fixture artifact layout")
	}
	st, err := os.Stat(reports[0])
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("capacity report must remain private")
	}
	b, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal("cannot read preparation report")
	}
	var report struct {
		HealthyIndex         *int   `json:"healthy_index"`
		Completed            *bool  `json:"completed"`
		Phase                string `json:"phase"`
		PreparationCompleted *bool  `json:"preparation_completed"`
		TestOutcome          string `json:"test_outcome"`
		SampledStatus        string `json:"sampled_qualification_status"`
		RequestedProfile     struct {
			Paths            *int    `json:"paths"`
			RobotCPUs        *string `json:"robot_cpus"`
			CPULayout        *string `json:"cpu_layout"`
			AutomaticRebuild *bool   `json:"automatic_rebuild"`
		} `json:"requested_profile"`
		Publication map[string]json.RawMessage `json:"publication_continuity"`
	}
	if json.Unmarshal(b, &report) != nil {
		t.Fatal("preparation report is not valid JSON")
	}
	if report.HealthyIndex == nil || *report.HealthyIndex != 3 {
		t.Fatal("preparation report lost the planned healthy position")
	}
	if report.Completed == nil || *report.Completed != wantCompleted || report.PreparationCompleted == nil || *report.PreparationCompleted != (wantPhase == "completed") {
		t.Fatal("completion did not preserve final phase and cleanup outcome")
	}
	if report.Phase != wantPhase || report.TestOutcome != wantOutcome || report.SampledStatus != "not_started" {
		t.Fatal("preparation, test outcome, and unstarted qualification were conflated")
	}
	profile := report.RequestedProfile
	if profile.Paths == nil || *profile.Paths != 8 || profile.RobotCPUs == nil || *profile.RobotCPUs != "" ||
		profile.CPULayout == nil || *profile.CPULayout != "shared" || profile.AutomaticRebuild == nil || !*profile.AutomaticRebuild {
		t.Fatal("requested profile was lost before preparation completed")
	}
	var contract int
	var status string
	if json.Unmarshal(report.Publication["contract_version"], &contract) != nil || contract != 2 ||
		json.Unmarshal(report.Publication["status"], &status) != nil || status != "not_started" {
		t.Fatal("unstarted publication measurement was not explicitly preserved")
	}
	for _, key := range []string{"app", "app2", "input", "started_at", "ended_at", "baseline_count"} {
		if _, exists := report.Publication[key]; exists {
			t.Fatal("preparation failure fabricated a measured publication window")
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		t.Fatal("cannot inspect preparation measurement fields")
	}
	for _, key := range []string{"first_payload_seconds", "samples", "steady_seconds", "steady_applied_cycles", "maximum_fresh_observation_gap_seconds", "fault_installed_at", "result", "continuity_failure"} {
		if _, exists := fields[key]; exists {
			t.Fatal("unmeasured preparation emitted a measured result or false zero")
		}
	}
}

func TestApplicationCapacityReportPreparationWorker(t *testing.T) {
	mode := os.Getenv("VPNCTL_CAPACITY_PREPARATION_REPORT_WORKER")
	if mode == "" {
		return
	}
	artifacts := os.Getenv("VPNCTL_ARTIFACT_DIR")
	recordReservation := func(results string) {
		if err := os.WriteFile(filepath.Join(artifacts, "callback-entered"), nil, 0600); err != nil {
			t.Fatal("cannot record preparation callback entry")
		}
		// Record reservation validity without changing the injected Fatal/Skip
		// outcome. On the old code all scenarios therefore fail for the actual
		// missing-report defect, rather than an unrelated worker exit mismatch.
		st, err := os.Stat(results)
		if err == nil && st.IsDir() && st.Mode().Perm() == 0700 && filepath.Dir(results) == artifacts {
			if err := os.WriteFile(filepath.Join(artifacts, "reservation-valid"), nil, 0600); err != nil {
				t.Fatal("cannot record results-directory reservation")
			}
		}
	}
	if mode == "completed" || mode == "completed-cleanup-fatal" {
		results, report := newApplicationCapacityReport(t, 3, true, 8, "", "shared")
		recordReservation(results)
		report["phase"], report["preparation_completed"] = "completed", true
		if mode == "completed-cleanup-fatal" {
			t.Cleanup(func() {
				if err := os.WriteFile(filepath.Join(artifacts, "cleanup-entered"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				t.Fatal("synthetic cleanup failure after completed work")
			})
		}
		return
	}
	build := func(t *testing.T, paths int, group *os.File, results string) *m3AuthorityFixture {
		t.Helper()
		if paths != 8 || group != nil {
			t.Fatal("unexpected preparation callback arguments")
		}
		recordReservation(results)
		switch mode {
		case "fatal":
			t.Fatal("synthetic preparation failure")
		case "skip":
			t.Skip("synthetic preparation skip")
		case "cleanup-fatal":
			t.Cleanup(func() {
				if err := os.WriteFile(filepath.Join(artifacts, "cleanup-entered"), nil, 0600); err != nil {
					t.Fatal("cannot record preparation cleanup entry")
				}
				t.Fatal("synthetic preparation cleanup failure")
			})
			t.Skip("synthetic preparation skip before cleanup failure")
		default:
			t.Fatal("unknown preparation regression scenario")
		}
		return nil // Fatal and Skip never return; no real fixture can be used.
	}
	applicationMixedCandidatesProfileWithFixture(t, 3, true, 8, "", "shared", build)
	t.Fatal("preparation failure callback unexpectedly returned")
}
