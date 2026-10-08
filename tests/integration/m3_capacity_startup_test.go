//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only the startup profile changes the initial fixture commands' resource role.
// Network construction, pre-provisioned WireGuard keys and server work remain
// measurement fixtures; actual node join, registration and preparation do not.
type capacityStartup struct {
	group    *capacityGroup
	started  time.Time
	before   map[string]any
	report   map[string]any
	commands []map[string]any
}

func (s *capacityStartup) begin(t *testing.T, results string) {
	t.Helper()
	s.started = time.Now()
	s.before = s.group.evidence(t)
	s.report = map[string]any{"ready_candidates": 0}
	t.Cleanup(func() {
		s.report["commands"] = s.commands
		if s.report["seconds"] == nil {
			s.report["seconds"] = time.Since(s.started).Seconds()
		}
		writeM3Report(t, filepath.Join(results, "startup-capacity.json"), map[string]any{
			"completed": !t.Failed(), "startup": s.report, "resource_profile": s.before,
			"resource_profile_after": s.group.evidence(t),
		})
	})
}

func (s *capacityStartup) ready(t *testing.T, paths int) {
	t.Helper()
	elapsed := time.Since(s.started).Seconds()
	s.report["seconds"], s.report["commands"], s.report["ready_candidates"] = elapsed, s.commands, paths
	if elapsed > 120 {
		t.Fatal("initial enrollment and preparation exceeded 120 seconds")
	}
}

func startupPhase(args []string) string {
	phase := args[3] // node relay action, never arbitrary command arguments or tokens
	if phase == "target" {
		phase = args[4]
	}
	for i := 4; i+1 < len(args); i++ {
		if args[i] == "--path-id" || args[i] == "--target-id" {
			return phase + "/" + args[i+1]
		}
	}
	return phase
}

func verifyStartupPlacement(proof, group, cpus string) error {
	lines := strings.Split(proof, "\n")
	if len(lines) == 0 || lines[0] != "0::/"+filepath.Base(group) {
		return fmt.Errorf("startup command escaped robot cgroup")
	}
	for _, line := range lines[1:] {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok && strings.TrimSpace(value) == cpus {
			return nil
		}
	}
	return fmt.Errorf("startup command CPU mask differs from robot mask")
}

func (s *capacityStartup) run(t *testing.T, ctx context.Context, ns, phase string, args ...string) ([]byte, error) {
	t.Helper()
	proof := filepath.Join(t.TempDir(), "placement")
	// clone3 places even the namespace launcher and evidence commands in the
	// robot group. The final exec inherits that group and CPU mask. No arguments,
	// credentials or command output are copied into the public phase report.
	wrapped := []string{"sh", "-c", `cat /proc/self/cgroup > "$1" && cat /proc/self/status >> "$1" && shift && exec "$@"`, "capacity", proof}
	cmd := netCommand(ctx, ns, append(wrapped, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(s.group.file.Fd())}
	started := time.Now()
	output, err := cmd.CombinedOutput()
	elapsed := time.Since(started).Seconds()
	evidence, readErr := os.ReadFile(proof)
	if readErr != nil {
		t.Fatal("missing startup process placement evidence", readErr)
	}
	if placementErr := verifyStartupPlacement(string(evidence), s.group.path, s.group.cpus); placementErr != nil {
		t.Fatal(placementErr)
	}
	s.commands = append(s.commands, map[string]any{"phase": phase, "seconds": elapsed,
		"succeeded": err == nil, "retryable": false,
		"placement_verified": true, "cpus": s.group.cpus})
	return output, err
}

func TestStartupPlacementEvidence(t *testing.T) {
	good := "0::/vpnctl-capacity-123\nName:\tcat\nCpus_allowed_list:\t0\n"
	for _, tc := range []struct {
		name, proof string
		want        bool
	}{
		{"actual robot placement", good, true},
		{"server group", strings.Replace(good, "vpnctl-capacity-123", "server", 1), false},
		{"server CPU", strings.Replace(good, "list:\t0", "list:\t1", 1), false},
		{"overlapping mask", strings.Replace(good, "list:\t0", "list:\t0-1", 1), false},
		{"missing mask", "0::/vpnctl-capacity-123\n", false},
		{"missing proof", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyStartupPlacement(tc.proof, "/sys/fs/cgroup/vpnctl-capacity-123", "0") == nil; got != tc.want {
				t.Fatalf("verified=%t want=%t", got, tc.want)
			}
		})
	}
}
