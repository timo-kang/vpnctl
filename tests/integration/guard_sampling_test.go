//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// Worker stderr may contain arbitrary runtime output. Preserve only known,
// exact error lines; a failed sample is never evidence of an inactive lease.
func guardSamplingFailure(ctx context.Context, err error) string {
	class := "worker_start_failed"
	exit := -1
	var failed *exec.ExitError
	if errors.As(err, &failed) {
		exit = failed.ExitCode()
		class = "worker_failed"
		for _, line := range strings.Split(string(failed.Stderr), "\n") {
			switch strings.TrimSpace(line) {
			case netlink.ErrDumpInterrupted.Error():
				class = "link_dump_interrupted"
			case "operation not permitted":
				class = "permission_denied"
			}
		}
	}
	if ctx.Err() != nil {
		class = "cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			class = "deadline_exceeded"
		}
	}
	return fmt.Sprintf("class=%s exit=%d", class, exit)
}

func TestGuardSamplingFailureClassification(t *testing.T) {
	for _, tc := range []struct{ stderr, want string }{
		{netlink.ErrDumpInterrupted.Error() + "\n", "link_dump_interrupted"},
		{"operation not permitted\n", "permission_denied"},
		{"private-value dump interrupted\n", "worker_failed"},
		{"unknown private-value\n", "worker_failed"},
	} {
		got := guardSamplingFailure(context.Background(), &exec.ExitError{Stderr: []byte(tc.stderr)})
		if got != "class="+tc.want+" exit=-1" {
			t.Fatalf("classification mismatch: %q", got)
		}
	}
	if got := guardSamplingFailure(context.Background(), errors.New("private-value")); got != "class=worker_start_failed exit=-1" {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := guardSamplingFailure(ctx, &exec.ExitError{Stderr: []byte("dump interrupted\n")}); got != "class=cancelled exit=-1" {
		t.Fatal(got)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := guardSamplingFailure(ctx, errors.New("private-value")); got != "class=deadline_exceeded exit=-1" {
		t.Fatal(got)
	}
}

func TestGuardSamplingFailureWorker(t *testing.T) {
	if os.Getenv("VPNCTL_GUARD_SAMPLE_FAILURE") == "1" {
		fmt.Fprintln(os.Stderr, netlink.ErrDumpInterrupted)
		fmt.Fprintln(os.Stderr, "private-value")
		os.Exit(3)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-test.run=^TestGuardSamplingFailureWorker$")
	cmd.Env = append(os.Environ(), "VPNCTL_GUARD_SAMPLE_FAILURE=1")
	_, err = cmd.Output()
	if err == nil {
		t.Fatal("failed worker accepted")
	}
	if got := guardSamplingFailure(ctx, err); got != "class=link_dump_interrupted exit=3" {
		t.Fatal(got)
	}
}
