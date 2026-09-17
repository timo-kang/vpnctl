// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"vpnctl/internal/metrics"
)

const DefaultTimeout = 5 * time.Second

// Runner abstracts command execution for tests that do not touch host networking.
type Runner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) (string, error)
}

type ContextRunner interface {
	RunContext(context.Context, string, ...string) error
	OutputContext(context.Context, string, ...string) (string, error)
}

// OSRunner executes bounded commands on the host. Timeout <= 0 uses the default.
// Configure fields before sharing a runner with concurrent callers.
type OSRunner struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Timeout time.Duration
}

func NewOSRunner(stdout, stderr io.Writer) *OSRunner {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return &OSRunner{Stdout: stdout, Stderr: stderr}
}

func (r *OSRunner) Run(name string, args ...string) error {
	return r.RunContext(context.Background(), name, args...)
}
func (r *OSRunner) Output(name string, args ...string) (string, error) {
	return r.OutputContext(context.Background(), name, args...)
}
func (r *OSRunner) RunContext(ctx context.Context, name string, args ...string) error {
	var stderr bytes.Buffer
	err := r.execute(ctx, r.Stdout, &stderr, name, args...)
	if err != nil {
		return commandError(name, err, stderr.String())
	}
	if stderr.Len() > 0 && r.Stderr != nil {
		_, _ = io.Copy(r.Stderr, &stderr)
	}
	return nil
}
func (r *OSRunner) OutputContext(ctx context.Context, name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	if err := r.execute(ctx, &stdout, &stderr, name, args...); err != nil {
		// Successful output may contain WireGuard keys; never put stdout in errors.
		return "", commandError(name, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (r *OSRunner) execute(parent context.Context, stdout, stderr io.Writer, name string, args ...string) (err error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	command := filepath.Base(name)
	label := command
	if label != "ip" && label != "wg" {
		label = "other"
	}
	defer func() {
		result := "success"
		if err != nil {
			result = "error"
		}
		if errors.Is(err, context.Canceled) {
			result = "canceled"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			result = "timeout"
		}
		elapsed := time.Since(start)
		metrics.SystemCommandSeconds.WithLabelValues(label, result).Observe(elapsed.Seconds())
		if err != nil || elapsed >= time.Second {
			// Names and durations only: arguments/output may contain credentials.
			slog.Warn("system command completed", "command", command, "result", result, "duration", elapsed)
		}
	}()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Kill the command's whole process group so shell helpers cannot keep pipes
	// or networking work alive after cancellation of their parent command.
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 250 * time.Millisecond
	err = cmd.Run()
	if err != nil && cmd.Process != nil {
		// A failed leader can leave descendants holding pipes. ExitError takes
		// precedence over ErrWaitDelay, so clean up the group on every failure.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if ctx.Err() != nil {
		err = errors.Join(ctx.Err(), err)
	}
	return err
}

func commandError(name string, err error, stderr string) error {
	if text := strings.TrimSpace(stderr); text != "" {
		return fmt.Errorf("%s: %w: %s", filepath.Base(name), err, text)
	}
	return fmt.Errorf("%s: %w", filepath.Base(name), err)
}
