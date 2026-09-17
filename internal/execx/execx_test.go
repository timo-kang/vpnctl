package execx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOutputPreservesStartError(t *testing.T) {
	_, err := NewOSRunner(io.Discard, io.Discard).Output("vpnctl-nonexistent-test-command")
	if err == nil || err.Error() == "" || !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("original start error lost: %v", err)
	}
}

func TestCommandHelper(t *testing.T) {
	if os.Getenv("VPNCTL_COMMAND_HELPER") != "1" {
		return
	}
	args := os.Args
	mode := args[len(args)-1]
	switch mode {
	case "failure":
		fmt.Fprint(os.Stdout, "private-output-marker")
		fmt.Fprint(os.Stderr, "diagnostic-marker")
		os.Exit(7)
	case "success":
		fmt.Fprint(os.Stdout, "value\n")
		fmt.Fprint(os.Stderr, "warning\n")
		os.Exit(0)
	case "wait":
		time.Sleep(time.Hour)
	case "tree", "pipe", "pipe_failure":
		child := exec.Command(os.Args[0], "-test.run=^TestCommandHelper$", "wait")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("VPNCTL_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(3)
		}
		if mode == "pipe_failure" {
			os.Exit(7)
		}
		if mode == "pipe" {
			os.Exit(0)
		}
		_ = child.Wait()
	}
	os.Exit(0)
}

func TestOutputPreservesExitAndSeparatesStreams(t *testing.T) {
	t.Setenv("VPNCTL_COMMAND_HELPER", "1")
	r := NewOSRunner(io.Discard, io.Discard)
	_, err := r.Output(os.Args[0], "-test.run=^TestCommandHelper$", "failure")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || !strings.Contains(err.Error(), "diagnostic-marker") || strings.Contains(err.Error(), "private-output-marker") {
		t.Fatalf("wrong failure diagnostics: %v", err)
	}
	out, err := r.Output(os.Args[0], "-test.run=^TestCommandHelper$", "success")
	if err != nil || out != "value" {
		t.Fatalf("stderr polluted output: %q %v", out, err)
	}
}

func TestCommandTimeoutAndCancellation(t *testing.T) {
	t.Setenv("VPNCTL_COMMAND_HELPER", "1")
	for _, mode := range []string{"timeout", "cancel", "already-canceled"} {
		t.Run(mode, func(t *testing.T) {
			r := NewOSRunner(io.Discard, io.Discard)
			r.Timeout = 100 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "already-canceled" {
				cancel()
			}
			done := make(chan error, 1)
			go func() { done <- r.RunContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$", "wait") }()
			if mode == "cancel" {
				time.Sleep(30 * time.Millisecond)
				cancel()
			}
			select {
			case err := <-done:
				want := context.Canceled
				if mode == "timeout" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("want %v got %v", want, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("command did not stop")
			}
		})
	}
}

func TestCommandGroupAndInheritedPipeCleanup(t *testing.T) {
	t.Setenv("VPNCTL_COMMAND_HELPER", "1")
	for _, mode := range []string{"tree", "pipe", "pipe_failure"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "child.pid")
			t.Setenv("VPNCTL_CHILD_PID", path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := NewOSRunner(io.Discard, io.Discard)
			done := make(chan error, 1)
			go func() { done <- r.RunContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$", mode) }()
			var pid int
			until := time.Now().Add(2 * time.Second)
			for time.Now().Before(until) {
				data, _ := os.ReadFile(path)
				pid, _ = strconv.Atoi(string(data))
				if pid > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if pid == 0 {
				t.Fatal("helper child did not start")
			}
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
			if mode == "tree" {
				cancel()
			}
			select {
			case err := <-done:
				want := error(context.Canceled)
				if mode == "pipe" {
					want = exec.ErrWaitDelay
				}
				if mode == "pipe_failure" {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 7 {
						t.Fatalf("exit error lost: %v", err)
					}
				} else if !errors.Is(err, want) {
					t.Fatalf("want %v got %v", want, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("command group/pipes outlived budget")
			}
			for deadline := time.Now().Add(time.Second); ; {
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if os.IsNotExist(err) || strings.Contains(string(data), ") Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("helper child survived command cancellation")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
