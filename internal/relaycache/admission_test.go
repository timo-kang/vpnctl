// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newAdmission(t *testing.T, dir string) *admission {
	t.Helper()
	root, err := openDirectory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	a := &admission{files: &files{root: root}}
	t.Cleanup(func() { a.Close() })
	return a
}
func scanAdmission(t *testing.T, a *admission, want bool) {
	t.Helper()
	got, err := a.scan(context.Background())
	if err != nil || got != want {
		t.Fatalf("first=%v want=%v err=%v", got, want, err)
	}
}

// Deterministic overtaking pressure: a previous winner repeatedly rejoins while
// an older observer and maintenance cycle wait. Timing cannot make this pass.
func TestAdmissionFIFORejoin(t *testing.T) {
	dir := privateTempDir(t)
	for i := 0; i < 20; i++ {
		a, b, c := newAdmission(t, dir), newAdmission(t, dir), newAdmission(t, dir)
		scanAdmission(t, a, true)
		scanAdmission(t, b, false)
		scanAdmission(t, c, false)
		a.Close()
		d := newAdmission(t, dir)
		scanAdmission(t, d, false)
		scanAdmission(t, c, false)
		scanAdmission(t, b, true)
		b.Close()
		scanAdmission(t, d, false)
		scanAdmission(t, c, true)
		c.Close()
		scanAdmission(t, d, true)
		d.Close()
	}
}

func TestAdmissionCancellationAndStoreLifetime(t *testing.T) {
	dir := privateTempDir(t)
	s := openCache(t, dir)
	s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	holder, err := OpenQueued(ctx, dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	short, stop := context.WithTimeout(ctx, 80*time.Millisecond)
	defer stop()
	started := time.Now()
	if _, err := OpenQueued(short, dir, Options{NodeID: "robot"}); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("wait did not cancel", err)
	}
	if _, err := Open(dir, Options{NodeID: "robot"}); !errors.Is(err, ErrBusy) {
		t.Fatal("admission replaced cache exclusion", err)
	}
	waiting := newAdmission(t, dir)
	scanAdmission(t, waiting, false)
	holder.Close()
	scanAdmission(t, waiting, true)
	waiting.Close()
	next, err := OpenQueued(ctx, dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal("cancelled ticket retained", err)
	}
	next.Close()
	if _, err := OpenQueued(context.Background(), dir, Options{NodeID: "robot"}); err == nil {
		t.Fatal("unbounded wait accepted")
	}
}

func TestAdmissionBoundAndUnsafeState(t *testing.T) {
	t.Run("bounded", func(t *testing.T) {
		dir := privateTempDir(t)
		live := make([]*admission, admissionSlots)
		for i := range live {
			live[i] = newAdmission(t, dir)
			scanAdmission(t, live[i], i == 0)
		}
		extra := newAdmission(t, dir)
		if _, err := extra.scan(context.Background()); !errors.Is(err, ErrAdmissionFull) {
			t.Fatal(err)
		}
		live[3].Close() // A cancelled middle waiter must not block or change order.
		scanAdmission(t, extra, false)
		if extra.ticket != admissionSlots+1 {
			t.Fatal("reused cancelled ticket", extra.ticket)
		}
	})
	t.Run("corrupt_live", func(t *testing.T) {
		dir := privateTempDir(t)
		a := newAdmission(t, dir)
		scanAdmission(t, a, true)
		if err := a.slot.Truncate(1); err != nil {
			t.Fatal(err)
		}
		b := newAdmission(t, dir)
		if _, err := b.scan(context.Background()); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		a.Close()
		scanAdmission(t, b, true) // Dead content has no authority.
	})
	for _, name := range []string{"admission.lock", "admission-00"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTempDir(t)
			foreign := filepath.Join(privateTempDir(t), "foreign")
			if err := os.WriteFile(foreign, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(foreign, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			a := newAdmission(t, dir)
			if _, err := a.scan(context.Background()); !errors.Is(err, ErrUnsafe) {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(foreign)
			if string(b) != "untouched" {
				t.Fatal("followed foreign file")
			}
		})
	}
}

// Exercise real process death, not PID probing or mocked liveness.
func TestAdmissionProcessWorker(t *testing.T) {
	dir := os.Getenv("VPNCTL_ADMISSION_WORKER_DIR")
	if dir == "" {
		return
	}
	a := newAdmission(t, dir)
	first, err := a.scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("READY %v\n", first)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "check":
			first, err := a.scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("FIRST %v\n", first)
		case "close":
			a.Close()
			fmt.Println("CLOSED")
			return
		}
	}
}

func TestAdmissionCrossProcessFIFOAndCrash(t *testing.T) {
	dir := privateTempDir(t)
	type child struct {
		cmd *exec.Cmd
		in  io.WriteCloser
		out *bufio.Scanner
	}
	start := func() child {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAdmissionProcessWorker$")
		cmd.Env = append(os.Environ(), "VPNCTL_ADMISSION_WORKER_DIR="+dir)
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
		return child{cmd, in, bufio.NewScanner(out)}
	}
	read := func(c child, want string) {
		t.Helper()
		line := make(chan string, 1)
		go func() {
			if c.out.Scan() {
				line <- c.out.Text()
			} else {
				line <- "EOF"
			}
		}()
		select {
		case got := <-line:
			if got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("worker stalled")
		}
	}
	check := func(c child, want bool) { fmt.Fprintln(c.in, "check"); read(c, fmt.Sprint("FIRST ", want)) }
	a := start()
	read(a, "READY true")
	b := start()
	read(b, "READY false")
	c := start()
	read(c, "READY false")
	if err := a.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := a.cmd.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatal("crash not exercised", err)
	}
	d := start()
	read(d, "READY false")
	check(c, false)
	check(d, false)
	check(b, true)
	// Kill the head before it performs work; the following process must advance.
	if err := b.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	b.cmd.Wait()
	check(d, false)
	check(c, true)
	fmt.Fprintln(c.in, "close")
	read(c, "CLOSED")
	check(d, true)
}

func TestAdmissionRejectsDirectoryReplacement(t *testing.T) {
	parent := privateTempDir(t)
	dir := filepath.Join(parent, "cache")
	holder := openCache(t, dir)
	replacementDir := filepath.Join(parent, "replacement")
	replacement := openCache(t, replacementDir)
	replacement.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		s, err := OpenQueued(ctx, dir, Options{NodeID: "robot"})
		if s != nil {
			s.Close()
		}
		result <- err
	}()
	// Wait for a published queue ticket, while cache.lock is still held.
	for {
		f, err := os.OpenFile(filepath.Join(dir, "admission-00"), os.O_RDWR, 0600)
		if err == nil {
			err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				break
			}
		}
		if err := admissionPause(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Both directories are initialized before the atomic exchange. A two-step
	// rename legitimately returns ErrMissing between removal and creation and
	// would never exercise the identity comparison this test is checking.
	if err := unix.Renameat2(unix.AT_FDCWD, dir, unix.AT_FDCWD, replacementDir, unix.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrUnsafe) {
		t.Fatal("queue admitted a different cache", err)
	}
	holder.Close()
	// The failed opener must have released the replacement's cache lock too.
	next, err := OpenQueued(ctx, dir, Options{NodeID: "robot"})
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
