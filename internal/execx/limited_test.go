// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package execx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLimitedCommandHelper(t *testing.T) {
	if os.Getenv("VPNCTL_LIMIT_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "stdout":
		fmt.Fprint(os.Stdout, strings.Repeat("private", 10000))
	case "stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("private", 10000))
	case "failure":
		fmt.Fprint(os.Stdout, "PRIVATE")
		fmt.Fprint(os.Stderr, "secret-diagnostic")
		os.Exit(3)
	case "env":
		fmt.Fprint(os.Stdout, os.Getenv("LC_ALL"))
	case "wait":
		time.Sleep(time.Hour)
	}
	os.Exit(0)
}

func TestLimitedOutputBoundsAndSanitization(t *testing.T) {
	t.Setenv("VPNCTL_LIMIT_HELPER", "1")
	// The race runtime sleeps for a second at process exit by default. Disable
	// only that helper teardown delay; production command deadlines stay intact.
	r := &OSRunner{Timeout: time.Second, Env: []string{"LC_ALL=C", "GORACE=atexit_sleep_ms=0"}}
	for _, mode := range []string{"stdout", "stderr"} {
		out, stderr, err := r.OutputLimitedContext(context.Background(), 8192, os.Args[0], "-test.run=^TestLimitedCommandHelper$", mode)
		if !errors.Is(err, ErrOutputLimit) || out != "" || stderr != "" || strings.Contains(err.Error(), "private") {
			t.Fatalf("%s: %q %q %v", mode, out, stderr, err)
		}
	}
	out, stderr, err := r.OutputLimitedContext(context.Background(), 8192, os.Args[0], "-test.run=^TestLimitedCommandHelper$", "failure")
	if err == nil || out != "" || stderr != "secret-diagnostic" || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("streams leaked into error: %q %q %v", out, stderr, err)
	}
	out, _, err = r.OutputLimitedContext(context.Background(), 8192, os.Args[0], "-test.run=^TestLimitedCommandHelper$", "env")
	if err != nil || out != "C" {
		t.Fatal("locale override lost", out, err)
	}
	for _, limit := range []int{0, -1} {
		if _, _, err := r.OutputLimitedContext(context.Background(), limit, "unused"); err == nil {
			t.Fatal("bad limit accepted")
		}
	}
	// Exercise io.Copy's optimization paths; no promoted ReadFrom may grow the buffer.
	b := &limitedBuffer{limit: 4}
	if _, err := io.Copy(b, strings.NewReader("12345")); !errors.Is(err, ErrOutputLimit) || b.buf.Len() > 4 {
		t.Fatal("copy bypassed bound", err)
	}
}

func TestLimitedCommandCancellation(t *testing.T) {
	t.Setenv("VPNCTL_LIMIT_HELPER", "1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &OSRunner{Timeout: 30 * time.Millisecond}
	for _, ctx := range []context.Context{ctx, context.Background()} {
		out, stderr, err := r.OutputLimitedContext(ctx, 8192, os.Args[0], "-test.run=^TestLimitedCommandHelper$", "wait")
		if err == nil || out != "" || stderr != "" || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
			t.Fatal("cancellation lost", err)
		}
	}
}
