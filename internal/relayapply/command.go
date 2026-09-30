// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type commandFunc func(context.Context, string, string, ...string) ([]byte, error)
type outputBuffer struct {
	b   bytes.Buffer
	max int
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.b.Len() {
		return 0, errors.New("command output limit")
	}
	return b.b.Write(p)
}

// Configuration may contain a private key; neither command input nor stderr is
// included in errors. Children inherit only a pipe, not a secret argv/file.
func command(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C")
	c.Stdin = strings.NewReader(input)
	out, stderr := &outputBuffer{max: 512 << 10}, &outputBuffer{max: 4096}
	c.Stdout, c.Stderr = out, stderr
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		err := syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	c.WaitDelay = 250 * time.Millisecond
	if err := c.Run(); err != nil {
		if c.Process != nil {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("kernel command failed")
	}
	return out.b.Bytes(), nil
}

var _ io.Writer = (*outputBuffer)(nil)
