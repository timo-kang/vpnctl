// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

var ErrOutputLimit = errors.New("command output exceeds limit")

// Keep bytes.Buffer private so io.Copy cannot bypass Write via ReadFrom.
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buf.Len() {
		b.exceeded = true
		return 0, ErrOutputLimit
	}
	return b.buf.Write(p)
}

// OutputLimitedContext retains at most limit stdout bytes and min(limit,4096)
// stderr bytes. It uses the same deadline/process-group cleanup as OutputContext.
// Errors never include either stream. Callers must sanitize returned stderr
// before publishing diagnostics. Partial stdout is discarded on any failure.
func (r *OSRunner) OutputLimitedContext(ctx context.Context, limit int, name string, args ...string) (string, string, error) {
	if limit <= 0 {
		return "", "", errors.New("invalid output limit")
	}
	out, stderr := &limitedBuffer{limit: limit}, &limitedBuffer{limit: min(limit, 4096)}
	err := r.execute(ctx, out, stderr, name, args...)
	if out.exceeded || stderr.exceeded {
		return "", "", errors.Join(ErrOutputLimit, err)
	}
	if err != nil {
		return "", stderr.buf.String(), fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return out.buf.String(), stderr.buf.String(), nil
}
