// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

func rpFilterPath(path string) bool {
	name, ok := strings.CutPrefix(path, "/proc/sys/net/ipv4/conf/")
	if !ok {
		return false
	}
	name, ok = strings.CutSuffix(name, "/rp_filter")
	if !ok || len(name) == 0 || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Never cache this value: a network manager may change rp_filter between the
// precheck and postcheck. Only bounded, regular proc settings are read; a FIFO
// or symlink must fail without blocking. The caller still validates the value.
func readProcSetting(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("kernel setting unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid kernel setting file")
	}
	const limit = 32
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || len(b) > limit {
		return nil, errors.New("invalid kernel setting read")
	}
	return b, nil
}
