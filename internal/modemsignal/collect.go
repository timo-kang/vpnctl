// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package modemsignal

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"vpnctl/internal/execx"
)

var ErrUnsupported = errors.New("extended modem signals unsupported")

// Collector permits a fixture/provider reader. Read must honor context and
// output bounds; no device mutation is part of this interface.
type Collector struct {
	Read func(context.Context, string) (string, error)
}

func ValidIndex(index string) bool {
	n, err := strconv.ParseUint(index, 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == index
}

func (c Collector) Collect(ctx context.Context, index string) Snapshot {
	result := func(state, reason string) Snapshot {
		return unavailable(time.Now().UTC().Truncate(time.Microsecond), state, reason)
	}
	if !ValidIndex(index) {
		return result("unknown", "invalid_modem_index")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	read := c.Read
	if read == nil {
		read = readMMCLI
	}
	var raw string
	err := ctx.Err()
	if err == nil {
		raw, err = read(ctx, index)
	}
	// Even a faulty injected provider cannot turn canceled/stale work into data.
	if ctx.Err() != nil && !errors.Is(err, execx.ErrOutputLimit) {
		err = ctx.Err()
	}
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return result("unknown", "canceled")
		case errors.Is(err, context.DeadlineExceeded):
			return result("unknown", "timeout")
		case errors.Is(err, execx.ErrOutputLimit):
			return result("unknown", "output_limit")
		case errors.Is(err, ErrUnsupported):
			return result("unsupported", "signal_interface_unsupported")
		default:
			return result("unknown", "collector_unavailable")
		}
	}
	return Parse(raw, time.Now().UTC().Truncate(time.Microsecond))
}

func readMMCLI(ctx context.Context, index string) (string, error) {
	if _, err := exec.LookPath("mmcli"); err != nil {
		return "", err
	}
	r := &execx.OSRunner{Timeout: 2 * time.Second, Env: []string{"LC_ALL=C"}}
	out, stderr, err := r.OutputLimitedContext(ctx, MaxOutputBytes, "mmcli", "--modem", index, "--signal-get", "--output-keyvalue")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 && strings.TrimSpace(stderr) == "error: modem has no extended signal capabilities" {
		return "", ErrUnsupported
	}
	return out, err
}
