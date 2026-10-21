// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package modemsignal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/execx"
)

func TestSignalCollectorFailuresAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		err           error
		state, reason string
	}{
		{ErrUnsupported, "unsupported", "signal_interface_unsupported"},
		{execx.ErrOutputLimit, "unknown", "output_limit"},
		{context.Canceled, "unknown", "canceled"},
		{context.DeadlineExceeded, "unknown", "timeout"},
		{errors.New("PRIVATE_MODEM_OUTPUT"), "unknown", "collector_unavailable"},
	} {
		c := Collector{Read: func(context.Context, string) (string, error) { return fixture, tc.err }}
		s := c.Collect(context.Background(), "0")
		if s.State != tc.state || s.Reason != tc.reason || s.LTE.RSSI.Value != nil {
			t.Fatal("error became valid data", s)
		}
		if err := s.Validate(time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	called := false
	c := Collector{Read: func(context.Context, string) (string, error) { called = true; return fixture, nil }}
	for _, index := range []string{"", "--enable", "0;reset", "-1", "00", "4294967296"} {
		if c.Collect(context.Background(), index).Reason != "invalid_modem_index" {
			t.Fatal("unsafe index accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Collect(ctx, "0").Reason != "canceled" || called {
		t.Fatal("canceled work executed")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if c.Collect(ctx, "0").Reason != "timeout" || called {
		t.Fatal("expired context executed")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	c.Read = func(context.Context, string) (string, error) { cancel(); return fixture, nil }
	if c.Collect(ctx, "0").State != "unknown" {
		t.Fatal("late result survived cancellation")
	}
	c.Read = func(context.Context, string) (string, error) { return strings.Repeat("x", MaxOutputBytes+1), nil }
	if c.Collect(context.Background(), "0").Reason != "output_limit" {
		t.Fatal("provider bypassed size limit")
	}
}

func TestReadMMCLIOnlyReadsSignalCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	path := filepath.Join(dir, "mmcli")
	// This owned fake executable never invokes any modem or system service.
	script := "#!/bin/sh\n[ \"$LC_ALL\" = C ] || exit 9\n[ \"$#\" = 4 ] || exit 8\n[ \"$1 $2 $3 $4\" = '--modem 12 --signal-get --output-keyvalue' ] || exit 7\nprintf 'modem.signal.lte.snr : 0.00\\n'\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	s := (Collector{}).Collect(context.Background(), "12")
	if s.State != "cached" || s.LTE.SNR.Value == nil || *s.LTE.SNR.Value != 0 {
		t.Fatal("command/locale contract changed", s)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'error: modem has no extended signal capabilities\\n' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if s := (Collector{}).Collect(context.Background(), "12"); s.State != "unsupported" {
		t.Fatal("unsupported interface not identified", s)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'PRIVATE_PERMISSION_ERROR\\n' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if s := (Collector{}).Collect(context.Background(), "12"); s.Reason != "collector_unavailable" {
		t.Fatal("error text leaked/classified as unsupported", s)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s := (Collector{}).Collect(context.Background(), "12"); s.Reason != "collector_unavailable" {
		t.Fatal("missing optional tool", s)
	}
}
