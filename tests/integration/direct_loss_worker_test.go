//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/direct"
)

type directLossSample struct {
	Sequence  int           `json:"sequence"`
	At        time.Time     `json:"at"`
	Elapsed   time.Duration `json:"elapsed_ns"`
	OK        bool          `json:"ok"`
	Gap       time.Duration `json:"gap_ns"`
	Completed bool          `json:"completed"`
}

// Measure actual nonce replies in a persistent namespace worker. Re-executing
// the test binary per packet, a 500ms receive timeout and coordinator sleeps
// otherwise add blind intervals to the reported five-second outage bound.
func runDirectLossWatch() error {
	return directLossWatch(os.Getenv("VPNCTL_PROBE_ENDPOINT"), os.Stdout)
}

func directLossWatch(endpoint string, output io.Writer) error {
	start := time.Now()
	lastGood := start
	encoder := json.NewEncoder(output)
	for n := 1; ; n++ {
		_, err := direct.ProbePeer(context.Background(), ":0", endpoint, 100*time.Millisecond)
		now := time.Now()
		gap := now.Sub(lastGood)
		done := now.Sub(start) >= 12*time.Second && err == nil
		sample := directLossSample{n, now.UTC(), now.Sub(start), err == nil, gap, done}
		if e := encoder.Encode(sample); e != nil {
			return e
		}
		if n == 1 && err != nil {
			return fmt.Errorf("loss monitor baseline failed: %w", err)
		}
		// The recovery reply itself is included, not just earlier failed probes.
		if gap > 5*time.Second {
			return fmt.Errorf("observed overlay gap exceeded 5s: %s", gap)
		}
		if done {
			return nil
		}
		if err == nil {
			lastGood = now
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type lossSampleWriter struct {
	samples    []directLossSample
	afterFirst func()
}

func (w *lossSampleWriter) Write(b []byte) (int, error) {
	var sample directLossSample
	if err := json.Unmarshal(b, &sample); err != nil {
		return 0, err
	}
	w.samples = append(w.samples, sample)
	if len(w.samples) == 1 && w.afterFirst != nil {
		w.afterFirst()
	}
	return len(b), nil
}

func TestDirectLossWatchRejectsOverlongOutage(t *testing.T) {
	responder, err := direct.StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = responder.Close() })
	endpoint := responder.LocalAddr()
	writer := &lossSampleWriter{afterFirst: func() { _ = responder.Close() }}
	err = directLossWatch(endpoint, writer)
	if err == nil || !strings.Contains(err.Error(), "gap exceeded 5s") {
		t.Fatal("permanent outage accepted", err)
	}
	if len(writer.samples) < 2 || !writer.samples[0].OK {
		t.Fatal("missing baseline", writer.samples)
	}
	last := writer.samples[len(writer.samples)-1]
	if last.OK || last.Completed || last.Gap <= 5*time.Second {
		t.Fatal("overlong loss not recorded", last)
	}
}
