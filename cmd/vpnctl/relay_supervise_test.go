// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
)

func TestRelaySupervisorContinuesAfterFailureAndBoundsCycles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	calls := 0
	err := superviseRelay(ctx, &out, func(c context.Context, refresh bool) (relaySupervisionReport, error) {
		calls++
		deadline, ok := c.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("unbounded supervision cycle")
		}
		if refresh != (calls == 1) {
			t.Fatal("refresh cadence ignored", calls, refresh)
		}
		if calls == 2 {
			cancel()
		}
		return relaySupervisionReport{SchemaVersion: 1, State: "degraded", Reason: "injected"}, errors.New("injected")
	}, 20*time.Second)
	if err != nil || calls != 2 {
		t.Fatal("supervision stopped on a transient failure", calls, err)
	}
	d := json.NewDecoder(&out)
	for n := 0; n < 2; n++ {
		var r relaySupervisionReport
		if err := d.Decode(&r); err != nil || r.State != "degraded" || r.ObservedAt.IsZero() {
			t.Fatal(r, err)
		}
	}
}

func TestRelaySupervisorRetriesOnlyNamespaceContentionWithinBudget(t *testing.T) {
	calls := 0
	want := new(relayapply.DeploymentEngine)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := openSupervisedDeployment(ctx, func() (*relayapply.DeploymentEngine, error) {
		calls++
		if calls < 3 {
			return nil, relayapply.ErrKernelBusy
		}
		return want, nil
	})
	if err != nil || got != want || calls != 3 {
		t.Fatal("contention did not converge", calls, err)
	}
	denied := errors.New("journal domain mismatch")
	calls = 0
	if _, err := openSupervisedDeployment(ctx, func() (*relayapply.DeploymentEngine, error) { calls++; return nil, denied }); !errors.Is(err, denied) || calls != 1 {
		t.Fatal("non-contention error retried", calls, err)
	}
	short, stop := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer stop()
	started := time.Now()
	if _, err := openSupervisedDeployment(short, func() (*relayapply.DeploymentEngine, error) { return nil, relayapply.ErrKernelBusy }); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("contention escaped budget", err)
	}
	calls = 0
	if _, err := openSupervisedDeployment(short, func() (*relayapply.DeploymentEngine, error) { calls++; return want, nil }); !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatal("cancelled cycle opened engine", calls, err)
	}
}

func TestRelaySupervisorYieldsAfterOverrunningCadence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var completed time.Time
	var idle time.Duration
	calls := 0
	err := superviseRelay(ctx, io.Discard, func(context.Context, bool) (relaySupervisionReport, error) {
		calls++
		if calls == 1 {
			time.Sleep(1100 * time.Millisecond)
			completed = time.Now()
		} else {
			idle = time.Since(completed)
			cancel()
		}
		return relaySupervisionReport{SchemaVersion: 1}, nil
	}, time.Second)
	if err != nil || calls != 2 || idle < 50*time.Millisecond {
		t.Fatal("overrunning supervisor monopolizes namespace", calls, idle, err)
	}
}

type failedLeaseWriter struct{}

func (failedLeaseWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRelaySupervisorStopsRenewingWhenOutputFails(t *testing.T) {
	calls := 0
	err := superviseRelay(context.Background(), failedLeaseWriter{}, func(context.Context, bool) (relaySupervisionReport, error) {
		calls++
		return relaySupervisionReport{}, nil
	}, time.Second)
	if !errors.Is(err, io.ErrClosedPipe) || calls != 1 {
		t.Fatal(calls, err)
	}
	for _, args := range [][]string{{"--refresh-interval", "0s"}, {"--refresh-interval", "21s"}, {"unexpected"}, {"--relay-id", "../invalid"}} {
		if err := runRelaySupervise(args); err == nil {
			t.Fatal("invalid supervisor options accepted", args)
		}
	}
}
