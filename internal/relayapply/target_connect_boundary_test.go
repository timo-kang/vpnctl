// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayselect"
)

func TestPolicyConnectLimitIncludesExactBoundary(t *testing.T) {
	e, _, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	target := entry.Candidate.Targets[0]
	for _, duration := range []time.Duration{999 * time.Millisecond, time.Second} {
		t.Run(duration.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transfers := 0
				k := kernel{run: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
					if name == "ip" {
						return json.Marshal([]object{{"dev": entry.Candidate.Pin.WGInterface, "from": strings.TrimSuffix(entry.Candidate.InnerAddress, "/32")}})
					}
					if name == "wg" && args[2] == "latest-handshakes" {
						return []byte(entry.Candidate.RelayPublicKey + " 1"), nil
					}
					transfers++
					return fmt.Appendf(nil, "%s %d %d", entry.Candidate.RelayPublicKey, 100*transfers, 100*transfers), nil
				}}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				ctx = context.WithValue(ctx, targetConnectLimitKey{}, time.Second)
				proof, err := k.probeTargetWithDial(ctx, entry, target, func(ctx context.Context, _ Entry, _ relaycatalog.Target) (net.Conn, error) {
					// Complete exactly at the policy's accepted <= boundary. Checking
					// cancellation models a context-aware dialer returning from its wait.
					time.Sleep(duration)
					synctest.Wait() // Run any deadline cancellation scheduled at this instant.
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					a, b := net.Pipe()
					_ = b.Close()
					return a, nil
				})
				if err != nil || proof.duration != duration {
					t.Fatalf("policy-eligible connect rejected: duration=%s proof=%+v err=%v", duration, proof, err)
				}
			})
		})
	}
}

func TestReconcileConnectPolicyDoesNotLeakIntoRawObservation(t *testing.T) {
	e, _, _, _ := appFixture(t)
	policy := relayselect.DefaultPolicy()
	policy.MaxConnectTime = 1500 * time.Millisecond
	selector, err := relayselect.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	var expected atomic.Int64
	expected.Store(int64(policy.MaxConnectTime))
	var calls atomic.Int32
	e.probe = func(ctx context.Context, _ Entry, _ relaycatalog.Target) (targetProof, error) {
		calls.Add(1)
		got, _ := ctx.Value(targetConnectLimitKey{}).(time.Duration)
		if got != time.Duration(expected.Load()) {
			t.Errorf("wrong dial policy: got=%s want=%s", got, time.Duration(expected.Load()))
		}
		return targetProof{duration: time.Millisecond, handshake: 1, rx: 96, tx: 192}, nil
	}
	for i := 0; i < 2; i++ {
		out, err := e.ReconcileTarget(context.Background(), "app", "", selector, 2*time.Second)
		if i == 0 && out.Applied || i == 1 && (err != nil || !out.Applied) {
			t.Fatalf("unexpected confirmation/application: cycle=%d applied=%t err=%v", i, out.Applied, err)
		}
	}
	expected.Store(0)
	before := calls.Load()
	raw, err := e.ObserveTarget(context.Background(), "app", "", 2*time.Second)
	if err != nil || !raw.Valid || calls.Load() <= before {
		t.Fatalf("raw observation lost its original budget: valid=%t err=%v calls=%d", raw.Valid, err, calls.Load()-before)
	}
}

func TestCanceledReconcileJoinsPolicyLimitedProofs(t *testing.T) {
	e, _, _, _ := appFixture(t)
	selector := appSelector(t)
	entered := make(chan struct{}, 3)
	var live atomic.Int32
	e.probe = func(ctx context.Context, _ Entry, _ relaycatalog.Target) (targetProof, error) {
		live.Add(1)
		defer live.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return targetProof{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan TargetReconcileResult, 1)
	go func() { out, _ := e.ReconcileTarget(ctx, "app", "", selector, 2*time.Second); done <- out }()
	for range 3 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("not all candidate proofs started")
		}
	}
	cancel()
	select {
	case out := <-done:
		if out.Applied || live.Load() != 0 {
			t.Fatalf("canceled reconcile retained application/proofs: applied=%t live=%d", out.Applied, live.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled reconcile did not join its workers")
	}
}
