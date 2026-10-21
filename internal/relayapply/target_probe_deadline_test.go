// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

type deadlineProbeBackend struct {
	*fakeNodeLease
	entered chan time.Time
}

func (b deadlineProbeBackend) Check(ctx context.Context, _ Entry, _ bool) (bool, error) {
	deadline, _ := ctx.Deadline()
	b.entered <- deadline
	<-ctx.Done()
	return false, ctx.Err()
}

func TestProbeAttemptPostcheckKeepsEarliestDeadline(t *testing.T) {
	for _, replacement := range []string{"unbounded", "later", "earlier"} {
		t.Run(replacement, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				originalDeadline := time.Now().Add(time.Second)
				original, cancel := context.WithDeadline(context.Background(), originalDeadline)
				defer cancel()
				e, k, _, attempt := probeAttemptFixture(t, original)
				attempt.run(successfulAttempt)
				observed, blocks := attempt.observation.ObservedAt, k.blocks
				post, stop := context.WithCancel(context.Background())
				defer stop()
				wantDeadline := originalDeadline
				if replacement != "unbounded" {
					deadline := originalDeadline.Add(time.Second)
					if replacement == "earlier" {
						deadline = originalDeadline.Add(-500 * time.Millisecond)
						wantDeadline = deadline
					}
					var cancelPost context.CancelFunc
					post, cancelPost = context.WithDeadline(post, deadline)
					defer cancelPost()
				}
				entered := make(chan time.Time, 1)
				e.backend = deadlineProbeBackend{k, entered}
				done := make(chan TargetObservation, 1)
				go func() { done <- e.finishTargetProbe(post, attempt) }()
				if got := <-entered; !got.Equal(wantDeadline) {
					t.Errorf("postcheck deadline=%s, want %s", got, wantDeadline)
				}
				select {
				case out := <-done:
					if out.State != "unknown" || !out.ObservedAt.Equal(observed) || out.RXDelta != 0 || out.TXDelta != 0 {
						t.Fatal("expired postcheck accepted or refreshed proof")
					}
					if !time.Now().Equal(wantDeadline) {
						t.Fatal("postcheck did not finish at the earliest deadline")
					}
				case <-time.After(3 * time.Second):
					stop()
					<-done
					t.Fatal("postcheck outlived its original deadline")
				}
				if k.blocks != blocks || !k.active["p0"] {
					t.Fatal("deadline rejection changed a current lease")
				}
				if out := e.finishTargetProbe(context.Background(), attempt); out.Reason != "probe_attempt_unavailable" {
					t.Fatal("expired proof remained reusable")
				}
			})
		})
	}
}
