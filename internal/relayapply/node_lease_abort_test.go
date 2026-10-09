// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Model a queued kernel operation whose successful ACK arrives as cancellation
// is observed. Block honors cancellation just like the real nft/BPF operations.
type queuedGrantBackend struct {
	*overlapLeaseBackend
	first, completed  chan struct{}
	deadline          time.Time
	cleanupDeadlineOK bool
	cleanupRan        bool
	afterCancellation func()
}

func (b *queuedGrantBackend) Lease(ctx context.Context, entry Entry, _ FreshApproval) (DeploymentLease, error) {
	b.deadline, _ = ctx.Deadline()
	close(b.first)
	<-ctx.Done()
	if b.afterCancellation != nil {
		b.afterCancellation()
	}
	b.mu.Lock()
	b.active[entry.Candidate.PathID] = true
	b.grants[entry.Candidate.PathID]++
	b.mu.Unlock()
	close(b.completed)
	return DeploymentLease{Active: true}, nil
}
func (b *queuedGrantBackend) Block(ctx context.Context, entry Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-b.completed:
	default:
		return errors.New("cleanup preceded worker completion")
	}
	deadline, ok := ctx.Deadline()
	b.cleanupDeadlineOK = ok && deadline.Equal(b.deadline)
	b.cleanupRan = true
	return b.overlapLeaseBackend.Block(ctx, entry)
}
func TestNodeLeaseOverlapAuthorityRevokesQueuedGrantButCallerCancelPreservesIt(t *testing.T) {
	for _, mode := range []string{"late_checkpoint_failure", "caller_cancellation", "late_checkpoint_failure_then_caller_cancellation"} {
		t.Run(mode, func(t *testing.T) {
			e, k, dir := nodeLeaseFixture(t)
			for i := 0; i < 2; i++ {
				if _, err := e.PrepareProtected(context.Background(), fmt.Sprint("p", i), "", true); err != nil {
					t.Fatal(err)
				}
			}
			b := &queuedGrantBackend{overlapLeaseBackend: &overlapLeaseBackend{
				fakeKernel: k.fakeKernel, active: map[string]bool{"p1": true}, grants: map[string]int{}, blocks: map[string]int{},
				started: make(chan string, 32), finished: make(chan string, 32), gates: map[string]<-chan struct{}{}, fail: map[string]error{},
			}, first: make(chan struct{}), completed: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			callerCanceledAfterAuthority := false
			if mode == "late_checkpoint_failure_then_caller_cancellation" {
				b.afterCancellation = func() {
					// Only an observed authority error cancels this child
					// renewal first. A later caller shutdown cannot undo it.
					callerCanceledAfterAuthority = true
					cancel()
				}
			}
			b.beforeCheck = func(ctx context.Context, entry Entry) error {
				if entry.Candidate.PathID != "p1" {
					return nil
				}
				select {
				case <-b.first:
				case <-ctx.Done():
					return ctx.Err()
				}
				if mode == "caller_cancellation" {
					cancel()
					return ctx.Err()
				}
				return os.Remove(filepath.Join(dir, "state.json"))
			}
			e.backend = b
			result, err := e.MaintainLeases(ctx)
			if err == nil || result.KernelReady || len(e.maintained) != 0 || b.grants["p0"] != 1 {
				t.Fatal("invalid abort or queued-grant setup", err)
			}
			if mode == "late_checkpoint_failure_then_caller_cancellation" && (!callerCanceledAfterAuthority || !errors.Is(ctx.Err(), context.Canceled)) {
				t.Fatal("fixture did not cancel the caller after authority failure")
			}
			for _, path := range result.Paths {
				if path.KernelReady || path.Lease != nil && path.Lease.Active {
					t.Fatal("aborted sweep retained readiness", path.PathID)
				}
				if mode == "caller_cancellation" {
					// The ACK completed under valid authority. An observer
					// restart must not interrupt another app sharing this gate.
					if !b.active[path.PathID] || b.blocks[path.PathID] != 0 {
						t.Fatal("caller cancellation revoked a valid shared grant", path.PathID)
					}
				} else if b.active[path.PathID] || b.blocks[path.PathID] != 1 {
					t.Fatal("authority failure retained a usable gate", path.PathID)
				}
			}
			if mode == "caller_cancellation" && b.cleanupRan {
				t.Fatal("caller cancellation started detached global revocation")
			}
			if mode != "caller_cancellation" && (!b.cleanupRan || !b.cleanupDeadlineOK) {
				t.Fatal("cleanup was canceled or given a new time budget")
			}
		})
	}
}
