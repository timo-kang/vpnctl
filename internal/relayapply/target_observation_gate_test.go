// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

// Cancelling a queued or already granted ticket must neither steal the live
// owner's gate nor strand a different, still-valid candidate. Whole-wave
// cancellation tests alone cannot detect a gate left permanently occupied.
func TestObservationCanceledAdmissionDoesNotStrandOtherChecks(t *testing.T) {
	for _, granted := range []bool{false, true} {
		name := "queued"
		if granted {
			name = "granted_before_wait"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				gates := newObservationGates(3)
				releaseFirst, err := gates[0].acquire(context.Background(), true)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				last := make(chan func(), 1)
				go func() {
					release, err := gates[2].acquire(context.Background(), true)
					if err != nil {
						panic(err)
					}
					last <- release
				}()
				synctest.Wait()
				if granted {
					// Dispatch grants the middle ticket before its worker arrives.
					releaseFirst()
				}
				cancel()
				releaseCancelled, err := gates[1].acquire(ctx, true)
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled ticket entered a check", err)
				}
				releaseCancelled()
				synctest.Wait()
				if !granted {
					select {
					case <-last:
						t.Fatal("cancelled waiter released another candidate's active check")
					default:
					}
					releaseFirst()
				}
				releaseLast := <-last
				releaseLast()
				// A cancelled middle candidate cannot retain the owner when the
				// final candidate proceeds to its real postproof boundary.
				releasePost, err := gates[2].acquire(context.Background(), false)
				if err != nil {
					t.Fatal(err)
				}
				releasePost()
			})
		})
	}
}

func TestObservationCanceledPostcheckDoesNotStrandVerifiedTCP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gates := newObservationGates(2)
		releaseFirst, err := gates[0].acquire(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		releaseFirst()
		releaseSecond, err := gates[1].acquire(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cancelled := make(chan error, 1)
		go func() {
			release, err := gates[0].acquire(ctx, false)
			release()
			cancelled <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-cancelled; !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled postcheck entered", err)
		}
		verified := make(chan func(), 1)
		go func() {
			release, err := gates[1].acquire(context.Background(), false)
			if err != nil {
				panic(err)
			}
			verified <- release
		}()
		synctest.Wait()
		select {
		case <-verified:
			t.Fatal("cancelled postcheck released another active check")
		default:
		}
		releaseSecond()
		releasePost := <-verified
		releasePost()
	})
}
