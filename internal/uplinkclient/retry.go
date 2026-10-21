// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"context"
	"math/rand/v2"
	"time"
)

// Each loop owns its backoff. In particular, API delivery cannot reset an
// application's payload backoff. Equal jitter avoids zero-delay busy retry.
type backoff struct{ delay time.Duration }

func (b *backoff) reset() { b.delay = 0 }
func (b *backoff) next() time.Duration {
	if b.delay == 0 {
		b.delay = 250 * time.Millisecond
	} else {
		b.delay = min(8*time.Second, b.delay*2)
	}
	return b.delay/2 + time.Duration(rand.Int64N(int64(b.delay/2)+1))
}
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Watch reconnects until cancellation, authenticating every new Unix connection.
// Only valid API records reset this loop's own backoff; application retries are
// independent. State retains an absolute observation deadline across reconnects.
func Watch(ctx context.Context, opts Options, state *State) error {
	if state == nil {
		return errTransport
	}
	var retry backoff
	for ctx.Err() == nil {
		before := state.AcceptedFrames()
		_ = Stream(ctx, opts, state)
		if state.AcceptedFrames() != before {
			retry.reset()
		}
		if err := wait(ctx, retry.next()); err != nil {
			return err
		}
	}
	return ctx.Err()
}
