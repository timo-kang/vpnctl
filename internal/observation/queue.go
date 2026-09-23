// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package observation delivers bounded, best-effort probe history off the
// heartbeat, credential and route-control paths. It is not a durable spool.
package observation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/metrics"
)

const Capacity = 256
const Attempts = 5

// ErrQuotaRejected marks an explicit logical quota rejection from the server,
// not a transient transport, WAL or storage failure.
var ErrQuotaRejected = errors.New("probe history quota rejected")

type Sender func(context.Context, history.Observation) (retry bool, err error)

type delivery struct {
	e        history.Observation
	attempts int
	ready    time.Time
}

type Queue struct {
	dropped      atomic.Uint64
	quotaDropped atomic.Uint64
	mu           sync.Mutex
	pending      []delivery
	outstanding  int // includes the single in-flight attempt and delayed retries
	wake         chan struct{}
	closed       bool
}

func New() *Queue { return &Queue{wake: make(chan struct{}, 1)} }

// Emit copies a completed operation's outcome; it never waits for delivery.
func (q *Queue) Emit(e history.Observation) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.emitLocked(e)
}

func (q *Queue) emitLocked(e history.Observation) {
	if q.closed {
		q.count("stopped_dropped")
		return
	}
	if q.outstanding == Capacity {
		q.count("overflow_dropped")
		return
	}
	// 128 random bits keep IDs unique across process restarts without a clock.
	var id [16]byte
	_, _ = rand.Read(id[:])
	e.ID = base64.RawURLEncoding.EncodeToString(id[:])
	if e.Success != nil {
		v := *e.Success
		e.Success = &v
	}
	if e.RTTMs != nil {
		v := *e.RTTMs
		e.RTTMs = &v
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	e = e.Canonicalize()
	q.pending = append(q.pending, delivery{e: e})
	q.outstanding++
	q.count("queued")
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *Queue) count(result string) {
	if strings.HasSuffix(result, "_dropped") {
		q.dropped.Add(1)
	}
	if result == "quota_dropped" {
		q.quotaDropped.Add(1)
	}
	metrics.ProbeHistoryDeliveryTotal.WithLabelValues(result).Inc()
}

// Run has one lifecycle owner. Each observation gets at most five attempts (3s each)
// with 1/2/4/8s backoff. Backoff does not hold up another ready observation.
// Pending, delayed and in-flight work share one Capacity budget. Shutdown
// cancels I/O and discards pending memory only.
// Callers must honor ctx; attempts reuse exactly the same ID/body.
func (q *Queue) Run(ctx context.Context, send Sender) {
	var reported uint64
	report := func() {
		if count := q.dropped.Load(); count != reported {
			slog.Warn("probe history incomplete", "dropped", count, "quota_dropped", q.quotaDropped.Load())
			reported = count
		}
	}
	defer report()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		q.closed = true
		for range q.pending {
			q.count("shutdown_dropped")
		}
		q.pending = nil
		q.outstanding = 0
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ticker.C:
			report()
		default:
		}
		job, wait, ok := q.takeReady(time.Now())
		if ok {
			q.attempt(ctx, job, send)
			continue
		}
		var timer *time.Timer
		var ready <-chan time.Time
		if wait >= 0 {
			timer = time.NewTimer(wait)
			ready = timer.C
		}
		select {
		case <-ctx.Done():
		case <-q.wake:
		case <-ready:
		case <-ticker.C:
			report()
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// Choose the oldest ready job. Retried jobs join the tail, so neither new work
// nor an always-failing job can monopolize the worker. The bounded scan also
// avoids an unbounded per-peer map when identities/sources churn.
func (q *Queue) takeReady(now time.Time) (delivery, time.Duration, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	wait := time.Duration(-1)
	for i, job := range q.pending {
		delay := job.ready.Sub(now)
		if delay <= 0 {
			copy(q.pending[i:], q.pending[i+1:])
			q.pending[len(q.pending)-1] = delivery{}
			q.pending = q.pending[:len(q.pending)-1]
			return job, 0, true
		}
		if wait < 0 || delay < wait {
			wait = delay
		}
	}
	return delivery{}, wait, false
}

func (q *Queue) attempt(ctx context.Context, job delivery, send Sender) {
	var retry bool
	err := ctx.Err()
	if err == nil {
		work, cancel := context.WithTimeout(ctx, 3*time.Second)
		retry, err = send(work, job.e)
		cancel()
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	job.attempts++
	switch {
	case err == nil:
		q.count("delivered")
	case ctx.Err() != nil:
		q.count("shutdown_dropped")
	case errors.Is(err, ErrQuotaRejected):
		q.count("quota_dropped")
	case !retry:
		q.count("rejected_dropped")
	case job.attempts == Attempts:
		q.count("exhausted_dropped")
	default:
		q.count("retry")
		job.ready = time.Now().Add(time.Second << (job.attempts - 1))
		q.pending = append(q.pending, job)
		return
	}
	q.outstanding--
}

type contextKey struct{}

func WithQueue(ctx context.Context, q *Queue) context.Context {
	return context.WithValue(ctx, contextKey{}, q)
}
func FromContext(ctx context.Context) *Queue          { q, _ := ctx.Value(contextKey{}).(*Queue); return q }
func Emit(ctx context.Context, o history.Observation) { FromContext(ctx).Emit(o) }
