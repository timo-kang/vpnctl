// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package observation delivers bounded, best-effort probe history off the
// heartbeat, credential and route-control paths. It is not a durable spool.
package observation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

type Sender func(context.Context, history.Observation) (retry bool, err error)

type Queue struct {
	dropped atomic.Uint64
	mu      sync.Mutex
	pending chan history.Observation
	closed  bool
}

func New() *Queue { return &Queue{pending: make(chan history.Observation, Capacity)} }

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
	select {
	case q.pending <- e:
		q.count("queued")
	default:
		q.count("overflow_dropped")
	}
}

func (q *Queue) count(result string) {
	if strings.HasSuffix(result, "_dropped") {
		q.dropped.Add(1)
	}
	metrics.ProbeHistoryDeliveryTotal.WithLabelValues(result).Inc()
}

// Run has one lifecycle owner. Each observation gets at most five attempts (3s each)
// with 1/2/4/8s backoff. Shutdown cancels I/O and discards pending memory only.
// Callers must honor ctx; attempts reuse exactly the same ID/body.
func (q *Queue) Run(ctx context.Context, send Sender) {
	var reported uint64
	report := func() {
		if count := q.dropped.Load(); count != reported {
			slog.Warn("probe history incomplete", "dropped", count)
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
		for {
			select {
			case <-q.pending:
				q.count("shutdown_dropped")
			default:
				return
			}
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report()
		case e := <-q.pending:
			q.deliver(ctx, e, send)
		}
	}
}

func (q *Queue) deliver(ctx context.Context, e history.Observation, send Sender) {
	for attempt := 0; attempt < Attempts; attempt++ {
		if ctx.Err() != nil {
			q.count("shutdown_dropped")
			return
		}
		work, cancel := context.WithTimeout(ctx, 3*time.Second)
		retry, err := send(work, e)
		cancel()
		if err == nil {
			q.count("delivered")
			return
		}
		if ctx.Err() != nil {
			q.count("shutdown_dropped")
			return
		}
		if !retry {
			q.count("rejected_dropped")
			return
		}
		if attempt == Attempts-1 {
			q.count("exhausted_dropped")
			return
		}
		q.count("retry")
		timer := time.NewTimer(time.Second << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			q.count("shutdown_dropped")
			return
		case <-timer.C:
		}
	}
}

type contextKey struct{}

func WithQueue(ctx context.Context, q *Queue) context.Context {
	return context.WithValue(ctx, contextKey{}, q)
}
func FromContext(ctx context.Context) *Queue          { q, _ := ctx.Value(contextKey{}).(*Queue); return q }
func Emit(ctx context.Context, o history.Observation) { FromContext(ctx).Emit(o) }
