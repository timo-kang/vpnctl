// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package diagnostic delivers best-effort events without putting history I/O on
// certificate, registration or discovery critical paths. It is not an audit log.
package diagnostic

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/metrics"
)

const Capacity = 64
const Attempts = 5

type Sender func(context.Context, history.Event) (retry bool, err error)

type Queue struct {
	dropped              atomic.Uint64
	mu                   sync.Mutex
	pending              chan history.Event
	states               map[string]string
	role, node, instance string
	sequence             uint64
	closed               bool
}

func New(role, node string) *Queue {
	return &Queue{pending: make(chan history.Event, Capacity), states: make(map[string]string), role: role, node: node, instance: rand.Text()}
}

// Emit copies a completed operation's outcome; it never waits for delivery.
func (q *Queue) Emit(e history.Event) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.emitLocked(e)
}

// Observe coalesces repeated states across session retries. Keys are fixed by
// producers; the small cap also prevents accidental unbounded tracking.
func (q *Queue) Observe(key string, e history.Event) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	old, exists := q.states[key]
	if exists && old == e.Current {
		return
	}
	if !exists && len(q.states) >= 16 {
		q.count("state_capacity_dropped")
		return
	}
	q.states[key] = e.Current
	e.Previous = old
	q.emitLocked(e)
}

func (q *Queue) emitLocked(e history.Event) {
	if q.closed {
		q.count("stopped_dropped")
		return
	}
	q.sequence++
	e.ID = fmt.Sprintf("%s-%020d", q.instance, q.sequence)
	e.NodeID = q.node
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
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
	metrics.DiagnosticDeliveryTotal.WithLabelValues(q.role, result).Inc()
}

// Run has one lifecycle owner. Each event gets at most five attempts (3s each)
// with 1/2/4/8s backoff. Shutdown cancels I/O and discards pending memory only.
// Callers must honor ctx; attempts reuse exactly the same ID/body.
func (q *Queue) Run(ctx context.Context, send Sender) {
	var reported uint64
	report := func() {
		if count := q.dropped.Load(); count != reported {
			slog.Warn("diagnostic timeline incomplete", "role", q.role, "producer", q.instance, "dropped", count)
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

func (q *Queue) deliver(ctx context.Context, e history.Event, send Sender) {
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
func FromContext(ctx context.Context) *Queue                   { q, _ := ctx.Value(contextKey{}).(*Queue); return q }
func Emit(ctx context.Context, e history.Event)                { FromContext(ctx).Emit(e) }
func Observe(ctx context.Context, key string, e history.Event) { FromContext(ctx).Observe(key, e) }

// Discovery records only attempted I/O, never a cache hit or canceled shutdown.
func Discovery(ctx context.Context, target string, err error) {
	if ctx.Err() == context.Canceled {
		return
	}
	state, severity := "up", "info"
	if err != nil {
		state, severity = "down", "warning"
	}
	Observe(ctx, "discovery:"+target, history.Event{Kind: "discovery_error", Source: "node-discovery", Target: target, Current: state, Severity: severity, Validity: "observed"})
}
