// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// PKI writers queue before stateMu, never while admitted to its reader set.
// Destructive transitions take the same gate before draining requests. An admin
// need not wait for the entire renewal backlog; when both classes are waiting,
// they alternate so repeated admin work cannot starve credential maintenance.
// This is scheduling only: identity/trust are rechecked after admission.
type pkiWaiter struct {
	ready   chan struct{}
	granted bool
}
type writerAdmission struct {
	mu           sync.Mutex
	active       bool
	lastPriority bool
	normal       []*pkiWaiter
	priority     []*pkiWaiter
}

func (g *writerAdmission) acquire(ctx context.Context) (func(), error) {
	return g.admit(ctx, false, "pki_writer")
}
func (g *writerAdmission) acquirePriority(ctx context.Context) (func(), error) {
	return g.admit(ctx, true, "pki_writer")
}

// dispatchLocked preserves FIFO within each class and wakes only the next writer.
func (g *writerAdmission) dispatchLocked() {
	if g.active {
		return
	}
	priority := len(g.priority) > 0 && (len(g.normal) == 0 || !g.lastPriority)
	queue := &g.normal
	if priority {
		queue = &g.priority
	}
	if len(*queue) == 0 {
		return
	}
	next := (*queue)[0]
	(*queue)[0] = nil
	*queue = (*queue)[1:]
	next.granted = true
	g.active = true
	g.lastPriority = priority
	close(next.ready)
}
func (g *writerAdmission) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active = false
	g.dispatchLocked()
}
func (g *writerAdmission) admit(ctx context.Context, priority bool, operation string) (func(), error) {
	start := time.Now()
	defer observeStage(operation, "admission_wait", start)
	return g.wait(ctx, priority)
}
func (g *writerAdmission) wait(ctx context.Context, priority bool) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waiter := &pkiWaiter{ready: make(chan struct{})}
	g.mu.Lock()
	queue := &g.normal
	if priority {
		queue = &g.priority
	}
	*queue = append(*queue, waiter)
	g.dispatchLocked()
	g.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-waiter.ready:
	}
	g.mu.Lock()
	if err := ctx.Err(); err != nil {
		if waiter.granted {
			g.active = false
		} else {
			for i, w := range *queue {
				if w == waiter {
					copy((*queue)[i:], (*queue)[i+1:])
					(*queue)[len(*queue)-1] = nil
					*queue = (*queue)[:len(*queue)-1]
					break
				}
			}
		}
		g.dispatchLocked()
		g.mu.Unlock()
		return nil, err
	}
	g.mu.Unlock()
	return g.release, nil
}
func (s *Server) requestMayWritePKI(r *http.Request) bool {
	if s.authority == nil {
		return false
	}
	if r.Method == http.MethodPost && (r.URL.Path == "/pki/renew" || r.URL.Path == "/pki/ack") {
		return true
	}
	// Legacy first use persists certificate metadata even on a read endpoint.
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		return !s.authority.CertificateObserved(r.TLS.VerifiedChains[0][0])
	}
	return false
}

// These handlers only read committed state, or release authorization admission
// before querying history. Other handlers may wait for disk, WG or another
// writer, so drain them separately without closing admission for cheap reads.
func requestNeedsMutationDrain(r *http.Request) bool {
	switch r.URL.Path {
	case "/fleet/status", "/pki/trust", "/fleet/history", "/fleet/uplinks", "/fleet/events", "/fleet/alerts":
		return false
	default:
		return true
	}
}

// Read bounded bodies before reserving a writer or joining the mutation set.
// A slow sender must not own the certificate/registry writer while uploading.
func bufferAdmissionBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	body := http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	raw, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid or oversized request body")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return true
}
