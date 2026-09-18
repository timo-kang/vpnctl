// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// PKI writers queue before stateMu, never while admitted to its reader set.
// Destructive transitions take the same gate before draining requests. This
// prevents a backlog of serialized durable writes from stopping all API reads.
// The gate is not authorization: identity/trust are rechecked after admission.
type pkiAdmission struct {
	once   sync.Once
	active chan struct{}
}

func (g *pkiAdmission) acquire(ctx context.Context) (func(), error) {
	start := time.Now()
	defer observeStage("pki_writer", "admission_wait", start)
	g.once.Do(func() { g.active = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case g.active <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-g.active
			return nil, err
		}
		return func() { <-g.active }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
