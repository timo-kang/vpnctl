// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"vpnctl/internal/metrics"
)

const adminQueueLimit = 8
const adminQueueWait = 2 * time.Second

var errAdminOverloaded = errors.New("admin mutation queue full or admission deadline exceeded; operation not started")

// Waiting administrators hold no controller state locks. Once admitted, a mutation
// finishes even if its client disconnects; callers reconcile uncertain responses.
type adminAdmission struct {
	once   sync.Once
	slots  chan struct{}
	active chan struct{}
}

func (g *adminAdmission) acquire(ctx context.Context) (func(), error) {
	start := time.Now()
	defer observeStage("admin_mutation", "admission_wait", start)
	g.once.Do(func() {
		g.slots = make(chan struct{}, adminQueueLimit+1)
		g.active = make(chan struct{}, 1)
	})
	if err := ctx.Err(); err != nil {
		metrics.AdminAdmissionTotal.WithLabelValues("canceled").Inc()
		return nil, err
	}
	select {
	case g.slots <- struct{}{}:
	default:
		metrics.AdminAdmissionTotal.WithLabelValues("overload").Inc()
		return nil, errAdminOverloaded
	}
	wait, cancel := context.WithTimeout(ctx, adminQueueWait)
	defer cancel()
	select {
	case g.active <- struct{}{}:
		// A simultaneous cancellation must not win a random select and start work.
		if wait.Err() == nil {
			metrics.AdminAdmissionTotal.WithLabelValues("accepted").Inc()
			return func() { <-g.active; <-g.slots }, nil
		}
		<-g.active
	case <-wait.Done():
	}
	<-g.slots
	if ctx.Err() != nil {
		metrics.AdminAdmissionTotal.WithLabelValues("canceled").Inc()
		return nil, ctx.Err()
	}
	metrics.AdminAdmissionTotal.WithLabelValues("overload").Inc()
	return nil, errAdminOverloaded
}
