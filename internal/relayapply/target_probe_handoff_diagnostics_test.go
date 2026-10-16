// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"testing"
	"time"

	"vpnctl/internal/relayobserve"
)

type countedHandoffBackend struct {
	*fakeNodeLease
	checks int
}

func (b *countedHandoffBackend) Check(ctx context.Context, entry Entry, fresh bool) (bool, error) {
	defer relayobserve.Command(ctx, false)()
	b.checks++
	return b.fakeNodeLease.Check(ctx, entry, fresh)
}

func TestReconcileHandoffAttributesFreshCommandsToPostcheck(t *testing.T) {
	e, machine, kernel, dir := appFixture(t)
	current := e
	t.Cleanup(func() {
		current.Close()
		current.cache.Close()
	})
	counted := &countedHandoffBackend{fakeNodeLease: kernel}
	owner := &testObservationOwner{dir: dir, source: e, machine: machine, kernel: kernel,
		edit: func(fresh *Engine) { fresh.backend = counted }}
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	out, fresh, _ := e.ReconcileTargetWithHandoff(ctx, "app", "", appSelector(t), time.Second, owner)
	if fresh == nil || fresh == e {
		t.Fatal("fresh owner unavailable")
	}
	current = fresh
	if out.Selection.Reason != "candidate_evidence_incomplete" || out.Applied || counted.checks == 0 || out.Diagnostics == nil {
		t.Fatal("first confirmation did not exercise fresh postchecks")
	}
	pre, post := out.Diagnostics.Phases["precheck"], out.Diagnostics.Phases["postcheck"]
	if pre.KernelCommands != 0 || post.KernelCommands != counted.checks {
		t.Fatalf("fresh commands attributed to old phase: pre=%d post=%d checks=%d", pre.KernelCommands, post.KernelCommands, counted.checks)
	}
	if post.Calls != counted.checks || post.Duration <= 0 {
		t.Fatalf("postcheck phase double counted or omitted: %+v", post)
	}
}
