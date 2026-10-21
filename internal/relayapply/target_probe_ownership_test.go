// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"testing"
	"time"
	"vpnctl/internal/relaycatalog"
)

// Model the boundary that a future ownership handoff must survive. Kernel
// shape alone must not let an old proof authorize a different journal owner.
func TestProbeRejectsChangedJournalBeforeLeaseSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Engine)
	}{
		{"removed", func(e *Engine) { e.journal.Entries = nil }},
		{"recreated", func(e *Engine) { e.journal.Entries[0].Alias += "-new" }},
		{"pending", func(e *Engine) { e.journal.Entries[0].Phase = "releasing" }},
		{"generation", func(e *Engine) { e.journal.Entries[0].Generation++ }},
		{"domain", func(e *Engine) { e.journal.Domain += "-new" }},
		{"node", func(e *Engine) { e.journal.Node += "-new" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, k, _ := nodeLeaseFixture(t)
			if _, err := e.PrepareProtected(context.Background(), "p0", "", true); err != nil {
				t.Fatal(err)
			}
			if _, err := e.MaintainLeases(context.Background()); err != nil {
				t.Fatal(err)
			}
			entry := e.journal.Entries[0]
			blocks := k.blocks
			called := false
			out := e.observePrepared(context.Background(), entry, entry.Candidate.Targets[0], time.Second, TargetObservation{PathID: "p0"}, func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
				called = true
				tc.change(e)
				return targetProof{handshake: 1, rx: 1, tx: 1}, nil
			})
			if !called || out.State != "unknown" || out.Reason != "candidate_changed_during_probe" {
				t.Fatalf("stale proof retained state: called=%t state=%s reason=%s", called, out.State, out.Reason)
			}
			if k.blocks != blocks || !k.active["p0"] {
				t.Fatal("stale observation changed another ownership state")
			}
		})
	}
}
