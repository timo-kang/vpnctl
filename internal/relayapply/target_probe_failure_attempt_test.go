// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

func TestTargetProbeFailureAttemptDiscardPreservesCapturedDiagnostic(t *testing.T) {
	_, _, _, attempt := probeAttemptFixture(t, context.Background())
	failure := probeFailure(context.Background(), "route_after", "", errors.New("private failure")).(*targetProbeError)
	attempt.run(func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
		return targetProof{}, failure
	})
	observed := attempt.observation.ObservedAt
	// The completed attempt must own a copy, not the provider's mutable error.
	failure.failure.Cause = "permission_denied"
	out := attempt.discard("observation_deadline")
	if out.State != "unknown" || out.Reason != "observation_deadline" || observed.IsZero() || !out.ObservedAt.Equal(observed) {
		t.Fatal("discard changed the result or original proof time")
	}
	if out.ProbeFailure == nil || *out.ProbeFailure != (relayobserve.ProbeFailure{Stage: "route_after", Cause: "unavailable", ContextState: "active"}) {
		t.Fatal("discard lost or borrowed the completed probe failure")
	}
	if got := attempt.discard("observation_deadline"); got.Reason != "probe_attempt_unavailable" || got.ProbeFailure != nil {
		t.Fatal("consumed diagnostic was replayed")
	}
}

func TestTargetProbeFailureDoesNotSurviveIntoNewAttempt(t *testing.T) {
	for _, mode := range []string{"canceled_gate", "unprepared", "success"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, attempt := probeAttemptFixture(t, context.Background())
			old := TargetObservation{PathID: "p0", ProbeFailure: &relayobserve.ProbeFailure{Stage: "connect", Cause: "refused", ContextState: "active"}}
			var out TargetObservation
			switch mode {
			case "canceled_gate":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				out = e.observePrepared(ctx, attempt.entry, attempt.target, time.Second, old, func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
					t.Fatal("canceled precheck ran a probe")
					return targetProof{}, nil
				})
				if out.State != "unknown" || out.Reason != "observation_deadline" {
					t.Fatal("canceled precheck changed verdict")
				}
			case "unprepared":
				entry := attempt.entry
				entry.ProbeRouting = false
				var next *targetProbeAttempt
				next, out = e.prepareTargetProbe(context.Background(), entry, attempt.target, time.Second, old)
				if next != nil || out.Reason != "probe_routing_not_prepared" {
					t.Fatal("unprepared candidate accepted")
				}
			case "success":
				next, failed := e.prepareTargetProbe(context.Background(), attempt.entry, attempt.target, time.Second, old)
				if next == nil {
					t.Fatalf("prepare failed: %s", failed.Reason)
				}
				next.run(successfulAttempt)
				out = e.finishTargetProbe(context.Background(), next)
				if out.State != "reachable" {
					t.Fatal("fresh proof rejected")
				}
			}
			if out.ProbeFailure != nil {
				t.Fatal("previous probe failure leaked into a new attempt")
			}
			if old.ProbeFailure == nil || old.ProbeFailure.Cause != "refused" {
				t.Fatal("new attempt mutated the previous observation")
			}
		})
	}
}
