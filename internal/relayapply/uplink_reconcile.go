// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"vpnctl/internal/relayselect"
)

// ReconcileTargetObserved is the opt-in producer boundary for the local status
// API. It performs the same route reconciliation as ReconcileTarget, then
// publishes only an in-process interpretation of its committed result. Status
// failures withdraw observations; they never grant, renew or modify a route.
func (e *Engine) ReconcileTargetObserved(ctx context.Context, id, controller string, selector *relayselect.Selector, timeout time.Duration, publisher *UplinkPublisher) (TargetReconcileResult, error) {
	out, _, err := e.reconcileTargetObserved(ctx, id, controller, selector, timeout, publisher, nil)
	return out, err
}

// ReconcileTargetObservedWithHandoff preserves the producer's original clock
// stamp across ownership release and returns the Engine owned by the caller.
// The snapshot is still observation only, never authority for route changes.
func (e *Engine) ReconcileTargetObservedWithHandoff(ctx context.Context, id, controller string, selector *relayselect.Selector, timeout time.Duration, publisher *UplinkPublisher, ownership TargetObservationOwnership) (TargetReconcileResult, *Engine, error) {
	if ownership == nil {
		if publisher != nil {
			publisher.Unavailable()
		}
		return TargetReconcileResult{}, e, errors.New("target ownership handoff unavailable")
	}
	return e.reconcileTargetObserved(ctx, id, controller, selector, timeout, publisher, ownership)
}

func (e *Engine) reconcileTargetObserved(ctx context.Context, id, controller string, selector *relayselect.Selector, timeout time.Duration, publisher *UplinkPublisher, ownership TargetObservationOwnership) (TargetReconcileResult, *Engine, error) {
	if publisher == nil || publisher.target != id {
		if publisher != nil {
			publisher.Unavailable()
		}
		return TargetReconcileResult{}, e, errors.New("status publisher target mismatch")
	}
	withdrawal := publisher.withdrawal.Load()
	start, clockErr := publisher.clock()
	out, current, err := e.reconcileTarget(ctx, id, controller, selector, timeout, ownership)
	observation := statusObservation{withdrawal: withdrawal, stamp: start, maxAge: out.Selection.Policy.MaxAge}
	if clockErr == nil && ctx.Err() == nil && current != nil && !current.closed && !current.uncertain && !errors.Is(err, errTargetObservationOwnership) && start.domain == statusDomain(current.journal.Domain) {
		observation = current.uplinkObservation(out, observation)
	}
	publisher.publish(observation)
	return out, current, err
}

func (e *Engine) uplinkObservation(out TargetReconcileResult, o statusObservation) statusObservation {
	g := out.Application.Reservation
	if g != nil && g.TargetID == out.Application.TargetID && (out.Application.Guarded || out.Application.Activated) {
		if g.RouteRevision == ^uint64(0) {
			return o
		}
		// Compare an explicit journal transition and installation identity privately.
		// Never export reservation ownership or use wall time/catalog generation.
		identity := struct {
			Owner    string
			Revision uint64
			Active   *TargetRoute
		}{g.Owner, g.RouteRevision, g.Active}
		b, _ := json.Marshal(identity)
		digest := sha256.Sum256(b)
		o.routeIdentity = hex.EncodeToString(digest[:])
	}
	report, err := e.cache.Status()
	if err != nil {
		return o
	}
	if report.Validity == "expired" || report.BlockedReason == "identity_denied" {
		o.kind = statusBlocked
		// No live approval is required to report a newly read negative policy state.
		// This budget describes that observation only, never permission for traffic.
		o.maxAge = relayselect.DefaultPolicy().MaxAge
		return o
	}
	witness, _, _, err := e.cache.LeaseApproval()
	if err != nil || !report.UsableCache || witness.Domain != e.journal.Domain || witness.Generation != out.Selection.Generation || witness.Controller != out.Selection.ControllerID || witness.Node != out.Selection.NodeID {
		return o
	}
	o.approvalUntil = witness.UntilBootNS
	proof := out.Application.Proof
	if out.Applied && out.Application.Activated && out.Application.State == "active" && g != nil && g.Phase == "active" && g.Active != nil && g.Pending == nil && g.RouteRevision > 0 && o.routeIdentity != "" && proof != nil && proof.Evidence == "unbound_tcp_connect" && proof.leaseDeadlineNS > 0 && proof.Interface == g.Active.Interface && proof.Source == g.Active.Source {
		o.kind, o.pathID, o.leaseUntil = statusReachable, g.Active.PathID, proof.leaseDeadlineNS
	} else if out.Application.Guarded && out.Selection.DesiredPathID == "" && allPermittedCandidatesUnreachable(out.Selection) {
		o.kind = statusUnreachable
	}
	return o
}

func allPermittedCandidatesUnreachable(d relayselect.Decision) bool {
	if d.SchemaVersion != 1 || len(d.Candidates) == 0 || d.Policy.Validate() != nil || !(d.State == "no_verified_path" && d.Reason == "target_connect_failed" || d.Policy.Mode == "manual" && d.State == "unavailable" && d.Reason == "manual_pin_unavailable") {
		return false
	}
	count := 0
	for _, c := range d.Candidates {
		if c.Exclusion == "manual_pin" || c.Exclusion == "cost_limit" {
			continue
		}
		if c.State != "unreachable" || c.Exclusion != c.Reason || !(c.Reason == "unreachable" || c.Reason == "timeout" || c.Reason == "refused") {
			return false
		}
		count++
	}
	return count > 0
}
