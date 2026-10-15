// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

// Private, one-use evidence for the current ownership lifetime only. It cannot
// be serialized as authority or resumed by a new Engine. Cross-Engine use requires the separate
// targetProbeHandoff identity and lifetime contract.
type targetProbeAttempt struct {
	owner        *Engine
	node, domain string
	ctx          context.Context
	entry        Entry
	target       relaycatalog.Target
	timeout      time.Duration
	observation  TargetObservation
	state        atomic.Uint32 // prepared=0, running=1, completed=2, consumed=3
	proof        targetProof
	err          error
	floor        time.Duration
	clockErr     error
}

func cloneProbeEntry(entry Entry) Entry {
	if entry.Candidate.Pin != nil {
		pin := *entry.Candidate.Pin
		entry.Candidate.Pin = &pin
	}
	entry.Candidate.Targets = slices.Clone(entry.Candidate.Targets)
	for i := range entry.Candidate.Targets {
		entry.Candidate.Targets[i] = cloneProbeTarget(entry.Candidate.Targets[i])
	}
	return entry
}
func cloneProbeTarget(target relaycatalog.Target) relaycatalog.Target {
	target.Prefixes = slices.Clone(target.Prefixes)
	return target
}
func unknownProbe(out TargetObservation, reason string) TargetObservation {
	out.State, out.Reason = "unknown", reason
	out.ConnectTime, out.Handshake, out.RXDelta, out.TXDelta = 0, 0, 0, 0
	if out.ObservedAt.IsZero() {
		out.ObservedAt = time.Now()
	}
	return out
}
func (a *targetProbeAttempt) current(e *Engine) bool {
	if a == nil || a.owner != e || e.closed || e.uncertain || a.node != e.journal.Node || a.domain != e.journal.Domain {
		return false
	}
	i := e.index(a.entry.Candidate.PathID)
	return i >= 0 && entryFingerprint(e.journal.Entries[i]) == a.observation.Fingerprint
}

func (e *Engine) prepareTargetProbe(ctx context.Context, entry Entry, target relaycatalog.Target, timeout time.Duration, out TargetObservation) (*targetProbeAttempt, TargetObservation) {
	entry = cloneProbeEntry(entry)
	out.ObservedAt = time.Time{}
	fail := func(reason string) (*targetProbeAttempt, TargetObservation) { return nil, unknownProbe(out, reason) }
	generation, err := relayobserve.UnderlayGeneration(ctx, entry.Candidate.UnderlayID)
	if err != nil {
		return fail("underlay_events_unavailable")
	}
	out.UnderlayGeneration = generation
	if !entry.ProbeRouting {
		return fail("probe_routing_not_prepared")
	}
	if entry.Phase != "prepared" {
		return fail("pending_journal")
	}
	out.Fingerprint = entryFingerprint(entry)
	a := &targetProbeAttempt{owner: e, node: e.journal.Node, domain: e.journal.Domain, ctx: ctx, entry: entry, target: cloneProbeTarget(target), timeout: timeout, observation: out}
	// Identity precedes checkLease, whose rejection can block a kernel lease.
	if !a.current(e) {
		return fail("candidate_changed_before_probe")
	}
	if !slices.ContainsFunc(entry.Candidate.Targets, func(approved relaycatalog.Target) bool { return reflect.DeepEqual(approved, a.target) }) {
		return fail("target_definition_changed")
	}
	if e.stillApproved(entry) != nil {
		return fail("approval_expired_or_changed")
	}
	if _, err := e.checkLease(ctx, entry); err != nil {
		return fail("lease_inactive")
	}
	ready, err := e.targetProbeChecker(ctx)(ctx, entry, false)
	if err != nil || !ready {
		return fail("kernel_conflict_or_unavailable")
	}
	if inventoryMatches(ctx, entry, e.underlays, e.collector) != nil {
		return fail("inventory_changed")
	}
	return a, TargetObservation{}
}

// The worker touches only its copied inputs, context and result. No Engine,
// cache, journal or lease mutation is used while the socket proof runs.
func (a *targetProbeAttempt) run(probe func(context.Context, Entry, relaycatalog.Target) (targetProof, error)) {
	if a == nil || a.ctx == nil || !a.state.CompareAndSwap(0, 1) {
		return
	}
	ctx, done := relayobserve.Phase(a.ctx, "probe")
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	a.proof, a.err = probe(ctx, cloneProbeEntry(a.entry), cloneProbeTarget(a.target))
	a.observation.ObservedAt = time.Now()
	cancel()
	done()
	if _, shared := a.ctx.Value(observationCheckerKey{}).(ownedObservationChecker); shared {
		a.floor, a.clockErr = leaseBootTime()
	}
	a.state.CompareAndSwap(1, 2) // An early consumer permanently invalidates the attempt.
}

// A canceled gate owns no Engine state. Drain its completed result without
// reading the journal or invoking any checker that another worker may own.
func (a *targetProbeAttempt) discard(reason string) TargetObservation {
	if a == nil || a.state.Swap(3) != 2 {
		return unknownProbe(TargetObservation{}, "probe_attempt_unavailable")
	}
	return unknownProbe(a.observation, reason)
}

func (e *Engine) finishTargetProbe(ctx context.Context, a *targetProbeAttempt) TargetObservation {
	if a == nil || a.state.Swap(3) != 2 {
		return unknownProbe(TargetObservation{}, "probe_attempt_unavailable")
	}
	out := a.observation
	fail := func(reason string) TargetObservation { return unknownProbe(out, reason) }
	if !a.current(e) {
		return fail("candidate_changed_during_probe")
	}
	return e.finishTargetProbeEvidence(ctx, a)
}

// Caller has consumed the attempt and validated its ownership contract.
func (e *Engine) finishTargetProbeEvidence(ctx context.Context, a *targetProbeAttempt) TargetObservation {
	out := a.observation
	fail := func(reason string) TargetObservation { return unknownProbe(out, reason) }
	if a.ctx.Err() != nil || ctx.Err() != nil {
		return fail("observation_deadline")
	}
	if a.clockErr != nil {
		return fail("observation_clock_unavailable")
	}
	// The caller supplies phase attribution, never a replacement lifetime.
	// Preserve the original deadline and cancellation while checking fresh state.
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.ctx, cancel)
	defer func() { stop(); cancel() }()
	if deadline, ok := a.ctx.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithDeadline(ctx, deadline)
		defer cancelDeadline()
	}
	ctx = context.WithValue(ctx, observationFloorKey{}, a.floor)
	entry := a.entry
	ready, err := e.targetProbeChecker(ctx)(ctx, entry, false)
	if err != nil || !ready {
		return fail("kernel_changed_during_probe")
	}
	if inventoryMatches(ctx, entry, e.underlays, e.collector) != nil {
		return fail("inventory_changed")
	}
	if e.stillApproved(entry) != nil {
		return fail("approval_expired_or_changed")
	}
	if a.ctx.Err() != nil || ctx.Err() != nil {
		return fail("observation_deadline")
	}
	if _, err := e.checkLease(ctx, entry); err != nil {
		return fail("lease_expired_during_probe")
	}
	current, err := relayobserve.UnderlayGeneration(ctx, entry.Candidate.UnderlayID)
	if err != nil {
		return fail("underlay_events_unavailable")
	}
	if current != out.UnderlayGeneration {
		return fail("underlay_changed_during_probe")
	}
	if a.ctx.Err() != nil || ctx.Err() != nil {
		return fail("observation_deadline")
	}
	if a.err != nil {
		var failure *targetConnectError
		if errors.As(a.err, &failure) {
			out.State, out.Reason = "unreachable", failure.reason
			return out
		}
		return fail("probe_evidence_unavailable")
	}
	out.ConnectTime, out.Handshake, out.RXDelta, out.TXDelta = a.proof.duration, a.proof.handshake, a.proof.rx, a.proof.tx
	out.State, out.Reason = "reachable", "tcp_connect_verified"
	return out
}
