// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

var errTargetObservationOwnership = errors.New("target observation ownership changed")

// A process-local, one-use observation ticket. It carries no grant to renew a
// lease or change routes. The coordinator closes the old Engine AND Store, then
// acquires fresh ownership within this ticket's original context deadline.
type targetProbeHandoff struct {
	attempt                                        *targetProbeAttempt
	scope                                          *relaycache.ObservationScope
	approval                                       relaycache.ApprovalWitness
	targetDigest, preparationDigest, catalogDigest [32]byte
	startedBoot, untilBoot                         time.Duration
	clock                                          func() (time.Duration, error)
	cancel                                         context.CancelFunc
}

// TargetObservationOwnership releases and reacquires every process-wide
// resource which serializes this node. Reacquire must load a new Store and
// journal. It must honor ctx and return an Engine that the caller owns and
// closes. Errors leave the prior Engine closed when Release succeeded.
type TargetObservationOwnership interface {
	Release(ctx context.Context, engine *Engine) error
	Reacquire(ctx context.Context) (*Engine, error)
}

func preparationDigest(e *Engine, path string) [32]byte {
	var intent *PreparationIntent
	if i := e.preparationIndex(path); i >= 0 {
		intent = &e.journal.Preparations[i]
	}
	data, _ := json.Marshal(intent)
	return sha256.Sum256(data)
}

func (e *Engine) handoffCatalogDigest() ([32]byte, bool) {
	r, err := e.cache.Status()
	if err != nil || !r.UsableCache || r.Catalog == nil {
		return [32]byte{}, false
	}
	data, err := json.Marshal(r.Catalog)
	return sha256.Sum256(data), err == nil
}

func (e *Engine) prepareTargetProbeHandoff(parent context.Context, entry Entry, target relaycatalog.Target, timeout time.Duration, out TargetObservation, clock func() (time.Duration, error)) (*targetProbeHandoff, TargetObservation) {
	fail := func(reason string) (*targetProbeHandoff, TargetObservation) { return nil, unknownProbe(out, reason) }
	start, err := clock()
	if err != nil || start < 0 {
		return fail("observation_clock_unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, targetObservationWaveDuration)
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining <= 0 || start > time.Duration(1<<63-1)-remaining {
		cancel()
		return fail("observation_deadline")
	}
	h := &targetProbeHandoff{clock: clock, startedBoot: start, untilBoot: start + remaining, cancel: cancel}
	ok := false
	defer func() {
		if !ok {
			h.Close()
		}
	}()
	if e.closed || e.uncertain || entry.LeaseVersion != 3 || entry.ProbeScope != 1 {
		return fail("handoff_ownership_unavailable")
	}
	i := e.targetIndex(target.ID)
	if i < 0 {
		return fail("target_changed_during_probe")
	}
	g := e.journal.Targets[i]
	if g.RouteRevision == ^uint64(0) || (g.Phase != "guarded" && g.Phase != "active") {
		return fail("target_changed_during_probe")
	}
	h.targetDigest = targetGuardDigest(g)
	allowed, err := e.preparationAllowed(entry.Candidate.PathID)
	if err != nil || !allowed {
		return fail("preparation_consent_unavailable")
	}
	h.preparationDigest = preparationDigest(e, entry.Candidate.PathID)
	var valid bool
	h.catalogDigest, valid = e.handoffCatalogDigest()
	if !valid {
		return fail("approval_expired_or_changed")
	}
	h.approval, _, _, err = e.cache.LeaseApproval() // Never transfer transient rearm proof.
	if err != nil {
		return fail("approval_expired_or_changed")
	}
	h.scope, err = e.cache.PinObservationScope()
	if err != nil {
		return fail("handoff_ownership_unavailable")
	}
	var failure TargetObservation
	h.attempt, failure = e.prepareTargetProbe(ctx, entry, target, timeout, out)
	if h.attempt == nil {
		return nil, failure
	}
	if h.attempt.observation.UnderlayGeneration == "" {
		return fail("underlay_events_unavailable")
	}
	if !h.withinLifetime() {
		return fail("observation_deadline")
	}
	ok = true
	return h, TargetObservation{}
}

func (h *targetProbeHandoff) withinLifetime() bool {
	if h.attempt.ctx.Err() != nil {
		return false
	}
	now, err := h.clock()
	return err == nil && now >= h.startedBoot && now < h.untilBoot
}

func (h *targetProbeHandoff) run(probe func(context.Context, Entry, relaycatalog.Target) (targetProof, error)) {
	if h == nil || h.attempt == nil {
		return
	}
	// The worker still touches no Engine/Store state. It may be launched while
	// the coordinator owns the locks, then continue after ownership is returned.
	if !h.withinLifetime() {
		h.Close()
		return
	}
	h.attempt.run(probe)
}
func (h *targetProbeHandoff) discard(reason string) TargetObservation {
	if h == nil || h.attempt == nil {
		return unknownProbe(TargetObservation{}, "probe_attempt_unavailable")
	}
	return h.attempt.discard(reason)
}
func (h *targetProbeHandoff) Close() {
	if h == nil {
		return
	}
	if h.attempt != nil {
		h.attempt.state.Swap(3)
	}
	if h.cancel != nil {
		h.cancel()
	}
	h.scope.Close()
}

// Reject changed ownership before checkLease, whose failure may block a lease.
func (h *targetProbeHandoff) matches(e *Engine) bool {
	a := h.attempt
	if e == nil || e == a.owner || !a.owner.closed || e.closed || e.uncertain || a.node != e.journal.Node || a.domain != e.journal.Domain || !h.scope.Matches(e.cache) {
		return false
	}
	i := e.index(a.entry.Candidate.PathID)
	if i < 0 || entryFingerprint(e.journal.Entries[i]) != a.observation.Fingerprint {
		return false
	}
	j := e.targetIndex(a.target.ID)
	if j < 0 || e.journal.Targets[j].RouteRevision == ^uint64(0) || targetGuardDigest(e.journal.Targets[j]) != h.targetDigest {
		return false
	}
	allowed, err := e.preparationAllowed(a.entry.Candidate.PathID)
	if err != nil || !allowed || preparationDigest(e, a.entry.Candidate.PathID) != h.preparationDigest {
		return false
	}
	digest, ok := e.handoffCatalogDigest()
	if !ok || digest != h.catalogDigest {
		return false
	}
	w, _, _, err := e.cache.LeaseApproval()
	return err == nil && w == h.approval
}

func (e *Engine) finishTargetProbeHandoff(caller context.Context, h *targetProbeHandoff) TargetObservation {
	if h == nil {
		return unknownProbe(TargetObservation{}, "probe_attempt_unavailable")
	}
	defer h.Close()
	if h.attempt == nil || h.attempt.state.Swap(3) != 2 {
		return unknownProbe(TargetObservation{}, "probe_attempt_unavailable")
	}
	a := h.attempt
	fail := func(reason string) TargetObservation { return unknownProbe(a.observation, reason) }
	if caller.Err() != nil || !h.withinLifetime() {
		return fail("observation_deadline")
	}
	if !h.matches(e) {
		return fail("handoff_ownership_changed")
	}
	// Keep the original monitor and its generation history. A caller cannot
	// replace a lost/restarted stream with a new provider reporting the same ID.
	ctx, cancel := context.WithCancel(a.ctx)
	stop := context.AfterFunc(caller, cancel)
	defer func() { stop(); cancel() }()
	if deadline, ok := caller.Deadline(); ok {
		var done context.CancelFunc
		ctx, done = context.WithDeadline(ctx, deadline)
		defer done()
	}
	generation, err := relayobserve.UnderlayGeneration(ctx, a.entry.Candidate.UnderlayID)
	if err != nil || generation == "" {
		return fail("underlay_events_unavailable")
	}
	if generation != a.observation.UnderlayGeneration {
		return fail("underlay_changed_during_probe")
	}
	if !h.withinLifetime() {
		return fail("observation_deadline")
	}
	out := e.finishTargetProbeEvidence(ctx, a)
	if caller.Err() != nil || !h.withinLifetime() {
		return fail("observation_deadline")
	}
	return out
}
