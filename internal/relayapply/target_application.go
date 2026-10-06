// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

const TargetApplyDuration = 5 * time.Second

// TargetRoute is the exact owned route tuple, not reusable approval or health.
type TargetRoute struct {
	PathID    string `json:"path_id"`
	Interface string `json:"interface"`
	Source    string `json:"source"`
	LinkIndex uint32 `json:"link_index"`
	Alias     string `json:"alias"`
}
type ApplicationProof struct {
	Evidence    string        `json:"evidence"`
	Interface   string        `json:"interface"`
	Source      string        `json:"source"`
	ObservedAt  time.Time     `json:"observed_at"`
	ConnectTime time.Duration `json:"connect_time_ns"`
}
type TargetReconcileResult struct {
	SchemaVersion int                       `json:"schema_version"`
	StartedAt     time.Time                 `json:"started_at"`
	FinishedAt    time.Time                 `json:"finished_at"`
	Applied       bool                      `json:"applied"`
	Selection     relayselect.Decision      `json:"selection"`
	Application   TargetGuardResult         `json:"application"`
	Diagnostics   *relayobserve.Diagnostics `json:"diagnostics,omitempty"`
}

func routeForEntry(e Entry) *TargetRoute {
	return &TargetRoute{e.Candidate.PathID, e.Candidate.Pin.WGInterface, strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), e.LinkIndex, e.Alias}
}
func sameTargetRoute(a, b *TargetRoute) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func validateTargetPhase(g TargetGuard) error {
	if g.ApplicationVersion < 0 || g.ApplicationVersion > 1 || (g.Active != nil || g.Pending != nil) && g.ApplicationVersion != 1 {
		return ErrConflict
	}
	for _, r := range []*TargetRoute{g.Active, g.Pending} {
		if r == nil {
			continue
		}
		ip, err := netip.ParseAddr(r.Source)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.String() != r.Source || !validGuardID(r.PathID) || len(r.Interface) != 14 || !strings.HasPrefix(r.Interface, "vr") || r.LinkIndex < 100000 || r.LinkIndex > 0x3fffffff+100000 || len(r.Alias) != 39 || !strings.HasPrefix(r.Alias, "vpnctl:") {
			return ErrConflict
		}
		if _, err := hex.DecodeString(r.Interface[2:]); err != nil {
			return err
		}
		if _, err := hex.DecodeString(r.Alias[7:]); err != nil {
			return err
		}
	}
	switch g.Phase {
	case "reserving", "guarded":
		if g.Active != nil || g.Pending != nil {
			return ErrConflict
		}
	case "active":
		if g.Active == nil || g.Pending != nil || g.VerifiedAt == nil || g.VerifiedAt.IsZero() || g.ChangedAt == nil || g.ChangedAt.IsZero() {
			return ErrConflict
		}
	case "switching":
		if g.Active == nil && g.Pending == nil {
			return ErrConflict
		}
	case "releasing":
	default:
		return ErrConflict
	}
	return nil
}
func targetReferences(g TargetGuard, path string) bool {
	return g.Active != nil && g.Active.PathID == path || g.Pending != nil && g.Pending.PathID == path
}
func (e *Engine) pendingTargetReferences(path string) bool {
	for _, g := range e.journal.Targets {
		if g.Phase != "active" && targetReferences(g, path) {
			return true
		}
	}
	return false
}
func (e *Engine) approvedTarget(g TargetGuard) (relaycatalog.Target, error) {
	r, err := e.cache.Status()
	if err != nil || !r.UsableCache || r.Catalog == nil || r.ControllerID != g.Controller || r.NodeID != g.Node || r.Catalog.Validate(g.Node, time.Now()) != nil {
		return relaycatalog.Target{}, errors.Join(ErrLeaseExpired, err)
	}
	for _, t := range r.Catalog.Spec.Targets {
		prefixes := slices.Clone(t.Prefixes)
		slices.Sort(prefixes)
		if t.ID == g.TargetID && slices.Equal(prefixes, g.Prefixes) {
			return t, nil
		}
	}
	return relaycatalog.Target{}, ErrConflict
}

// targetEntry checks the journal/approval relationship only. Every caller must
// additionally verify the live inventory, kernel and lease before using it.
func (e *Engine) targetEntry(g TargetGuard, route *TargetRoute) (Entry, relaycatalog.Target, error) {
	target, err := e.approvedTarget(g)
	if err != nil || route == nil {
		return Entry{}, target, errors.Join(ErrRecovery, err)
	}
	i := e.index(route.PathID)
	if i < 0 {
		return Entry{}, target, ErrRecovery
	}
	entry := e.journal.Entries[i]
	if entry.LeaseVersion != 3 || entry.ProbeScope != 1 || !entry.ProbeRouting || entry.Phase != "prepared" || !sameTargetRoute(route, routeForEntry(entry)) || entry.Controller != g.Controller || entry.Node != g.Node {
		return entry, target, ErrConflict
	}
	allowed := false
	for _, t := range entry.Candidate.Targets {
		allowed = allowed || t.ID == target.ID && slices.Equal(t.Prefixes, target.Prefixes)
	}
	if !allowed {
		return entry, target, ErrConflict
	}
	return entry, target, nil
}
func (e *Engine) approvedTargetEntry(ctx context.Context, g TargetGuard, route *TargetRoute) (Entry, relaycatalog.Target, error) {
	entry, target, err := e.targetEntry(g, route)
	if err != nil {
		return entry, target, err
	}
	if err := e.stillApproved(entry); err != nil {
		return entry, target, err
	}
	if err := inventoryMatches(ctx, entry, e.underlays, e.collector); err != nil {
		return entry, target, err
	}
	ready, err := e.backend.Check(ctx, entry, false)
	if err != nil || !ready {
		return entry, target, errors.Join(ErrConflict, err)
	}
	if _, err := e.checkLease(ctx, entry); err != nil {
		return entry, target, err
	}
	return entry, target, nil
}
func (e *Engine) blockTargetCandidates(ctx context.Context, g TargetGuard) error {
	b, ok := e.backend.(nodeLeaseBackend)
	if !ok {
		return ErrRecovery
	}
	var err error
	for _, entry := range e.journal.Entries {
		if targetReferences(g, entry.Candidate.PathID) {
			err = errors.Join(err, b.Block(ctx, entry))
		}
	}
	return err
}
func (e *Engine) applicationProof(ctx context.Context, g TargetGuard, route *TargetRoute) (ApplicationProof, error) {
	entry, target, err := e.approvedTargetEntry(ctx, g, route)
	if err != nil {
		return ApplicationProof{}, err
	}
	b, ok := e.targets.(targetApplicationBackend)
	if !ok {
		return ApplicationProof{}, ErrRecovery
	}
	if err := b.CheckRoutes(ctx, g, e.journal.Entries, route); err != nil {
		return ApplicationProof{}, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	probe := b.ProbeApplication
	if e.appProbe != nil {
		probe = e.appProbe
	}
	proof, err := probe(probeCtx, g, entry, target)
	cancel()
	if err != nil {
		return proof, err
	}
	if _, _, err := e.approvedTargetEntry(ctx, g, route); err != nil {
		return proof, err
	}
	if err := b.CheckRoutes(ctx, g, e.journal.Entries, route); err != nil {
		return proof, err
	}
	return proof, ctx.Err()
}
func (e *Engine) inspectActiveTarget(parent context.Context, g TargetGuard) (TargetGuardResult, error) {
	ctx, cancel := context.WithTimeout(parent, TargetApplyDuration)
	defer cancel()
	proof, err := e.applicationProof(ctx, g, g.Active)
	if err != nil {
		return e.targetFailure(g.TargetID, "active_path_unverified", err)
	}
	out := e.targetResult(g.TargetID, "active", "unbound_tcp_connect_verified")
	out.Activated, out.Proof = true, &proof
	return out, nil
}

// quarantineTarget never removes the reservation or repairs foreign state.
// An interrupted switch is recovered closed, without replaying old observations.
func (e *Engine) quarantineTarget(parent context.Context, id string) (TargetGuardResult, error) {
	parent, done := relayobserve.Phase(parent, "quarantine")
	defer done()
	i := e.targetIndex(id)
	if i < 0 {
		return e.targetFailure(id, "target_not_owned", ErrConflict)
	}
	g := e.journal.Targets[i]
	if g.Active == nil && g.Pending == nil {
		return e.InspectTarget(parent, id)
	}
	ctx, cancel := context.WithTimeout(parent, TargetApplyDuration)
	defer cancel()
	b, ok := e.targets.(targetApplicationBackend)
	if !ok {
		return e.targetFailure(id, "application_backend_unavailable", ErrRecovery)
	}
	g.Phase = "switching"
	e.journal.Targets[i] = g
	if err := e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed", errors.Join(err, e.blockTargetCandidates(ctx, g)))
	}
	if err := b.SetRoutes(ctx, g, e.journal.Entries, nil); err != nil {
		return e.targetFailure(id, "target_quarantine_conflict", errors.Join(err, e.blockTargetCandidates(ctx, g)))
	}
	g.Active, g.Pending, g.VerifiedAt = nil, nil, nil
	at := time.Now()
	g.ChangedAt = &at
	g.Phase = "guarded"
	e.journal.Targets[i] = g
	if err := e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed", err)
	}
	return e.InspectTarget(ctx, id)
}

// ReconcileTarget obtains and consumes observations under this engine's shared
// cache/namespace ownership. No API accepts serialized decisions as authority.
func (e *Engine) ReconcileTarget(parent context.Context, id, controller string, selector *relayselect.Selector, timeout time.Duration) (out TargetReconcileResult, err error) {
	parent, recorder := relayobserve.Start(parent)
	defer func() { out.Diagnostics = recorder.Snapshot() }()
	out = TargetReconcileResult{SchemaVersion: 1, StartedAt: time.Now(), Application: e.targetResult(id, "blocked", "not_applied")}
	defer func() {
		out.FinishedAt = time.Now()
		g := out.Application.Reservation
		if selector != nil && out.Application.Activated && g != nil && g.Active != nil && g.ChangedAt != nil {
			selector.RecordApplied(g.Active.PathID, *g.ChangedAt)
		} else if selector != nil && out.Application.Guarded {
			selector.RecordApplied("", out.FinishedAt)
		}
	}()
	if e.uncertain || selector == nil {
		return out, relaycache.ErrUncertain
	}
	i := e.targetIndex(id)
	if i < 0 || controller != "" && e.journal.Targets[i].Controller != controller {
		return out, ErrConflict
	}
	g := e.journal.Targets[i]
	if g.Phase == "switching" {
		out.Application, err = e.quarantineTarget(parent, id)
		return out, errors.Join(ErrRecovery, err)
	}
	if g.Phase != "guarded" && g.Phase != "active" {
		return out, ErrRecovery
	}
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()
	report, _ := e.ObserveTarget(ctx, id, controller, timeout)
	for j := range report.Paths {
		k := e.index(report.Paths[j].PathID)
		if k >= 0 && (e.journal.Entries[k].LeaseVersion != 3 || e.journal.Entries[k].ProbeScope != 1) {
			report.Paths[j].State, report.Paths[j].Reason = "unknown", "application_preparation_required"
		}
	}
	out.Selection = selector.Decide(report)
	if out.Selection.DesiredPathID == "" {
		out.Application, err = e.quarantineTarget(ctx, id)
		return out, errors.Join(out.Selection.Error(), err)
	}
	// The bounded observation wave already maintained every lease. Repeating
	// the full sweep here can starve another target's freshness window. Apply
	// still rechecks current approval, live lease, inventory and kernel state;
	// an expired lease cannot be rearmed by a successful observation.
	if e.uncertain {
		return out, relaycache.ErrUncertain
	}
	k := e.index(out.Selection.DesiredPathID)
	if k < 0 {
		return out, ErrRecovery
	}
	desired := routeForEntry(e.journal.Entries[k])
	applyCtx, stop := context.WithTimeout(ctx, TargetApplyDuration)
	out.Application, err = e.applyTarget(applyCtx, g, desired, out.Selection, timeout)
	stop()
	if err != nil && !e.uncertain && e.targetIndex(id) >= 0 && e.journal.Targets[i].Phase == "switching" {
		// A bounded, fresh rollback is permitted only by this cycle's policy.
		recovery, done := context.WithTimeout(context.WithoutCancel(parent), TargetApplyDuration)
		out.Application, err = e.rollbackTarget(recovery, g, out.Selection, timeout, err)
		done()
	} else if err != nil && !out.Application.Activated {
		recovery, done := context.WithTimeout(context.WithoutCancel(parent), TargetApplyDuration)
		if e.uncertain {
			err = errors.Join(err, e.blockTargetCandidates(recovery, e.journal.Targets[i]))
		} else {
			var cleanupErr error
			out.Application, cleanupErr = e.quarantineTarget(recovery, id)
			err = errors.Join(err, cleanupErr)
		}
		done()
	}
	out.Applied = err == nil && out.Application.Activated
	return out, err
}
func (e *Engine) verifyTargetChoice(ctx context.Context, g TargetGuard, route *TargetRoute, d relayselect.Decision, timeout time.Duration) (Entry, error) {
	// observePrepared below checks live approval/lease/kernel/inventory both
	// before and after its fresh TCP proof. Do not repeat a third full precheck.
	entry, target, err := e.targetEntry(g, route)
	if err != nil {
		return entry, err
	}
	if entry.Generation != d.Generation || d.ControllerID != entry.Controller || d.NodeID != entry.Node || d.TargetID != g.TargetID || !time.Now().Before(d.ValidUntil) {
		return entry, ErrLeaseExpired
	}
	proof := e.observePrepared(ctx, entry, target, timeout, TargetObservation{PathID: route.PathID}, e.candidateProbe())
	if proof.State != "reachable" {
		return entry, errors.New("candidate revalidation failed: " + proof.Reason)
	}
	for _, c := range d.Candidates {
		if c.PathID == route.PathID && c.Eligible && c.Fingerprint == proof.Fingerprint {
			return entry, nil
		}
	}
	return entry, errors.New("candidate decision changed before application")
}
func (e *Engine) applyTarget(ctx context.Context, old TargetGuard, desired *TargetRoute, d relayselect.Decision, timeout time.Duration) (TargetGuardResult, error) {
	ctx, done := relayobserve.Phase(ctx, "apply")
	defer done()
	id := old.TargetID
	b, ok := e.targets.(targetApplicationBackend)
	if !ok {
		return e.targetFailure(id, "application_backend_unavailable", ErrRecovery)
	}
	for _, entry := range e.journal.Entries {
		if entry.ProbeRouting && entry.ProbeScope != 1 && guardPrefixesOverlap(old.Prefixes, prefixes(entry)) {
			return e.targetFailure(id, "source_only_probe_bypass", ErrConflict)
		}
	}
	entry, err := e.verifyTargetChoice(ctx, old, desired, d, timeout)
	if err != nil {
		return e.targetFailure(id, "candidate_revalidation_failed", err)
	}
	if err := b.CheckRoutes(ctx, old, e.journal.Entries, old.Active); err != nil {
		return e.targetFailure(id, "target_kernel_conflict", err)
	}
	g := old
	changed := !sameTargetRoute(old.Active, desired)
	if changed {
		g.Phase, g.Pending, g.ApplicationVersion = "switching", desired, 1
		e.journal.Targets[e.targetIndex(id)] = g
		if err := e.persist(); err != nil {
			return e.targetFailure(id, "journal_save_failed", err)
		}
		if err := b.SetRoutes(ctx, g, e.journal.Entries, desired); err != nil {
			return e.targetFailure(id, "target_switch_failed", err)
		}
		at := time.Now()
		g.ChangedAt = &at
	}
	proof, err := e.applicationProof(ctx, g, desired)
	if err != nil {
		return e.targetFailure(id, "application_verification_failed", err)
	}
	if !time.Now().Before(d.ValidUntil) {
		return e.targetFailure(id, "decision_expired", ErrLeaseExpired)
	}
	g.Active, g.Pending, g.Phase, g.Generation, g.VerifiedAt = desired, nil, "active", entry.Generation, &proof.ObservedAt
	e.journal.Targets[e.targetIndex(id)] = g
	if err := e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed", err)
	}
	out := e.targetResult(id, "active", "unbound_tcp_connect_verified")
	out.Activated, out.Proof = true, &proof
	return out, nil
}
func (e *Engine) rollbackTarget(ctx context.Context, old TargetGuard, d relayselect.Decision, timeout time.Duration, cause error) (TargetGuardResult, error) {
	ctx, done := relayobserve.Phase(ctx, "rollback")
	defer done()
	id := old.TargetID
	b := e.targets.(targetApplicationBackend)
	g := e.journal.Targets[e.targetIndex(id)]
	if old.Active != nil {
		entry, err := e.verifyTargetChoice(ctx, g, old.Active, d, timeout)
		if err == nil {
			err = b.SetRoutes(ctx, g, e.journal.Entries, old.Active)
		}
		if err == nil {
			proof, probeErr := e.applicationProof(ctx, g, old.Active)
			if probeErr == nil && time.Now().Before(d.ValidUntil) {
				g.Active, g.Pending, g.Phase, g.Generation, g.VerifiedAt = old.Active, nil, "active", entry.Generation, &proof.ObservedAt
				at := time.Now()
				g.ChangedAt = &at
				e.journal.Targets[e.targetIndex(id)] = g
				if err := e.persist(); err == nil {
					out := e.targetResult(id, "rolled_back", "switch_failed_valid_previous_path_restored")
					out.Activated, out.Proof = true, &proof
					return out, cause
				}
			}
		}
	}
	if e.uncertain {
		return e.targetFailure(id, "journal_save_failed", errors.Join(cause, e.blockTargetCandidates(ctx, g)))
	}
	out, err := e.quarantineTarget(ctx, id)
	return out, errors.Join(cause, err)
}
