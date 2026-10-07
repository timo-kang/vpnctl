// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayplan"
)

// Rebuilding runs AFTER all candidate leases have been serviced. Fast durable
// units share one budget and the existing maintenance deadline; the count cap
// prevents an unbounded loop even when a clock or test backend does not advance.
const NodeRebuildDuration = 750 * time.Millisecond
const nodeRebuildMaxUnits = 8

var preparationID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var preparationSteps = []string{"link", "tag", "guard", "endpoint", "rule", "address", "wg", "up", "probe-targets", "probe-source"}
var preparationRemovalSteps = []string{"probe-source", "link", "rule", "endpoint", "guard", "lease", "pins", "verify"}

// PreparationIntent is local desired state, separate from installed Entries.
// Consent also has to exist in the private cache for this exact revision.
// InFlight is durable before a non-idempotent add. An interrupted add is cleaned
// up with the original owner, never replayed or adopted as a successful install.
type PreparationIntent struct {
	PathID             string                     `json:"path_id"`
	Controller         string                     `json:"controller_id"`
	Revision           string                     `json:"revision"`
	TerminalScope      relayobserve.TerminalScope `json:"terminal_scope"`
	Phase              string                     `json:"phase"`
	Step               int                        `json:"step"`
	InFlight           bool                       `json:"in_flight,omitempty"`
	Failures           int                        `json:"failures,omitempty"`
	RetryBootNS        uint64                     `json:"retry_boot_ns,omitempty"`
	Reason             string                     `json:"reason,omitempty"`
	Previous           *PreparationIdentity       `json:"previous,omitempty"`
	UnderlayGeneration string                     `json:"underlay_generation,omitempty"`
}
type PreparationIdentity struct {
	Owner      string             `json:"owner"`
	Generation uint64             `json:"approval_generation"`
	Pin        relayplan.PinInput `json:"pin"`
}
type PreparationStatus struct {
	PreparationIntent
	Enabled bool                 `json:"enabled"`
	Current *PreparationIdentity `json:"current,omitempty"`
}

func preparationIdentity(entry Entry) *PreparationIdentity {
	return &PreparationIdentity{entry.Alias, entry.Generation, *entry.Candidate.Pin}
}
func validatePreparations(j Journal) error {
	if len(j.Preparations) > maxEntries {
		return errors.New("too many preparation intents")
	}
	seen := map[string]bool{}
	for _, p := range j.Preparations {
		if !preparationID.MatchString(p.PathID) || p.Controller == "" || len(p.Controller) > 256 || len(p.Revision) != 32 || seen[p.PathID] || p.Failures < 0 || p.Failures > 6 || p.RetryBootNS > uint64(1<<63-1) || len(p.Reason) > 128 {
			return errors.New("invalid preparation intent")
		}
		if _, err := hex.DecodeString(p.Revision); err != nil {
			return errors.New("invalid preparation revision")
		}
		if p.UnderlayGeneration != "" {
			if b, err := hex.DecodeString(p.UnderlayGeneration); err != nil || len(b) != 32 {
				return errors.New("invalid preparation event generation")
			}
		}
		if p.TerminalScope.UnderlayID == "" || p.TerminalScope.Table < 100000 || p.TerminalScope.Table > 624287 || p.TerminalScope.Metric < 100000 || p.TerminalScope.Metric > 0x3fffffff+100000 {
			return errors.New("invalid preparation terminal scope")
		}
		seen[p.PathID] = true
		var entry *Entry
		for i := range j.Entries {
			if j.Entries[i].Candidate.PathID == p.PathID {
				entry = &j.Entries[i]
			}
		}
		if entry != nil && (entry.Controller != p.Controller || entry.ProbeScope != 1 || !entry.ProbeRouting || entry.LeaseVersion != 3 || p.TerminalScope != terminalScope(*entry)) {
			return errors.New("preparation identity mismatch")
		}
		switch p.Phase {
		case "waiting":
			if entry != nil || p.Step != 0 || p.InFlight {
				return errors.New("invalid waiting preparation")
			}
		case "ready":
			if entry == nil || entry.Phase != "prepared" || p.Step != 0 || p.InFlight {
				return errors.New("invalid ready preparation")
			}
		case "preparing":
			if entry == nil || entry.Phase != "preparing" || p.Step < 0 || p.Step > len(preparationSteps) {
				return errors.New("invalid preparation cursor")
			}
		case "removing":
			if entry == nil || entry.Phase != "releasing" || p.Step < 0 || p.Step >= len(preparationRemovalSteps) {
				return errors.New("invalid removal cursor")
			}
		default:
			return errors.New("invalid preparation phase")
		}
	}
	if j.RebuildCursor != "" && !seen[j.RebuildCursor] {
		return errors.New("invalid rebuild cursor")
	}
	return nil
}
func (e *Engine) preparationIndex(path string) int {
	for i, p := range e.journal.Preparations {
		if p.PathID == path {
			return i
		}
	}
	return -1
}
func (e *Engine) preparationAllowed(path string) (bool, error) {
	i := e.preparationIndex(path)
	if i < 0 {
		return true, nil
	} // Existing manual preparation stays manual.
	p := e.journal.Preparations[i]
	return e.cache.PreparationConsent(path, p.Revision)
}
func (e *Engine) preparationStatus() []PreparationStatus {
	var out []PreparationStatus
	for _, p := range e.journal.Preparations {
		allowed, err := e.preparationAllowed(p.PathID)
		s := PreparationStatus{PreparationIntent: p, Enabled: allowed && err == nil}
		if err != nil {
			s.Reason = "preparation_consent_unavailable"
		} else if !allowed {
			s.Reason = "preparation_consent_revoked"
		}
		if i := e.index(p.PathID); i >= 0 {
			s.Current = preparationIdentity(e.journal.Entries[i])
		}
		out = append(out, s)
	}
	return out
}

// RequestPreparation explicitly opts in to initially closed application
// candidates. It records desire only. supervise performs bounded kernel work.
func (e *Engine) RequestPreparation(ctx context.Context, path, controller string) (Result, error) {
	if e.uncertain {
		return failure(path, "reopen_journal_required", relaycache.ErrUncertain)
	}
	if !preparationID.MatchString(path) {
		return failure(path, "invalid_path_id", ErrConflict)
	}
	if p := e.preparationIndex(path); p >= 0 {
		intent := e.journal.Preparations[p]
		if controller != "" && controller != intent.Controller {
			return failure(path, "controller_identity_mismatch", ErrConflict)
		}
		allowed, err := e.preparationAllowed(path)
		if err != nil || !allowed {
			return failure(path, "release_disabled_preparation_first", errors.Join(ErrRecovery, err))
		}
		out := result("scheduled", path, "explicit_preparation_intent")
		out.Preparations = e.preparationStatus()
		return out, nil
	}
	if len(e.journal.Preparations) >= maxEntries {
		return failure(path, "preparation_limit", ErrRecovery)
	}
	entry, until, err := e.approval(ctx, path, controller)
	if err != nil {
		return failure(path, "approval_or_inventory_unavailable", err)
	}
	if err = e.stillApproved(entry); err != nil || !time.Now().Before(until) || ctx.Err() != nil {
		return failure(path, "approval_changed", errors.Join(ErrRecovery, err, ctx.Err()))
	}
	owner, metric, _, err := token()
	if err != nil {
		return failure(path, "intent_identity_unavailable", err)
	}
	entry.Metric = metric
	p := PreparationIntent{PathID: path, Controller: entry.Controller, Revision: owner[7:], TerminalScope: terminalScope(entry), Phase: "waiting"}
	if i := e.index(path); i >= 0 {
		old := e.journal.Entries[i]
		if old.Phase != "prepared" || old.Controller != entry.Controller || old.LeaseVersion != 3 || old.ProbeScope != 1 || !old.ProbeRouting {
			return failure(path, "release_previous_candidate_first", ErrConflict)
		}
		p.Phase = "ready" // Explicitly manage an already journaled app candidate.
		p.TerminalScope = terminalScope(old)
	}
	e.journal.Preparations = append(e.journal.Preparations, p)
	if err = e.persist(); err != nil {
		return failure(path, "journal_save_failed", err)
	}
	if err = e.cache.AllowPreparation(path, p.Revision); err != nil {
		return failure(path, "preparation_consent_save_failed", err)
	}
	out := result("scheduled", path, "explicit_preparation_intent")
	out.Preparations = e.preparationStatus()
	return out, nil
}

func (e *Engine) rebuildNow() (time.Duration, error) {
	if e.rebuildClock != nil {
		return e.rebuildClock()
	}
	return leaseBootTime()
}
func (e *Engine) rebuildFailure(i int, reason string, cause error) error {
	p := &e.journal.Preparations[i]
	p.Reason = reason
	p.Failures = min(p.Failures+1, 6)
	now, err := e.rebuildNow()
	if err == nil {
		p.RetryBootNS = uint64(now + min(time.Second<<uint(p.Failures-1), 30*time.Second))
	}
	return errors.Join(cause, err, e.persist())
}
func (e *Engine) startPreparationRemoval(i, entryIndex int, reason string) error {
	p := &e.journal.Preparations[i]
	p.Previous = preparationIdentity(e.journal.Entries[entryIndex])
	p.Phase, p.Step, p.InFlight, p.Reason = "removing", 0, false, reason
	p.RetryBootNS, p.Failures = 0, 0
	e.journal.Entries[entryIndex].StrictOwner = e.journal.Entries[entryIndex].Phase == "prepared" || e.journal.Entries[entryIndex].StrictOwner
	e.journal.Entries[entryIndex].Phase = "releasing"
	return e.persist()
}

// RebuildCandidates advances at most eight durable work units. All share one
// 750ms BOOTTIME/wall budget; each additional unit needs 500ms remaining. The
// durable round-robin cursor and backoff survive one-shot supervisors/crashes.
// This method never opens leases or application routes.
func (e *Engine) RebuildCandidates(parent context.Context) (Result, error) {
	return e.rebuildCandidates(parent, nodeRebuildMaxUnits)
}

// A one-unit call lets fault tests stop at every persisted boundary; production
// always uses the bounded entry point above.
func (e *Engine) rebuildCandidates(parent context.Context, units int) (out Result, err error) {
	parent, done := relayobserve.Phase(parent, "rebuild")
	defer done()
	out = result("idle", "", "")
	defer func() {
		e.maintained = nil
		out.Preparations = e.preparationStatus()
		if err != nil {
			out.State = "blocked"
		}
	}()
	if e.uncertain {
		return failure("", "reopen_journal_required", relaycache.ErrUncertain)
	}
	if len(e.journal.Preparations) == 0 {
		return out, nil
	}
	start, err := e.rebuildNow()
	if err != nil {
		return failure("", "boottime_unavailable", err)
	}
	ctx, cancel := context.WithTimeout(parent, NodeRebuildDuration)
	defer cancel()
	budget := func() error {
		now, err := e.rebuildNow()
		if err != nil {
			return err
		}
		if now < start || now-start >= NodeRebuildDuration {
			return context.DeadlineExceeded
		}
		return ctx.Err()
	}
	if err = budget(); err != nil {
		return failure("", "rebuild_budget_exhausted", err)
	}
	for n := 0; n < units; n++ {
		if n > 0 {
			now, clockErr := e.rebuildNow()
			if clockErr != nil {
				return out, clockErr
			}
			if err = budget(); err != nil {
				return out, err
			}
			// Do not begin another kernel operation with only a small remainder.
			// Reserve real time too: injected BOOTTIME clocks are not deadlines.
			deadline, _ := ctx.Deadline()
			if now-start > NodeRebuildDuration-500*time.Millisecond || time.Until(deadline) < 500*time.Millisecond {
				break
			}
		}
		if err = e.syncTerminalScopes(ctx); err != nil {
			return failure("", "underlay_events_unavailable", err)
		}
		unit, unitErr := e.rebuildCandidateUnit(ctx, budget)
		if unit.PathID != "" || n == 0 {
			out = unit
		}
		if unitErr != nil {
			return out, unitErr
		}
		if unit.State == "idle" || unit.State == "prepared" {
			break
		}
	}
	return out, nil
}

func (e *Engine) rebuildCandidateUnit(ctx context.Context, budget func() error) (out Result, err error) {
	ctx, done := relayobserve.Phase(ctx, "rebuild_unit")
	defer done()
	out = result("idle", "", "")
	start, err := e.rebuildNow()
	if err != nil {
		return out, err
	}
	if err = budget(); err != nil {
		return out, err
	}
	begin := e.preparationIndex(e.journal.RebuildCursor) + 1
	for n := 0; n < len(e.journal.Preparations); n++ {
		i := (begin + n) % len(e.journal.Preparations)
		p := e.journal.Preparations[i]
		allowed, consentErr := e.preparationAllowed(p.PathID)
		if p.RetryBootNS > uint64(start) || consentErr == nil && allowed && p.Phase == "ready" && e.maintained[p.PathID] {
			continue
		}
		out.PathID, out.State = p.PathID, "rebuilding"
		e.journal.RebuildCursor = p.PathID
		// Commit the scheduling cursor with this unit's durable state change,
		// failure/backoff, or pre-add InFlight marker below. A separate cursor
		// write adds an fsync without authorizing or protecting any kernel work.
		// Creation still cannot run before owner/InFlight persistence succeeds;
		// removal already has a durable, idempotently recoverable releasing state.
		if consentErr != nil {
			return out, e.rebuildFailure(i, "preparation_consent_unavailable", consentErr)
		}
		entryIndex := e.index(p.PathID)
		if !allowed {
			if entryIndex < 0 {
				e.journal.Preparations = append(e.journal.Preparations[:i], e.journal.Preparations[i+1:]...)
				e.journal.RebuildCursor = ""
				out.State, out.Reason = "disabled", "preparation_consent_revoked"
				return out, e.persist()
			}
			if p.Phase != "removing" {
				return out, e.startPreparationRemoval(i, entryIndex, "preparation_consent_revoked")
			}
		}
		if p.Phase == "removing" {
			return out, e.removePreparation(ctx, i, entryIndex, budget)
		}
		if p.InFlight {
			return out, e.startPreparationRemoval(i, entryIndex, "interrupted_prepare")
		}
		entry, until, reason, err := e.preparationApproval(ctx, p)
		if err != nil {
			return out, e.rebuildFailure(i, reason, err)
		}
		generation, err := relayobserve.UnderlayGeneration(ctx, entry.Candidate.UnderlayID)
		if err != nil {
			return out, e.rebuildFailure(i, "underlay_events_unavailable", err)
		}
		e.journal.Preparations[i].UnderlayGeneration = generation
		valid := func() error {
			if err := budget(); err != nil {
				return err
			}
			if !time.Now().Before(until) {
				return ErrRecovery
			}
			return e.stillApproved(entry)
		}
		if err = valid(); err != nil {
			return out, e.rebuildFailure(i, "approval_or_budget_changed", err)
		}
		if p.Phase == "ready" {
			old := e.journal.Entries[entryIndex]
			ready, err := e.backend.Check(ctx, old, false)
			if err != nil {
				return out, e.rebuildFailure(i, "ownership_or_kernel_unavailable", err)
			}
			if err = valid(); err != nil {
				return out, e.rebuildFailure(i, "approval_or_budget_changed", err)
			}
			if ready && reflect.DeepEqual(old.Candidate, entry.Candidate) {
				return out, e.rebuildFailure(i, "awaiting_fresh_lease", ErrLeaseExpired)
			}
			return out, e.startPreparationRemoval(i, entryIndex, "candidate_inventory_changed")
		}
		if p.Phase == "waiting" {
			if len(e.journal.Entries) >= maxEntries {
				return out, e.rebuildFailure(i, "candidate_limit", ErrRecovery)
			}
			entry.Alias, entry.Metric, entry.LinkIndex, err = token()
			if err != nil {
				return out, e.rebuildFailure(i, "preparation_identity_unavailable", err)
			}
			// Keep the exact terminal event identity across this explicit intent's
			// rebuilds, including the interval with no installed entry. Other
			// processes may drain events before reading our latest journal. A new
			// metric would make that legitimate creation look globally foreign.
			// Link alias/index still rotate, and Check(available) must prove all
			// old resources absent before any new kernel creation.
			if p.TerminalScope.Table == entry.Candidate.Pin.Table && p.TerminalScope.UnderlayID == entry.Candidate.UnderlayID {
				entry.Metric = p.TerminalScope.Metric
			}
			if err = validateEntry(entry, e.journal.Node); err != nil {
				return out, e.rebuildFailure(i, "invalid_preparation", err)
			}
			if _, err = e.backend.Check(ctx, entry, true); err != nil {
				return out, e.rebuildFailure(i, "ownership_or_kernel_unavailable", err)
			}
			if err = valid(); err != nil {
				return out, e.rebuildFailure(i, "approval_or_budget_changed", err)
			}
			e.journal.Entries = append(e.journal.Entries, entry)
			e.journal.Preparations[i].TerminalScope = terminalScope(entry)
			e.journal.Preparations[i].Phase = "preparing"
			e.journal.Preparations[i].Reason = "initially_closed_prepare"
			return out, e.persist()
		}
		old := e.journal.Entries[entryIndex]
		if !reflect.DeepEqual(old.Candidate, entry.Candidate) {
			return out, e.startPreparationRemoval(i, entryIndex, "inventory_changed_during_prepare")
		}
		old.Generation, old.ApprovalUntil, old.ApprovalBootNS = entry.Generation, entry.ApprovalUntil, entry.ApprovalBootNS
		e.journal.Entries[entryIndex] = old
		if p.Step == len(preparationSteps) {
			ready, err := e.backend.Check(ctx, old, false)
			if err == nil && !ready {
				err = ErrRecovery
			}
			if err == nil {
				err = inventoryMatches(ctx, old, e.underlays, e.collector)
			}
			if err == nil {
				err = valid()
			}
			if err != nil {
				return out, e.startPreparationRemoval(i, entryIndex, "prepare_readback_failed")
			}
			e.journal.Entries[entryIndex].Phase = "prepared"
			e.journal.Preparations[i].Phase, e.journal.Preparations[i].Step = "ready", 0
			e.journal.Preparations[i].Reason = "awaiting_fresh_lease"
			e.journal.Preparations[i].Failures, e.journal.Preparations[i].RetryBootNS = 0, 0
			out.State = "prepared"
			return out, e.persist()
		}
		e.journal.Preparations[i].InFlight = true
		if err = e.persist(); err != nil {
			return out, err
		}
		if err = valid(); err == nil {
			step := preparationSteps[p.Step]
			if step == "wg" {
				err = e.cache.WithPathKey(old.Controller, old.Generation, p.PathID, old.Candidate.PublicKey, func(key string) error { return e.backend.Step(ctx, old, step, key) })
			} else {
				err = e.backend.Step(ctx, old, step, "")
			}
		}
		if err == nil {
			err = valid()
		}
		if err != nil {
			if saveErr := e.startPreparationRemoval(i, entryIndex, "prepare_step_interrupted"); saveErr != nil {
				return out, errors.Join(err, saveErr)
			}
			return out, e.rebuildFailure(i, "prepare_step_interrupted", err)
		}
		e.journal.Preparations[i].InFlight = false
		e.journal.Preparations[i].Step++
		e.journal.Preparations[i].Failures, e.journal.Preparations[i].RetryBootNS = 0, 0
		return out, e.persist()
	}
	return out, nil
}

func terminalScope(entry Entry) relayobserve.TerminalScope {
	return relayobserve.TerminalScope{UnderlayID: entry.Candidate.UnderlayID, Table: entry.Candidate.Pin.Table, Metric: entry.Metric}
}

func (e *Engine) syncTerminalScopes(ctx context.Context) error {
	seen := map[uint32]relayobserve.TerminalScope{}
	ambiguous := map[uint32]bool{}
	add := func(scope relayobserve.TerminalScope) {
		configured := false
		for _, u := range e.underlays {
			configured = configured || u.ID == scope.UnderlayID
		}
		if !configured {
			return
		}
		if old, ok := seen[scope.Table]; ok && old != scope {
			ambiguous[scope.Table] = true
		}
		seen[scope.Table] = scope
	}
	for _, entry := range e.journal.Entries {
		add(terminalScope(entry))
	}
	// Waiting intents retain scope through the durable removal/install gap.
	// Explicit release removes the intent and therefore retires this scope.
	for _, p := range e.journal.Preparations {
		add(p.TerminalScope)
	}
	var scopes []relayobserve.TerminalScope
	for table, scope := range seen {
		// Catalog slot migration can overlap an old waiting intent with a new
		// binding. No tuple proves one underlay then: retain global invalidation,
		// but do not prevent the normal owned cleanup/replan from resolving it.
		if !ambiguous[table] {
			scopes = append(scopes, scope)
		}
	}
	return relayobserve.SetTerminalScopes(ctx, scopes)
}

func (e *Engine) preparationApproval(ctx context.Context, p PreparationIntent) (Entry, time.Time, string, error) {
	ctx, done := relayobserve.Phase(ctx, "rebuild_inventory")
	defer done()
	r, err := e.cache.Status()
	if err != nil {
		return Entry{}, time.Time{}, "approval_unavailable", err
	}
	// A work unit changes one candidate. Collect its current underlay, not
	// every unrelated network again at each durable step. Keep the complete
	// catalog: resource slots depend on the original path order. Build still
	// validates all authority/bindings, and the full configuration is checked
	// before narrowing collection. No inventory survives this work unit.
	if err := relayplan.ValidateUnderlays(e.underlays); err != nil {
		return Entry{}, time.Time{}, "inventory_unknown", err
	}
	var underlays []relayplan.Underlay
	if r.Catalog != nil {
		for _, path := range r.Catalog.Spec.Paths {
			if path.ID != p.PathID {
				continue
			}
			for _, u := range e.underlays {
				if u.ID == path.UnderlayID {
					underlays = append(underlays, u)
				}
			}
		}
	}
	plan, err := relayplan.Build(ctx, r.NodeID, p.Controller, r, underlays, e.collector)
	if err != nil {
		return Entry{}, time.Time{}, "inventory_unknown", err
	}
	for _, c := range plan.Paths {
		if c.PathID != p.PathID {
			continue
		}
		if c.State != "eligible" || c.Pin == nil {
			return Entry{}, time.Time{}, c.Reason, ErrRecovery
		}
		w, _, _, err := e.cache.LeaseApproval()
		if err != nil || w.Domain != e.journal.Domain || w.Controller != p.Controller || w.Generation != plan.Generation {
			return Entry{}, time.Time{}, "lease_approval_unavailable", errors.Join(ErrRecovery, err)
		}
		entry := Entry{Controller: p.Controller, Node: r.NodeID, Generation: plan.Generation, ApprovalUntil: w.ExpiresAt, ApprovalBootNS: w.UntilBootNS, LeaseVersion: 3, ProbeRouting: true, ProbeScope: 1, Candidate: c, Phase: "preparing"}
		return entry, plan.ValidUntil, "", nil
	}
	return Entry{}, time.Time{}, "approved_path_unavailable", ErrRecovery
}

type preparationRemover interface {
	RemoveStep(context.Context, Entry, string) error
}

func (e *Engine) removePreparation(ctx context.Context, i, entryIndex int, budget func() error) error {
	p := e.journal.Preparations[i]
	entry := e.journal.Entries[entryIndex]
	// A prepared lease is never continued once releasing is durable. Blocking
	// also protects direct callers which did not run MaintainLeases first.
	if p.Step == 0 {
		b, ok := e.backend.(nodeLeaseBackend)
		if !ok {
			return e.rebuildFailure(i, "lease_backend_unavailable", ErrRecovery)
		}
		if err := b.Block(ctx, entry); err != nil {
			return e.rebuildFailure(i, "candidate_block_failed", err)
		}
	}
	for _, g := range e.journal.Targets {
		if targetReferences(g, p.PathID) {
			_, err := e.quarantineTarget(ctx, g.TargetID)
			if err != nil {
				return e.rebuildFailure(i, "target_quarantine_required", err)
			}
			return budget() // One target only; the next admission continues here.
		}
	}
	b, ok := e.backend.(preparationRemover)
	if !ok {
		return e.rebuildFailure(i, "incremental_cleanup_unavailable", ErrRecovery)
	}
	if err := budget(); err != nil {
		return err
	}
	if err := b.RemoveStep(ctx, entry, preparationRemovalSteps[p.Step]); err != nil {
		return e.rebuildFailure(i, "owned_cleanup_conflict_or_unavailable", err)
	}
	if err := budget(); err != nil {
		return e.rebuildFailure(i, "cleanup_budget_exhausted", err)
	}
	if p.Step+1 < len(preparationRemovalSteps) {
		e.journal.Preparations[i].Step++
	} else {
		e.journal.Entries = append(e.journal.Entries[:entryIndex], e.journal.Entries[entryIndex+1:]...)
		e.journal.Preparations[i].Phase, e.journal.Preparations[i].Step = "waiting", 0
		e.journal.Preparations[i].Reason = "owned_cleanup_complete"
	}
	e.journal.Preparations[i].InFlight = false
	e.journal.Preparations[i].Failures, e.journal.Preparations[i].RetryBootNS = 0, 0
	return e.persist()
}
