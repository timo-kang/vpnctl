// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

// TargetGuard reserves routing for locally originated IPv4 applications with mark zero.
// It deliberately installs only terminal unreachable routes, never a usable path.
// Reservations persist across approval expiry: withdrawing approval must not
// reopen a previously blocked target through the machine's default route.
type TargetGuard struct {
	Controller string   `json:"controller_id"`
	Node       string   `json:"node_id"`
	Generation uint64   `json:"generation"`
	TargetID   string   `json:"target_id"`
	Prefixes   []string `json:"prefixes"`
	Owner      string   `json:"owner"`
	Table      uint32   `json:"table"`
	Priority   uint32   `json:"priority"`
	Metric     uint32   `json:"metric"`
	Phase      string   `json:"phase"` // reserving, guarded, releasing
}

type TargetGuardResult struct {
	SchemaVersion int          `json:"schema_version"`
	State         string       `json:"state"`
	Reason        string       `json:"reason,omitempty"`
	TargetID      string       `json:"target_id"`
	Generation    uint64       `json:"generation"`
	Activated     bool         `json:"activated"`
	Guarded       bool         `json:"guarded"`
	Reservation   *TargetGuard `json:"reservation,omitempty"`
}

type targetBackend interface {
	Check(context.Context, TargetGuard, []Entry, bool) (bool, error)
	Ensure(context.Context, TargetGuard, []Entry) error
	Remove(context.Context, TargetGuard) error
}

func targetSlots(controller, node, target string) (uint32, uint32) {
	h := sha256.Sum256([]byte(controller + "\x00" + node + "\x00" + target))
	return 700000 + binary.BigEndian.Uint32(h[:4])%524288, 32000 + binary.BigEndian.Uint32(h[4:8])%760
}
func guardPrefixesOverlap(a, b []string) bool {
	for _, x := range a {
		p, err := netip.ParsePrefix(x)
		if err != nil {
			return true
		}
		for _, y := range b {
			q, err := netip.ParsePrefix(y)
			if err != nil || p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}
func validGuardID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func validateTargetGuards(entries []TargetGuard, node string) error {
	if len(entries) > relaycatalog.MaxTargets {
		return errors.New("too many target reservations")
	}
	for i, e := range entries {
		table, priority := targetSlots(e.Controller, e.Node, e.TargetID)
		if e.Controller == "" || e.Node != node || !validGuardID(e.TargetID) || e.Generation == 0 || e.Table != table || e.Priority != priority || e.Metric < 100000 || e.Metric > 0x3fffffff+100000 || len(e.Owner) != 39 || !strings.HasPrefix(e.Owner, "vpnctl:") || (e.Phase != "reserving" && e.Phase != "guarded" && e.Phase != "releasing") {
			return errors.New("invalid target reservation")
		}
		if _, err := hex.DecodeString(e.Owner[7:]); err != nil {
			return errors.New("invalid target owner")
		}
		if len(e.Prefixes) == 0 || len(e.Prefixes) > 8 || !slices.IsSorted(e.Prefixes) {
			return errors.New("invalid target prefixes")
		}
		for j, s := range e.Prefixes {
			p, err := netip.ParsePrefix(s)
			if err != nil || !p.Addr().Is4() || p.Bits() == 0 || p != p.Masked() || p.String() != s || guardPrefixesOverlap(e.Prefixes[:j], []string{s}) {
				return errors.New("invalid or overlapping target prefix")
			}
		}
		for _, old := range entries[:i] {
			if old.TargetID == e.TargetID || old.Table == e.Table || old.Priority == e.Priority || guardPrefixesOverlap(old.Prefixes, e.Prefixes) {
				return errors.New("conflicting target reservations")
			}
		}
	}
	return nil
}
func (e *Engine) targetIndex(id string) int {
	for i, t := range e.journal.Targets {
		if t.TargetID == id {
			return i
		}
	}
	return -1
}
func (e *Engine) targetResult(id, state, reason string) TargetGuardResult {
	out := TargetGuardResult{SchemaVersion: 1, TargetID: id, State: state, Reason: reason}
	if i := e.targetIndex(id); i >= 0 {
		v := e.journal.Targets[i]
		v.Prefixes = slices.Clone(v.Prefixes)
		out.Reservation = &v
		out.Generation = v.Generation
	}
	return out
}
func (e *Engine) targetFailure(id, reason string, err error) (TargetGuardResult, error) {
	return e.targetResult(id, "blocked", reason), fmt.Errorf("%s: %w", reason, err)
}

func (e *Engine) ReserveTarget(parent context.Context, id, controller string) (TargetGuardResult, error) {
	if e.uncertain {
		return e.targetFailure(id, "reopen_journal_required", relaycache.ErrUncertain)
	}
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()
	r, err := e.cache.Status()
	if err != nil {
		return e.targetFailure(id, "approval_unavailable", err)
	}
	if !r.UsableCache || r.Catalog == nil || r.Catalog.Validate(e.journal.Node, time.Now()) != nil || controller != "" && controller != r.ControllerID {
		return e.targetFailure(id, "approval_unavailable", errors.New("valid approved target required"))
	}
	var prefixes []string
	for _, t := range r.Catalog.Spec.Targets {
		if t.ID == id {
			prefixes = slices.Clone(t.Prefixes)
		}
	}
	if len(prefixes) == 0 {
		return e.targetFailure(id, "target_not_approved", errors.New("target not in approved catalog"))
	}
	slices.Sort(prefixes)
	if i := e.targetIndex(id); i >= 0 {
		old := e.journal.Targets[i]
		if old.Controller != r.ControllerID || !slices.Equal(old.Prefixes, prefixes) {
			return e.targetFailure(id, "reservation_definition_changed", ErrConflict)
		}
		if old.Phase != "guarded" {
			return e.targetFailure(id, "pending_target_journal", ErrRecovery)
		}
		return e.InspectTarget(ctx, id)
	}
	owner, metric, _, err := token()
	if err != nil {
		return e.targetFailure(id, "owner_unavailable", err)
	}
	table, priority := targetSlots(r.ControllerID, r.NodeID, id)
	entry := TargetGuard{Controller: r.ControllerID, Node: r.NodeID, Generation: r.ObservedGeneration, TargetID: id, Prefixes: prefixes, Owner: owner, Metric: metric, Table: table, Priority: priority, Phase: "reserving"}
	proposed := append(slices.Clone(e.journal.Targets), entry)
	if err = validateTargetGuards(proposed, e.journal.Node); err != nil {
		return e.targetFailure(id, "target_reservation_conflict", err)
	}
	if _, err = e.targets.Check(ctx, entry, e.journal.Entries, true); err != nil {
		return e.targetFailure(id, "kernel_conflict_or_unavailable", err)
	}
	// No key, peer or packet permission is installed. Recovery may finish this
	// blocking intent even if approval expires after this durable write.
	e.journal.Targets = proposed
	if err = e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed", err)
	}
	return e.finishTarget(ctx, id)
}
func (e *Engine) finishTarget(ctx context.Context, id string) (TargetGuardResult, error) {
	i := e.targetIndex(id)
	entry := e.journal.Targets[i]
	if err := e.targets.Ensure(ctx, entry, e.journal.Entries); err != nil {
		return e.targetFailure(id, "target_recovery_required", err)
	}
	ready, err := e.targets.Check(ctx, entry, e.journal.Entries, false)
	if err != nil || !ready {
		return e.targetFailure(id, "target_readback_incomplete", errors.Join(ErrRecovery, err))
	}
	e.journal.Targets[i].Phase = "guarded"
	if err = e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed", err)
	}
	out := e.targetResult(id, "guarded", "")
	out.Guarded = true
	return out, nil
}
func (e *Engine) InspectTarget(parent context.Context, id string) (TargetGuardResult, error) {
	if e.uncertain {
		return e.targetFailure(id, "reopen_journal_required", relaycache.ErrUncertain)
	}
	i := e.targetIndex(id)
	if i < 0 {
		return e.targetFailure(id, "target_not_owned", ErrConflict)
	}
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()
	entry := e.journal.Targets[i]
	ready, err := e.targets.Check(ctx, entry, e.journal.Entries, false)
	if err != nil {
		return e.targetFailure(id, "kernel_conflict_or_unavailable", err)
	}
	if !ready || entry.Phase != "guarded" {
		return e.targetFailure(id, "target_recovery_required", ErrRecovery)
	}
	out := e.targetResult(id, "guarded", "")
	out.Guarded = true
	return out, nil
}
func (e *Engine) RecoverTarget(parent context.Context, id string) (TargetGuardResult, error) {
	if e.uncertain {
		return e.targetFailure(id, "reopen_journal_required", relaycache.ErrUncertain)
	}
	i := e.targetIndex(id)
	if i < 0 {
		return e.targetFailure(id, "target_not_owned", ErrConflict)
	}
	if e.journal.Targets[i].Phase == "releasing" {
		return e.ReleaseTarget(parent, id)
	}
	if e.journal.Targets[i].Phase == "guarded" {
		return e.InspectTarget(parent, id)
	}
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()
	return e.finishTarget(ctx, id)
}

// ReleaseTarget intentionally relinquishes routing control. Unlike revocation,
// this explicit operator action can expose the target to main/default again.
func (e *Engine) ReleaseTarget(parent context.Context, id string) (TargetGuardResult, error) {
	if e.uncertain {
		return e.targetFailure(id, "reopen_journal_required", relaycache.ErrUncertain)
	}
	i := e.targetIndex(id)
	if i < 0 {
		return e.targetFailure(id, "target_not_owned", ErrConflict)
	}
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()
	e.journal.Targets[i].Phase = "releasing"
	if err := e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed", err)
	}
	if err := e.targets.Remove(ctx, e.journal.Targets[i]); err != nil {
		return e.targetFailure(id, "target_recovery_required", err)
	}
	e.journal.Targets = append(e.journal.Targets[:i], e.journal.Targets[i+1:]...)
	if err := e.persist(); err != nil {
		return e.targetFailure(id, "journal_save_failed_after_cleanup", err)
	}
	return e.targetResult(id, "released", ""), nil
}
