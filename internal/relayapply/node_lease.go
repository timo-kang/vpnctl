// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayplan"
)

const NodeMaintenanceDuration = 5 * time.Second

func (e *Engine) hasLeases() bool {
	for _, p := range e.journal.Entries {
		if p.LeaseVersion != 0 {
			return true
		}
	}
	return false
}

// MaintainLeases owns the same cache/namespace locks and journal as prepare,
// release and observe. It never adds routes or adopts drift. A rejected entry
// cannot prevent independent entries from being checked and renewed.
func (e *Engine) MaintainLeases(parent context.Context) (Result, error) {
	e.maintained = map[string]bool{}
	parent, done := relayobserve.Phase(parent, "maintenance")
	defer done()
	ctx, cancel := context.WithTimeout(parent, NodeMaintenanceDuration)
	defer cancel()
	out := result("empty", "", "")
	if !e.hasLeases() {
		return out, nil
	}
	b, ok := e.backend.(nodeLeaseBackend)
	if !ok {
		return failure("", "lease_backend_unavailable", ErrRecovery)
	}
	r, statusErr := e.cache.Status()
	w, at, boot, approvalErr := e.cache.LeaseApproval()
	if e.uncertain {
		statusErr = errors.Join(statusErr, relaycache.ErrUncertain)
	}
	var plan relayplan.Plan
	if statusErr == nil && approvalErr == nil && w.Domain == e.journal.Domain {
		plan, approvalErr = relayplan.Build(ctx, r.NodeID, "", r, e.underlays, e.collector)
	} else {
		approvalErr = errors.Join(approvalErr, statusErr, ErrRecovery)
	}
	check := e.backend.Check
	if k, ok := e.backend.(nodeKernel); ok {
		k.run = maintenanceInventory(k.run)
		// Lease below reads the live nft timer/flowtables and BPF owner,
		// conditionally renews, and reads both gates back. Checking the same
		// lease here duplicates that work without strengthening the grant.
		// Only public ownership inventories are shared; lease data is not.
		check = k.kernel.Check
	}
	// Finish journal updates before any renewal starts. Kernel ownership and
	// the durable approval clock are still checked at dispatch. A later clock
	// checkpoint failure cancels and revokes all renewals below.
	type renewal struct {
		index int
		entry Entry
	}
	var ready []renewal
	var failures []error
	for i, old := range e.journal.Entries {
		if old.LeaseVersion == 0 {
			continue
		}
		p := PathResult{PathID: old.Candidate.PathID, Phase: old.Phase}
		entry := old
		approved := false
		consent, consentErr := e.preparationAllowed(old.Candidate.PathID)
		if consent && consentErr == nil && !e.uncertain && !e.pendingTargetReferences(old.Candidate.PathID) && approvalErr == nil && old.Phase == "prepared" && old.Controller == w.Controller && old.Node == w.Node && w.Generation >= old.Generation {
			for _, candidate := range plan.Paths {
				if reflect.DeepEqual(candidate, old.Candidate) {
					approved = true
					break
				}
			}
		}
		var err error
		if !approved {
			p.Reason = "approval_or_inventory_unavailable"
			err = errors.Join(ErrRecovery, approvalErr, b.Block(ctx, old))
		} else {
			entry.Generation, entry.ApprovalUntil, entry.ApprovalBootNS = w.Generation, w.ExpiresAt, w.UntilBootNS
			// This records current authority, never kernel readiness or new
			// ownership. A conflicting resource still cannot receive a grant.
			if entry.Generation != old.Generation || !entry.ApprovalUntil.Equal(old.ApprovalUntil) || entry.ApprovalBootNS != old.ApprovalBootNS {
				e.journal.Entries[i] = entry
				err = e.persist()
			}
			if err != nil {
				p.Reason = "lease_renewal_failed"
				err = errors.Join(err, b.Block(ctx, entry))
			} else {
				ready = append(ready, renewal{len(out.Paths), entry})
			}
		}
		out.Paths = append(out.Paths, p)
		failures = append(failures, err)
	}
	// Only independent nft/BPF lease operations overlap. Keep engine/cache,
	// public inventory sharing and journal access serialized. Two workers bound
	// process pressure, and all workers finish before namespace ownership ends.
	slots := make(chan struct{}, 2)
	var workers sync.WaitGroup
	renewCtx, stopRenewals := context.WithCancel(ctx)
	defer stopRenewals()
	var authorityErr error
	for _, job := range ready {
		p, entry := out.Paths[job.index], job.entry
		err := ctx.Err()
		if e.uncertain {
			err = errors.Join(err, relaycache.ErrUncertain)
		}
		acquired := false
		if err == nil {
			select {
			case slots <- struct{}{}:
				acquired = true
			case <-ctx.Done():
			}
			err = ctx.Err()
		}
		p.Reason = "lease_renewal_failed"
		if err == nil {
			valid, checkErr := check(ctx, entry, false)
			if checkErr != nil || !valid {
				p.Reason = "kernel_conflict_or_unavailable"
				err = errors.Join(ErrRecovery, checkErr)
			} else {
				authorityErr = e.stillApproved(entry)
				err = errors.Join(authorityErr, ctx.Err())
			}
		}
		if authorityErr != nil || e.uncertain || ctx.Err() != nil {
			// Status checkpoints the cache clock. A failed write invalidates
			// this whole sweep, including a grant already in flight or done.
			authorityErr = errors.Join(authorityErr, err, ctx.Err())
			stopRenewals()
			if acquired {
				<-slots
			}
			break
		}
		if err != nil {
			failures[job.index] = errors.Join(err, b.Block(ctx, entry))
			out.Paths[job.index] = p
			if acquired {
				<-slots
			}
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			lease, err := b.Lease(renewCtx, entry, FreshApproval{at, boot})
			if err == nil && lease.rearmed && lease.Active {
				// Keep the first short authenticated grant and its continuation
				// in the same worker; never rearm a failed continuation.
				lease, err = b.Lease(renewCtx, entry, FreshApproval{})
			}
			p.Lease = &lease
			err = errors.Join(err, renewCtx.Err())
			if err == nil && !lease.Active {
				err = ErrLeaseExpired
			}
			if err != nil {
				failures[job.index] = errors.Join(err, b.Block(renewCtx, entry))
			} else {
				p.KernelReady, p.Reason = true, ""
			}
			out.Paths[job.index] = p
		}()
	}
	workers.Wait()
	if abort := errors.Join(authorityErr, ctx.Err()); abort != nil {
		// Join first: a worker must never reopen a gate after cleanup. Retain
		// namespace ownership and the original maintenance deadline, but let
		// cleanup use its remaining time even if the caller canceled. When
		// time is exhausted, report the cleanup failure; never claim readiness.
		deadline, _ := ctx.Deadline()
		cleanup, stopCleanup := context.WithDeadline(context.WithoutCancel(ctx), deadline)
		defer stopCleanup()
		for _, job := range ready {
			p := &out.Paths[job.index]
			p.KernelReady, p.Reason = false, "lease_renewal_failed"
			if p.Lease != nil {
				p.Lease.Active = false
			}
			failures[job.index] = errors.Join(failures[job.index], abort, b.Block(cleanup, job.entry))
		}
	}
	for _, p := range out.Paths {
		if p.KernelReady {
			e.maintained[p.PathID] = true
		}
	}
	all := errors.Join(failures...)
	if len(out.Paths) > 0 {
		out.State = "protected"
		out.KernelReady = true
	}
	if all != nil {
		out.State = "blocked"
		out.Reason = "candidate_requires_attention"
		out.KernelReady = false
	}
	return out, all
}

func (e *Engine) checkLease(ctx context.Context, entry Entry) (*DeploymentLease, error) {
	if entry.LeaseVersion == 0 {
		return nil, nil
	}
	b, ok := e.backend.(nodeLeaseBackend)
	if !ok {
		return nil, ErrRecovery
	}
	w, _, _, err := e.cache.LeaseApproval()
	if err != nil || w.Domain != e.journal.Domain || w.Generation != entry.Generation || w.Controller != entry.Controller || w.UntilBootNS != entry.ApprovalBootNS {
		return nil, errors.Join(ErrLeaseExpired, err, b.Block(ctx, entry))
	}
	s, err := b.LeaseStatus(ctx, entry)
	if err == nil && (!s.Active || s.Boot == nil || s.Boot.DeadlineNS > entry.ApprovalBootNS) {
		err = ErrLeaseExpired
	}
	if err != nil {
		s.Active = false // This is verified readiness, not a promise both gates responded.
		err = errors.Join(err, b.Block(ctx, entry))
	}
	return &s, err
}
