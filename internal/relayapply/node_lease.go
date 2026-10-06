// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"reflect"
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
	var all error
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
			ready, x := check(ctx, old, false)
			if x != nil || !ready {
				p.Reason = "kernel_conflict_or_unavailable"
				err = errors.Join(ErrRecovery, x, b.Block(ctx, old))
			} else {
				// Commit the authority change before granting any longer deadline.
				if entry.Generation != old.Generation || !entry.ApprovalUntil.Equal(old.ApprovalUntil) || entry.ApprovalBootNS != old.ApprovalBootNS {
					e.journal.Entries[i] = entry
					err = e.persist()
				}
				if err == nil {
					err = e.stillApproved(entry)
				}
				if err == nil {
					var lease DeploymentLease
					lease, err = b.Lease(ctx, entry, FreshApproval{at, boot})
					if err == nil && lease.rearmed && lease.Active {
						// Continue immediately so the first short grant does not
						// expire while checking the remaining seven candidates.
						lease, err = b.Lease(ctx, entry, FreshApproval{})
					}
					p.Lease = &lease
					if err == nil && !lease.Active {
						err = ErrLeaseExpired
					}
				}
				if err != nil {
					p.Reason = "lease_renewal_failed"
					err = errors.Join(err, b.Block(ctx, entry))
				} else {
					p.KernelReady = true
					e.maintained[old.Candidate.PathID] = true
				}
			}
		}
		out.Paths = append(out.Paths, p)
		all = errors.Join(all, err)
	}
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
