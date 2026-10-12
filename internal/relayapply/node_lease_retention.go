// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"time"

	"vpnctl/internal/relayguard"
)

// This is an availability hypothesis, not a promise about the next cycle.
// Retention never extends either kernel timer or changes approval authority.
const nodeLeaseRetainHeadroom = 5 * time.Second

type nodeLeaseRetention struct {
	guard      relayguard.State
	nftUntilNS uint64
	checkedNS  uint64
}

func planNodeLeaseRetention(s DeploymentLease, b relayguard.State, approval time.Time, approvalBootNS uint64, wall time.Time, boot time.Duration) (*nodeLeaseRetention, error) {
	if !s.Active || !b.Active || len(s.staged) != 0 {
		return nil, nil
	}
	if boot < 0 || b.ObservedNS == 0 || uint64(boot) < b.ObservedNS || b.Generation == 0 || b.MapID == 0 || b.ProgramID == 0 {
		return nil, ErrConflict
	}
	now := uint64(boot)
	if now >= b.DeadlineNS || now >= approvalBootNS || !wall.Before(s.Deadline) || !wall.Before(approval) {
		return nil, ErrLeaseExpired
	}
	if s.Deadline.After(approval) || b.DeadlineNS > approvalBootNS {
		// A shortened approval must use the normal bounded renewal path.
		return nil, nil
	}
	if s.nftRemaining <= 0 || s.nftRemaining > DeploymentLeaseDuration {
		return nil, nil
	}
	// ObservedNS was captured BEFORE nft was read. Adding the floored timer
	// there is a lower bound even when the reads or scheduling take time.
	left := uint64(s.nftRemaining)
	if b.ObservedNS > ^uint64(0)-left {
		return nil, ErrConflict
	}
	until := b.ObservedNS + left
	if now >= until {
		return nil, nil // no usable lower bound: original conditional renewal
	}
	if until-now < uint64(nodeLeaseRetainHeadroom) || b.DeadlineNS-now < uint64(nodeLeaseRetainHeadroom) || s.Deadline.Sub(wall) < nodeLeaseRetainHeadroom {
		return nil, nil
	}
	return &nodeLeaseRetention{guard: b, nftUntilNS: until, checkedNS: now}, nil
}

// Final readback is mandatory. A changed/expired gate cannot be used as an
// opportunity to renew against the earlier snapshot or a cached approval.
func validateNodeLeaseRetention(s DeploymentLease, b relayguard.State, approval time.Time, approvalBootNS uint64, wall time.Time, boot time.Duration) error {
	r := s.retained
	if r == nil || boot < 0 || uint64(boot) < r.checkedNS || b.ObservedNS < r.guard.ObservedNS || b.ObservedNS > uint64(boot) ||
		b.Generation != r.guard.Generation || b.MapID != r.guard.MapID || b.ProgramID != r.guard.ProgramID || b.DeadlineNS != r.guard.DeadlineNS {
		return ErrConflict
	}
	// A same-name element can have been shortened since the first read.
	// checkedNS precedes the final nft read, so this is another conservative
	// lower bound. A later readback must never extend the original bound.
	if s.nftRemaining <= 0 || s.nftRemaining > DeploymentLeaseDuration || r.checkedNS > ^uint64(0)-uint64(s.nftRemaining) {
		return ErrLeaseExpired
	}
	until := min(r.nftUntilNS, r.checkedNS+uint64(s.nftRemaining))
	now := uint64(boot)
	if !s.Active || !b.Active || now >= until || now >= b.DeadlineNS || now >= approvalBootNS ||
		b.DeadlineNS > approvalBootNS || s.Deadline.After(approval) || !wall.Before(s.Deadline) || !wall.Before(approval) {
		return ErrLeaseExpired
	}
	return nil
}
