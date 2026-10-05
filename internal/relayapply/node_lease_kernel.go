// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"time"

	"vpnctl/internal/relayguard"
)

// Only the lease fields are projected. Node preparation never runs the relay
// forwarding policy or deployment reconciler.
func nodeLeaseEntry(e Entry) DeploymentEntry {
	return DeploymentEntry{Interface: e.Candidate.Pin.WGInterface, Alias: e.Alias, LinkIndex: e.LinkIndex, Group: e.Metric, Phase: "applied", LeaseVersion: 3}
}
func nodeGuardOwner(e Entry) relayguard.Owner {
	o := guardOwner(nodeLeaseEntry(e))
	o.Pending = e.Phase != "prepared"
	return o
}

type nodeLeaseBackend interface {
	Lease(context.Context, Entry, FreshApproval) (DeploymentLease, error)
	LeaseStatus(context.Context, Entry) (DeploymentLease, error)
	Block(context.Context, Entry) error
}
type nodeKernel struct{ kernel }

func (k nodeKernel) leaseKernel() deploymentKernel { return deploymentKernel{kernel: k.kernel} }

func (k nodeKernel) Check(ctx context.Context, e Entry, fresh bool) (bool, error) {
	if e.LeaseVersion != 0 && fresh {
		if err := relayguard.Preflight(nodeGuardOwner(e)); err != nil {
			return false, err
		}
		if _, exists, err := k.leaseKernel().leaseRead(ctx, nodeLeaseEntry(e)); err != nil || exists {
			return false, errors.Join(ErrConflict, err)
		}
	}
	ready, err := k.kernel.Check(ctx, e, fresh)
	if err != nil || !ready || e.LeaseVersion == 0 {
		return ready, err
	}
	_, err = k.LeaseStatus(ctx, e)
	return err == nil, err
}
func (k nodeKernel) Step(ctx context.Context, e Entry, step, key string) error {
	if e.LeaseVersion != 0 && step == "up" {
		if _, err := k.kernel.Check(ctx, e, false); err != nil {
			return err
		}
		if err := k.leaseKernel().leaseCreate(ctx, nodeLeaseEntry(e)); err != nil {
			return err
		}
		if err := relayguard.Install(ctx, nodeGuardOwner(e)); err != nil {
			return err
		}
	}
	return k.kernel.Step(ctx, e, step, key)
}
func (k nodeKernel) Remove(ctx context.Context, e Entry) error {
	if e.LeaseVersion != 0 {
		if err := relayguard.InspectPartial(ctx, nodeGuardOwner(e)); err != nil {
			return err
		}
		if _, _, err := k.leaseKernel().leaseRead(ctx, nodeLeaseEntry(e)); err != nil {
			return err
		}
	}
	if err := k.kernel.Remove(ctx, e); err != nil {
		return err
	}
	if e.LeaseVersion != 0 {
		if err := k.leaseKernel().leaseRemove(ctx, nodeLeaseEntry(e)); err != nil {
			return err
		}
		return relayguard.RemovePins(ctx, nodeGuardOwner(e))
	}
	return nil
}
func (k nodeKernel) Block(ctx context.Context, e Entry) error {
	if e.LeaseVersion == 0 {
		return nil
	}
	// Independently attempt both gates. A foreign nft object does not prevent
	// revocation through a still-owned BPF object (and vice versa).
	return errors.Join(relayguard.Block(ctx, nodeGuardOwner(e)), k.leaseKernel().leaseBlock(ctx, nodeLeaseEntry(e)))
}
func (k nodeKernel) LeaseStatus(ctx context.Context, e Entry) (DeploymentLease, error) {
	s, err := k.leaseKernel().LeaseStatus(ctx, nodeLeaseEntry(e))
	if err != nil {
		return s, err
	}
	b, err := relayguard.Read(ctx, nodeGuardOwner(e))
	s.Boot = &b
	s.Active = s.Active && b.Active && err == nil
	return s, err
}
func (k nodeKernel) Lease(ctx context.Context, e Entry, fresh FreshApproval) (DeploymentLease, error) {
	b, err := relayguard.Read(ctx, nodeGuardOwner(e))
	if err != nil {
		return DeploymentLease{}, err
	}
	s, err := k.leaseKernel().stagedLeaseBounded(ctx, nodeLeaseEntry(e), e.ApprovalUntil, fresh, &b, e.ApprovalBootNS)
	if err != nil {
		s.Active = false
		return s, err
	}
	b, err = relayguard.Read(ctx, nodeGuardOwner(e))
	s.Boot = &b
	s.Active = s.Active && b.Active && err == nil
	if err == nil && (!s.Active || b.DeadlineNS > e.ApprovalBootNS || !time.Now().Before(e.ApprovalUntil)) {
		err = ErrLeaseExpired
		s.Active = false
	}
	return s, err
}
