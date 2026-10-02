// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"time"

	"vpnctl/internal/relayguard"
)

type FreshApproval struct {
	At     time.Time
	BootNS uint64
}

// ObserveApproval is called before the authenticated request (or an explicit
// operator apply), never reconstructed from a persisted response timestamp.
func ObserveApproval() (FreshApproval, error) {
	at := time.Now()
	boot, err := relayguard.Now()
	return FreshApproval{at, boot}, err
}

type bootDeploymentKernel struct{ deploymentKernel }

func guardOwner(e DeploymentEntry) relayguard.Owner {
	return relayguard.Owner{Interface: e.Interface, Alias: e.Alias, Index: int(e.LinkIndex), Group: e.Group, Pending: e.Phase != "applied"}
}

func (k bootDeploymentKernel) Check(ctx context.Context, e DeploymentEntry, fresh bool) (bool, error) {
	if fresh && e.LeaseVersion == 3 {
		if err := relayguard.Preflight(guardOwner(e)); err != nil {
			return false, err
		}
	}
	ready, err := k.deploymentKernel.Check(ctx, e, fresh)
	if err != nil || fresh || !ready || e.LeaseVersion != 3 {
		return ready, err
	}
	_, err = relayguard.Read(ctx, guardOwner(e))
	return err == nil, err
}

func (k bootDeploymentKernel) Step(ctx context.Context, e DeploymentEntry, step, key string) error {
	if e.LeaseVersion == 3 && step == "up" {
		if _, err := k.deploymentKernel.Check(ctx, e, false); err != nil {
			return err
		}
		if err := relayguard.Install(ctx, guardOwner(e)); err != nil {
			return err
		}
	}
	return k.deploymentKernel.Step(ctx, e, step, key)
}

func (k bootDeploymentKernel) Down(ctx context.Context, e DeploymentEntry) error {
	var bootErr error
	if e.LeaseVersion == 3 {
		bootErr = relayguard.Block(ctx, guardOwner(e))
	}
	return errors.Join(bootErr, k.deploymentKernel.Down(ctx, e))
}

func (k bootDeploymentKernel) Remove(ctx context.Context, e DeploymentEntry) error {
	if e.LeaseVersion == 3 {
		if err := relayguard.InspectPartial(ctx, guardOwner(e)); err != nil {
			return err
		}
	}
	if err := k.deploymentKernel.Remove(ctx, e); err != nil {
		return err
	}
	if e.LeaseVersion == 3 {
		return relayguard.RemovePins(ctx, guardOwner(e))
	}
	return nil
}

func (k bootDeploymentKernel) Lease(ctx context.Context, e DeploymentEntry, expiry time.Time, fresh FreshApproval) (DeploymentLease, error) {
	if e.LeaseVersion != 3 {
		return k.deploymentKernel.Lease(ctx, e, expiry, fresh)
	}
	boot, err := relayguard.Read(ctx, guardOwner(e))
	if err != nil {
		return DeploymentLease{}, err
	}
	state, err := k.stagedLease(ctx, e, expiry, fresh, &boot)
	if err != nil {
		state.Active = false
		state.Boot = &boot
		return state, err
	}
	boot, err = relayguard.Read(ctx, guardOwner(e))
	state.Boot = &boot
	state.Active = state.Active && boot.Active && err == nil
	if err == nil && !state.Active {
		err = ErrLeaseExpired
	}
	return state, err
}

func (k bootDeploymentKernel) LeaseStatus(ctx context.Context, e DeploymentEntry) (DeploymentLease, error) {
	state, err := k.deploymentKernel.LeaseStatus(ctx, e)
	if err != nil || e.LeaseVersion != 3 {
		return state, err
	}
	boot, err := relayguard.Read(ctx, guardOwner(e))
	state.Boot = &boot
	state.Active = state.Active && boot.Active && err == nil
	return state, err
}
