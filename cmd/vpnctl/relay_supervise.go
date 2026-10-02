// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
)

type relaySupervisionReport struct {
	SchemaVersion     int                          `json:"schema_version"`
	ObservedAt        time.Time                    `json:"observed_at"`
	CycleMS           int64                        `json:"cycle_ms"`
	State             string                       `json:"state"`
	Reason            string                       `json:"reason,omitempty"`
	Refresh           string                       `json:"refresh"`
	ApprovalValid     bool                         `json:"approval_valid"`
	ApprovalState     string                       `json:"approval_state"`
	LastRefreshAt     time.Time                    `json:"last_refresh_at,omitempty"`
	LastSuccessAt     time.Time                    `json:"last_success_at,omitempty"`
	ApprovalExpiresAt time.Time                    `json:"approval_expires_at,omitempty"`
	Kernel            *relayapply.DeploymentResult `json:"kernel,omitempty"`
}

const relayKernelRetryInterval = 25 * time.Millisecond

func relaySupervisionCycle(ctx context.Context, dir, principal, relay string, client relaycache.DeploymentClient, refresh bool) (relaySupervisionReport, error) {
	out := relaySupervisionReport{SchemaVersion: 1, ObservedAt: time.Now().UTC(), State: "degraded", Refresh: "not_due", ApprovalState: "unknown"}
	c, err := openSupervisedCache(ctx, func() (*relaycache.DeploymentStore, error) {
		return relaycache.OpenDeployment(dir, relaycache.DeploymentOptions{PrincipalID: principal, RelayID: relay})
	})
	if err != nil {
		out.Reason = "cache_unavailable"
		return out, err
	}
	defer c.Close()
	// Acquire the namespace before starting the bounded authenticated request.
	// Waiting behind another supervisor must not consume a fresh response's
	// five-second rearm window. Never relabel an old response with a new time.
	// The request holds the namespace for at most one second, within the same
	// five-second cycle; independent kernel leases still bound any stalled work.
	e, openErr := openSupervisedDeployment(ctx, func() (*relayapply.DeploymentEngine, error) { return relayapply.OpenDeployment(c) })
	if openErr != nil {
		out.Reason = "enforcement_unavailable"
		return out, openErr
	}
	defer e.Close()
	authenticatedAt := relayapply.FreshApproval{}
	var report relaycache.DeploymentReport
	if refresh {
		authenticatedStart, clockErr := relayapply.ObserveApproval()
		request, stop := context.WithTimeout(ctx, time.Second)
		report, err = c.Refresh(request, client)
		stop()
		if err == nil && report.ApprovalValid && clockErr == nil {
			authenticatedAt = authenticatedStart
		}
		out.Refresh = report.Refresh.Result
	} else {
		report, err = c.Status()
	}
	out.ApprovalValid = report.ApprovalValid
	out.ApprovalState = report.Validity
	out.LastRefreshAt = report.Refresh.CompletedAt
	out.LastSuccessAt = report.Refresh.LastSuccessAt
	if report.Deployment != nil {
		out.ApprovalExpiresAt = report.Deployment.ExpiresAt
	}
	// Even a rejected refresh must reach enforcement.
	kernel, enforceErr := e.Maintain(ctx, authenticatedAt)
	out.Kernel = &kernel
	latest, statusErr := c.Status()
	out.ApprovalValid = latest.ApprovalValid && statusErr == nil
	out.ApprovalState = latest.Validity
	if enforceErr != nil {
		out.Reason = kernel.Reason
		return out, enforceErr
	}
	if statusErr != nil {
		out.Reason = "approval_status_unavailable"
		return out, statusErr
	}
	out.State = "watching"
	if !out.ApprovalValid {
		out.State = "blocked"
		out.Reason = "approval_unavailable"
	}
	// A transport outage with still-valid approval is a recoverable refresh
	// failure. Maintain continues the existing lease until approval expires.
	return out, nil
}

// Retry cache and namespace contention within the existing cycle deadline.
// A once-per-second cache attempt can repeatedly collide with short CLI calls
// and let every lease expire despite idle gaps between those calls.
func openSupervisedCache(ctx context.Context, open func() (*relaycache.DeploymentStore, error)) (*relaycache.DeploymentStore, error) {
	return retrySupervisedLock(ctx, open, relaycache.ErrBusy)
}
func openSupervisedDeployment(ctx context.Context, open func() (*relayapply.DeploymentEngine, error)) (*relayapply.DeploymentEngine, error) {
	return retrySupervisedLock(ctx, open, relayapply.ErrKernelBusy)
}
func retrySupervisedLock[T any](ctx context.Context, open func() (T, error), busy error) (T, error) {
	var zero T
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		resource, err := open()
		if !errors.Is(err, busy) {
			return resource, err
		}
		timer := time.NewTimer(relayKernelRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}

func superviseRelay(ctx context.Context, w io.Writer, cycle func(context.Context, bool) (relaySupervisionReport, error), refreshInterval time.Duration) error {
	nextRefresh := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		started := time.Now()
		refresh := !started.Before(nextRefresh)
		if refresh {
			nextRefresh = started.Add(refreshInterval)
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		out, _ := cycle(bounded, refresh)
		cancel()
		out.ObservedAt = time.Now().UTC()
		out.CycleMS = time.Since(started).Milliseconds()
		if err := json.NewEncoder(w).Encode(out); err != nil {
			return err
		}
		wait := time.Until(started.Add(time.Second))
		// An overrun must still yield the namespace. Otherwise a supervisor
		// taking just over one second can reacquire on every cycle before a
		// competing process's bounded lock retry wakes up.
		if wait < 2*relayKernelRetryInterval {
			wait = 2 * relayKernelRetryInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runRelaySupervise(args []string) error {
	fs := flag.NewFlagSet("relay supervise", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "enrolled relay identity YAML")
	relay := fs.String("relay-id", "", "approved relay ID")
	dir := fs.String("cache-dir", "", "existing deployment cache directory")
	refresh := fs.Duration("refresh-interval", 5*time.Second, "authenticated approval refresh cadence in [1s,20s]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *refresh < time.Second || *refresh > 20*time.Second {
		return fmt.Errorf("supervise requires refresh-interval in [1s,20s] and no positional arguments")
	}
	if err := relaycache.ValidateDeploymentIdentity("placeholder", *relay); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.PKIDir == "" || cfg.Node.Controller == "" {
		return errors.New("enrolled relay identity, controller and pki_dir required")
	}
	if *dir == "" {
		*dir = filepath.Join(cfg.Node.PKIDir, "relay-deployments", *relay)
	}
	client := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
	defer client.CloseIdleConnections()
	ctx, stop := signalContext()
	defer stop()
	return superviseRelay(ctx, os.Stdout, func(ctx context.Context, refresh bool) (relaySupervisionReport, error) {
		return relaySupervisionCycle(ctx, *dir, cfg.Node.Name, *relay, client, refresh)
	}, *refresh)
}
