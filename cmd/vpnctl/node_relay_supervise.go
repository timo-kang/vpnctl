// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
)

type nodeSupervisionReport struct {
	SchemaVersion int                `json:"schema_version"`
	ObservedAt    time.Time          `json:"observed_at"`
	CycleMS       int64              `json:"cycle_ms"`
	State         string             `json:"state"`
	Reason        string             `json:"reason,omitempty"`
	Refresh       string             `json:"refresh"`
	Kernel        *relayapply.Result `json:"kernel,omitempty"`
}

func nodeSupervisionCycle(ctx context.Context, cfg *config.NodeConfig, dir string, client relaycache.Client, refresh bool) (nodeSupervisionReport, error) {
	out := nodeSupervisionReport{SchemaVersion: 1, State: "blocked", Refresh: "not_due"}
	locks, cancel := relaySupervisionLockContext(ctx)
	defer cancel()
	c, err := retrySupervisedLock(locks, func() (*relaycache.Store, error) { return openNodeRelayCache(cfg, dir, false) }, relaycache.ErrBusy)
	if err != nil {
		out.Reason = "cache_unavailable"
		return out, err
	}
	defer c.Close()
	e, err := retrySupervisedLock(locks, func() (*relayapply.Engine, error) { return relayapply.Open(c, cfg.RelayUnderlays) }, relayapply.ErrKernelBusy)
	if err != nil {
		out.Reason = "enforcement_unavailable"
		return out, err
	}
	defer e.Close()
	cancel()
	if refresh {
		request, stop := context.WithTimeout(ctx, time.Second)
		r, _ := c.Refresh(request, client)
		stop()
		out.Refresh = r.Refresh.Result
	}
	// Rejection/storage failure still reaches blocking. No output is written
	// while holding either lock. A blocked logger cannot renew kernel leases.
	r, err := e.MaintainLeases(ctx)
	out.Kernel = &r
	out.State = r.State
	out.Reason = r.Reason
	return out, err
}

func runNodeRelaySupervise(args []string) error {
	fs := flag.NewFlagSet("node relay supervise", flag.ContinueOnError)
	configPath := fs.String("config", "", "enrolled node configuration")
	dir := fs.String("cache-dir", "", "existing private node relay cache")
	interval := fs.Duration("refresh-interval", 5*time.Second, "authenticated refresh cadence in [1s,20s]")
	once := fs.Bool("once", false, "run one bounded authenticated maintenance cycle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *interval < time.Second || *interval > 20*time.Second {
		return fmt.Errorf("refresh-interval must be in [1s,20s]; no positional arguments")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.PKIDir == "" || cfg.Node.Controller == "" {
		return errors.New("enrolled node identity, controller and pki_dir required")
	}
	if *dir == "" {
		*dir = cfg.Node.RelayCacheDir
	}
	if *dir == "" {
		*dir = filepath.Join(cfg.Node.PKIDir, "relay-cache")
	}
	client := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
	defer client.CloseIdleConnections()
	ctx, stop := signalContext()
	defer stop()
	next := time.Time{}
	for ctx.Err() == nil {
		start := time.Now()
		refresh := !start.Before(next)
		bounded, cancel := context.WithTimeout(ctx, relayapply.NodeMaintenanceDuration)
		out, cycleErr := nodeSupervisionCycle(bounded, cfg.Node, *dir, client, refresh)
		cancel()
		if refresh && out.Refresh != "not_due" {
			next = start.Add(*interval)
		}
		out.ObservedAt = time.Now().UTC()
		out.CycleMS = time.Since(start).Milliseconds()
		if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
			return err
		}
		if *once {
			return cycleErr
		}
		timer := time.NewTimer(max(time.Until(start.Add(time.Second)), 2*relayKernelRetryInterval))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}
