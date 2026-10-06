// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
	"vpnctl/internal/underlayevent"
)

func runNodeRelaySelect(args []string) error {
	return runNodeRelaySelection(args, false)
}
func runNodeRelaySelection(args []string, apply bool) error {
	name := "node relay select"
	if apply {
		name = "node relay target reconcile"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "", "enrolled node configuration")
	cacheDir := fs.String("cache-dir", "", "private relay cache directory")
	target := fs.String("target-id", "", "approved application target ID")
	controller := fs.String("controller-id", "", "expected controller identity")
	watch := fs.Bool("watch", false, "continuously observe and decide (target reconcile also applies routes)")
	samples := fs.Int("samples", 2, "observation cycles (2..1000), ignored with --watch")
	interval := fs.Duration("interval", 2*time.Second, "delay between completed cycles (100ms..1m)")
	timeout := fs.Duration("probe-timeout", time.Second, "per-path TCP evidence timeout (10ms..2s)")
	policy := relayselect.DefaultPolicy()
	fs.StringVar(&policy.Mode, "mode", policy.Mode, "auto or manual")
	fs.StringVar(&policy.ManualPin, "path-id", "", "required in manual mode; never falls back to another path")
	fs.IntVar(&policy.MaxCost, "max-cost", policy.MaxCost, "maximum permitted cost (-1 is unrestricted)")
	fs.DurationVar(&policy.HoldDown, "hold-down", policy.HoldDown, "continuous recovery required before preferring another healthy path")
	fs.DurationVar(&policy.MinimumDwell, "minimum-dwell", policy.MinimumDwell, "minimum selected-path dwell; failure overrides it")
	fs.DurationVar(&policy.MaxConnectTime, "max-connect-time", policy.MaxConnectTime, "TCP connect latency ceiling")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *target == "" || *samples < 2 || *samples > 1000 || *interval < 100*time.Millisecond || *interval > time.Minute || *timeout < 10*time.Millisecond || *timeout > 2*time.Second {
		return fmt.Errorf("target-id and bounded samples/interval/probe-timeout required")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	selector, err := relayselect.New(policy)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.PKIDir == "" {
		return fmt.Errorf("enrolled node identity and pki_dir required")
	}
	dir := *cacheDir
	if dir == "" {
		dir = cfg.Node.RelayCacheDir
	}
	if dir == "" {
		dir = filepath.Join(cfg.Node.PKIDir, "relay-cache")
	}
	ctx, stop := signalContext()
	defer stop()
	events, err := underlayevent.New(cfg.Node.RelayUnderlays)
	if err != nil {
		return err
	}
	defer events.Close()
	ctx = relayobserve.WithUnderlayEvents(ctx, events)
	encoder := json.NewEncoder(os.Stdout)
	for i := 0; *watch || i < *samples; i++ {
		var cycleErr error
		if apply {
			out, err := reconcileApplicationTarget(ctx, cfg.Node, dir, *target, *controller, *timeout, selector)
			cycleErr = err
			if err := encoder.Encode(out); err != nil {
				return err
			}
		} else {
			report := collectTargetObservation(ctx, cfg.Node, dir, *target, *controller, *timeout)
			decision := selector.Decide(report)
			if err := encoder.Encode(decision); err != nil {
				return err
			}
			cycleErr = decision.Error()
		}
		if ctx.Err() != nil {
			return nil
		}
		if !*watch && i+1 == *samples {
			return cycleErr
		}
		// A relevant event wakes the next bounded cycle; periodic full verification
		// remains required even when the event stream is quiet.
		_ = events.Wait(ctx, *interval)
	}
	return nil
}

func reconcileApplicationTarget(parent context.Context, node *config.NodeConfig, dir, target, controller string, timeout time.Duration, selector *relayselect.Selector) (relayapply.TargetReconcileResult, error) {
	started := time.Now()
	parent, recorder := relayobserve.Start(parent)
	ctx, cancel := context.WithTimeout(parent, relayapply.MaxDuration)
	defer cancel()
	admission, done := relayobserve.Phase(ctx, "admission")
	cache, engine, err := openNodeRelayEngine(admission, node, dir)
	done()
	if err != nil {
		return relayapply.TargetReconcileResult{SchemaVersion: 1, StartedAt: started, FinishedAt: time.Now(), Diagnostics: recorder.Snapshot(), Selection: relayselect.Decision{SchemaVersion: 1, NodeID: node.Name, TargetID: target, State: "unknown", Reason: nodeAdmissionReason(err), Candidates: []relayselect.Candidate{}}, Application: relayapply.TargetGuardResult{SchemaVersion: 1, TargetID: target, State: "blocked", Reason: nodeAdmissionReason(err)}}, err
	}
	defer cache.Close()
	defer engine.Close()
	return engine.ReconcileTarget(ctx, target, controller, selector, timeout)
}

func collectTargetObservation(ctx context.Context, node *config.NodeConfig, dir, target, controller string, timeout time.Duration) relayapply.TargetReport {
	ctx, recorder := relayobserve.Start(ctx)
	// Release locks between cycles so refresh/prepare can proceed. Busy/corrupt
	// cache is unknown and immediately withdraws a recommendation, never healthy.
	unavailable := relayapply.TargetReport{SchemaVersion: 1, NodeID: node.Name, TargetID: target, Reason: "cache_unavailable", Paths: []relayapply.TargetObservation{}}
	admission, done := relayobserve.Phase(ctx, "admission")
	cache, engine, err := openNodeRelayEngine(admission, node, dir)
	done()
	if err != nil {
		unavailable.Diagnostics = recorder.Snapshot()
		return unavailable
	}
	defer cache.Close()
	defer engine.Close()
	report, _ := engine.ObserveTarget(ctx, target, controller, timeout)
	return report
}
