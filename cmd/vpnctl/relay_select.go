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
	"vpnctl/internal/relayselect"
)

func runNodeRelaySelect(args []string) error {
	fs := flag.NewFlagSet("node relay select", flag.ContinueOnError)
	configPath := fs.String("config", "", "enrolled node configuration")
	cacheDir := fs.String("cache-dir", "", "private relay cache directory")
	target := fs.String("target-id", "", "approved application target ID")
	controller := fs.String("controller-id", "", "expected controller identity")
	watch := fs.Bool("watch", false, "continuously report desired paths; never change application routes")
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
	encoder := json.NewEncoder(os.Stdout)
	for i := 0; *watch || i < *samples; i++ {
		report := collectTargetObservation(ctx, cfg.Node, dir, *target, *controller, *timeout)
		decision := selector.Decide(report)
		if err := encoder.Encode(decision); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !*watch && i+1 == *samples {
			return decision.Error()
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func collectTargetObservation(ctx context.Context, node *config.NodeConfig, dir, target, controller string, timeout time.Duration) relayapply.TargetReport {
	// Release locks between cycles so refresh/prepare can proceed. Busy/corrupt
	// cache is unknown and immediately withdraws a recommendation, never healthy.
	unavailable := relayapply.TargetReport{SchemaVersion: 1, NodeID: node.Name, TargetID: target, Reason: "cache_unavailable", Paths: []relayapply.TargetObservation{}}
	cache, engine, err := openNodeRelayEngine(ctx, node, dir)
	if err != nil {
		return unavailable
	}
	defer cache.Close()
	defer engine.Close()
	report, _ := engine.ObserveTarget(ctx, target, controller, timeout)
	return report
}
