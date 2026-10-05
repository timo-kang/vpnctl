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

	"vpnctl/internal/relayapply"
)

func runNodeRelayTarget(args []string) error {
	if len(args) == 0 || args[0] != "reserve" && args[0] != "inspect" && args[0] != "recover" && args[0] != "release" {
		return fmt.Errorf("node relay target reserve|inspect|recover|release required; reserve blocks application traffic")
	}
	fs := flag.NewFlagSet("node relay target "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "enrolled node configuration")
	cacheDir := fs.String("cache-dir", "", "private relay cache directory")
	target := fs.String("target-id", "", "approved application target ID")
	controller := fs.String("controller-id", "", "expected controller identity (reserve only)")
	timeout := fs.Duration("timeout", relayapply.MaxDuration, "bounded operation deadline, at most 1m")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *target == "" || *timeout <= 0 || *timeout > relayapply.MaxDuration || *controller != "" && args[0] != "reserve" {
		return fmt.Errorf("target-id, timeout in (0,1m] and no positional arguments required; controller-id is reserve only")
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
	parent, stop := signalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	cache, engine, err := openNodeRelayEngine(ctx, cfg.Node, dir)
	if err != nil {
		return err
	}
	defer cache.Close()
	defer engine.Close()
	var out relayapply.TargetGuardResult
	switch args[0] {
	case "reserve":
		out, err = engine.ReserveTarget(ctx, *target, *controller)
	case "inspect":
		out, err = engine.InspectTarget(ctx, *target)
	case "recover":
		out, err = engine.RecoverTarget(ctx, *target)
	case "release":
		out, err = engine.ReleaseTarget(ctx, *target)
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
		return encodeErr
	}
	return err
}
