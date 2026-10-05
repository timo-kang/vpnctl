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

func runNodeRelayApply(args []string) error {
	fs := flag.NewFlagSet("node relay "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "enrolled node configuration")
	cacheDir := fs.String("cache-dir", "", "private relay cache directory")
	probeRoutes := fs.Bool("probe-routes", false, "prepare owned target routes for explicit candidate-source probes")
	appRoutes := fs.Bool("app-routes", false, "prepare expiring application candidate with device-bound probes; implies --lease --probe-routes")
	lease := fs.Bool("lease", false, "install initially closed BOOTTIME/nft expiry protection; requires node relay supervise")
	path := fs.String("path-id", "", "approved path ID (prepare/release)")
	controller := fs.String("controller-id", "", "expected controller identity (prepare)")
	timeout := fs.Duration("timeout", relayapply.MaxDuration, "operation deadline, at most 1m; rollback has an independent 1m budget")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) > 0 || *timeout <= 0 || *timeout > relayapply.MaxDuration {
		return fmt.Errorf("unexpected arguments or timeout outside (0,1m]")
	}
	if (args[0] == "prepare" || args[0] == "release") != (*path != "") {
		return fmt.Errorf("prepare/release require --path-id; inspect/recover do not accept it")
	}
	if *probeRoutes && args[0] != "prepare" {
		return fmt.Errorf("probe-routes is only accepted by prepare")
	}
	if *appRoutes && args[0] != "prepare" {
		return fmt.Errorf("app-routes is only accepted by prepare")
	}
	if *lease && args[0] != "prepare" {
		return fmt.Errorf("lease is only accepted by prepare")
	}
	if *controller != "" && args[0] != "prepare" {
		return fmt.Errorf("controller-id is only accepted by prepare")
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
	var out relayapply.Result
	switch args[0] {
	case "prepare":
		if *appRoutes {
			out, err = engine.PrepareApplication(ctx, *path, *controller)
		} else if *lease {
			out, err = engine.PrepareProtected(ctx, *path, *controller, *probeRoutes)
		} else if *probeRoutes {
			out, err = engine.PrepareProbe(ctx, *path, *controller)
		} else {
			out, err = engine.Prepare(ctx, *path, *controller)
		}
	case "inspect":
		out, err = engine.Inspect(ctx)
	case "release":
		out, err = engine.Release(ctx, *path)
	case "recover":
		out, err = engine.Recover(ctx)
	}
	if outputErr := json.NewEncoder(os.Stdout).Encode(out); outputErr != nil {
		return outputErr
	}
	return err
}
