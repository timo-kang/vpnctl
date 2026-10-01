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

	"vpnctl/internal/api"
	"vpnctl/internal/relaycache"
)

func runRelayDeploymentCache(args []string) error {
	fs := flag.NewFlagSet("relay "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "enrolled relay identity YAML")
	relay := fs.String("relay-id", "", "explicitly authorized relay ID")
	dir := fs.String("cache-dir", "", "private cache directory (default: pki_dir/relay-deployments/relay-id)")
	timeout := fs.Duration("timeout", relaycache.MaxDeploymentRefreshDuration, "refresh deadline, at most 20s")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if len(fs.Args()) != 0 || *timeout <= 0 || *timeout > relaycache.MaxDeploymentRefreshDuration {
		return fmt.Errorf("relay cache commands require timeout in (0,20s] with no positional arguments")
	}
	timeoutSet := false
	fs.Visit(func(f *flag.Flag) { timeoutSet = timeoutSet || f.Name == "timeout" })
	if args[0] == "status" && timeoutSet {
		return fmt.Errorf("status is offline; --timeout requires refresh")
	}
	// Validate before joining relay ID into a directory path.
	if e := relaycache.ValidateDeploymentIdentity("placeholder", *relay); e != nil {
		return e
	}
	cfg, e := loadConfig(*cfgPath)
	if e != nil {
		return e
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.PKIDir == "" || args[0] == "refresh" && cfg.Node.Controller == "" {
		return fmt.Errorf("enrolled identity and pki_dir required; refresh also requires controller")
	}
	if *dir == "" {
		*dir = filepath.Join(cfg.Node.PKIDir, "relay-deployments", *relay)
	}
	s, e := relaycache.OpenDeployment(*dir, relaycache.DeploymentOptions{PrincipalID: cfg.Node.Name, RelayID: *relay, Create: args[0] == "refresh"})
	if errors.Is(e, relaycache.ErrMissing) && args[0] == "status" {
		return json.NewEncoder(os.Stdout).Encode(relaycache.MissingDeploymentReport(cfg.Node.Name, *relay))
	}
	if e != nil {
		return e
	}
	defer s.Close()
	var report relaycache.DeploymentReport
	if args[0] == "status" {
		report, e = s.Status()
	} else {
		client := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
		defer client.CloseIdleConnections()
		parent, stop := signalContext()
		defer stop()
		ctx, cancel := context.WithTimeout(parent, *timeout)
		defer cancel()
		report, e = s.Refresh(ctx, client)
	}
	if outputErr := json.NewEncoder(os.Stdout).Encode(report); outputErr != nil {
		return outputErr
	}
	return e
}
