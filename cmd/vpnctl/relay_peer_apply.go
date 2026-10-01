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
	"vpnctl/internal/relaycache"
)

func runRelayPeerApply(args []string) error {
	fs := flag.NewFlagSet("relay "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "enrolled relay identity YAML")
	relay := fs.String("relay-id", "", "approved relay ID")
	dir := fs.String("cache-dir", "", "private deployment cache directory")
	endpoint := fs.String("endpoint-id", "", "approved endpoint ID (apply/release)")
	key := fs.String("key-file", "", "external 0600 private WG key in an owned 0700 directory (apply)")
	generation := fs.Uint64("key-generation", 0, "local WG key generation (apply)")
	port := fs.Int("listen-port", 0, "local UDP listen port, independent of external NAT port (apply)")
	timeout := fs.Duration("timeout", relayapply.MaxDuration, "deadline, at most 1m; rollback has an independent 1m budget")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *timeout <= 0 || *timeout > relayapply.MaxDuration {
		return fmt.Errorf("unexpected arguments or timeout outside (0,1m]")
	}
	apply := args[0] == "apply"
	if (apply || args[0] == "release") != (*endpoint != "") {
		return fmt.Errorf("apply/release require --endpoint-id; inspect/recover do not accept it")
	}
	if apply && (*key == "" || *generation == 0 || *port < 1 || *port > 65535) {
		return fmt.Errorf("apply requires key-file, key-generation and listen-port in [1,65535]")
	}
	invalid := false
	fs.Visit(func(f *flag.Flag) {
		if !apply && (f.Name == "key-file" || f.Name == "key-generation" || f.Name == "listen-port") {
			invalid = true
		}
	})
	if invalid {
		return fmt.Errorf("key-file, key-generation and listen-port require apply")
	}
	if err := relaycache.ValidateDeploymentIdentity("placeholder", *relay); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.PKIDir == "" {
		return fmt.Errorf("enrolled relay identity and pki_dir required")
	}
	if *dir == "" {
		*dir = filepath.Join(cfg.Node.PKIDir, "relay-deployments", *relay)
	}
	s, err := relaycache.OpenDeployment(*dir, relaycache.DeploymentOptions{PrincipalID: cfg.Node.Name, RelayID: *relay})
	if err != nil {
		return err
	}
	defer s.Close()
	e, err := relayapply.OpenDeployment(s)
	if err != nil {
		return err
	}
	defer e.Close()
	parent, stop := signalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	var out relayapply.DeploymentResult
	switch args[0] {
	case "apply":
		out, err = e.Apply(ctx, relayapply.DeploymentOptions{EndpointID: *endpoint, KeyFile: *key, KeyGeneration: *generation, ListenPort: *port})
	case "inspect":
		out, err = e.Inspect(ctx)
	case "release":
		out, err = e.Release(ctx, *endpoint)
	case "recover":
		out, err = e.Recover(ctx)
	}
	if output := json.NewEncoder(os.Stdout).Encode(out); output != nil {
		return output
	}
	return err
}
