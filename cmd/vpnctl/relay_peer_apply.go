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
	lockWait := fs.Duration("lock-wait", 0, "optional total cache/namespace lock wait, at most 5s and within timeout; default fails fast")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *timeout <= 0 || *timeout > relayapply.MaxDuration {
		return fmt.Errorf("unexpected arguments or timeout outside (0,1m]")
	}
	if *lockWait < 0 || *lockWait > 5*time.Second || *lockWait > *timeout {
		return fmt.Errorf("lock-wait must be in [0,5s] and no greater than timeout")
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
	parent, stop := signalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	// Both locks share one wait budget, charged to the operation deadline.
	lockCtx := ctx
	if *lockWait > 0 {
		var stopWait context.CancelFunc
		lockCtx, stopWait = context.WithTimeout(ctx, *lockWait)
		defer stopWait()
	}
	s, err := openRelayCommandLock(lockCtx, *lockWait > 0, func() (*relaycache.DeploymentStore, error) {
		return relaycache.OpenDeployment(*dir, relaycache.DeploymentOptions{PrincipalID: cfg.Node.Name, RelayID: *relay})
	}, relaycache.ErrBusy)
	if err != nil {
		return err
	}
	defer s.Close()
	e, err := openRelayCommandLock(lockCtx, *lockWait > 0, func() (*relayapply.DeploymentEngine, error) {
		return relayapply.OpenDeployment(s)
	}, relayapply.ErrKernelBusy)
	if err != nil {
		return err
	}
	defer e.Close()
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

func openRelayCommandLock[T any](ctx context.Context, wait bool, open func() (T, error), busy error) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, errors.Join(busy, err)
	}
	if !wait {
		return open()
	}
	value, err := retrySupervisedLock(ctx, open, busy)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return value, errors.Join(busy, err)
	}
	return value, err
}
