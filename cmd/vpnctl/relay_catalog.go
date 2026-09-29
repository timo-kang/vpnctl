// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

func readRelaySpec(path string) (relaycatalog.Spec, error) {
	var s relaycatalog.Spec
	f, e := os.Open(path)
	if e != nil {
		return s, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, relaycatalog.MaxDocumentBytes+1))
	if e != nil {
		return s, e
	}
	if len(b) > relaycatalog.MaxDocumentBytes {
		return s, fmt.Errorf("catalog file exceeds 1MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&s); e != nil {
		return s, e
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return s, fmt.Errorf("catalog file must contain one JSON document")
	}
	return s, nil
}
func runControllerRelay(args []string) error {
	if len(args) == 0 || args[0] != "status" && args[0] != "apply" {
		return fmt.Errorf("controller relay status|apply required")
	}
	fs := flag.NewFlagSet("controller relay "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "controller YAML configuration")
	file := fs.String("file", "", "approved catalog JSON file")
	id := fs.String("controller-id", "", "identity from relay status (empty only for initialization)")
	gen := fs.Uint64("generation", 0, "expected current catalog generation (0 only for initialization)")
	ttl := fs.Duration("ttl", time.Hour, "catalog validity window, 1m..24h")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	req := api.AdminRequest{Operation: "relay.catalog." + args[0]}
	if args[0] == "apply" {
		if *file == "" {
			return fmt.Errorf("apply requires --file")
		}
		if *ttl < time.Minute || *ttl > 24*time.Hour || *ttl%time.Second != 0 {
			return fmt.Errorf("ttl must be whole seconds in 1m..24h")
		}
		spec, e := readRelaySpec(*file)
		if e != nil {
			return e
		}
		req.RelayCatalog = &relaycatalog.Update{ControllerID: *id, ExpectedGeneration: *gen, TTLSeconds: int(ttl.Seconds()), Spec: spec}
	}
	cfg, e := loadConfig(*cfgPath)
	if e != nil {
		return e
	}
	if cfg.Controller == nil {
		return fmt.Errorf("controller config required")
	}
	response, e := api.Admin(context.Background(), cfg.Controller.DataDir, req)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(response)
}
func runNodeRelay(args []string) error {
	if len(args) == 0 || args[0] != "catalog" && args[0] != "bind" && args[0] != "refresh" && args[0] != "status" {
		return fmt.Errorf("node relay catalog|bind|refresh|status required")
	}
	fs := flag.NewFlagSet("node relay "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "enrolled node YAML configuration")
	id := fs.String("controller-id", "", "approved controller catalog identity")
	gen := fs.Uint64("generation", 0, "expected current catalog generation")
	path := fs.String("path-id", "", "approved candidate path ID")
	key := fs.String("public-key", "", "node's distinct WireGuard public key for this path")
	cacheDir := fs.String("cache-dir", "", "node's private relay cache directory (default: node.relay_cache_dir or pki_dir/relay-cache)")
	timeout := fs.Duration("timeout", relaycache.MaxRefreshDuration, "refresh deadline, at most 2m")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if args[0] == "catalog" || args[0] == "bind" {
		var cacheFlag bool
		fs.Visit(func(f *flag.Flag) { cacheFlag = cacheFlag || f.Name == "cache-dir" || f.Name == "timeout" })
		if cacheFlag {
			return fmt.Errorf("cache-dir/timeout require refresh or status")
		}
	}
	if args[0] == "bind" {
		if *id == "" || *gen == 0 || *path == "" {
			return fmt.Errorf("bind requires --controller-id, --generation, --path-id and --public-key")
		}
		if e := relaycatalog.ValidatePublicKey(*key); e != nil {
			return e
		}
	}
	cfg, e := loadConfig(*cfgPath)
	if e != nil {
		return e
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.Controller == "" || cfg.Node.PKIDir == "" {
		return fmt.Errorf("enrolled node identity, controller and pki_dir required")
	}
	if args[0] == "refresh" || args[0] == "status" {
		if *id != "" || *gen != 0 || *path != "" || *key != "" {
			return fmt.Errorf("refresh/status do not accept manual binding flags")
		}
		if *timeout <= 0 || *timeout > relaycache.MaxRefreshDuration {
			return fmt.Errorf("timeout must be positive and at most 2m")
		}
		dir := *cacheDir
		if dir == "" {
			dir = cfg.Node.RelayCacheDir
		}
		if dir == "" {
			dir = filepath.Join(cfg.Node.PKIDir, "relay-cache")
		}
		legacy := []string{cfg.Node.WGPublicKey, cfg.Node.ServerPublicKey}
		if cfg.Node.WGPrivateKey != "" {
			data, err := base64.StdEncoding.DecodeString(cfg.Node.WGPrivateKey)
			if err != nil {
				return fmt.Errorf("invalid legacy WireGuard private key")
			}
			private, err := ecdh.X25519().NewPrivateKey(data)
			if err != nil {
				return fmt.Errorf("invalid legacy WireGuard private key")
			}
			public := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
			if cfg.Node.WGPublicKey != "" && relaycatalog.PublicKeyID(cfg.Node.WGPublicKey) != public {
				return fmt.Errorf("legacy WireGuard key pair mismatch")
			}
			legacy = append(legacy, public)
		}
		cache, err := relaycache.Open(dir, relaycache.Options{NodeID: cfg.Node.Name, Create: args[0] == "refresh", LegacyPublicKeys: legacy})
		if errors.Is(err, relaycache.ErrMissing) && args[0] == "status" {
			return json.NewEncoder(os.Stdout).Encode(relaycache.MissingReport(cfg.Node.Name))
		}
		if err != nil {
			return err
		}
		defer cache.Close()
		var report relaycache.Report
		if args[0] == "status" {
			report, err = cache.Status()
		} else {
			client := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
			defer client.CloseIdleConnections()
			parent, stop := signalContext()
			defer stop()
			ctx, cancel := context.WithTimeout(parent, *timeout)
			defer cancel()
			report, err = cache.Refresh(ctx, client)
		}
		if outputErr := json.NewEncoder(os.Stdout).Encode(report); outputErr != nil {
			return outputErr
		}
		return err
	}
	client := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
	defer client.CloseIdleConnections()
	var v relaycatalog.View
	if args[0] == "catalog" {
		v, e = client.RelayCatalog(context.Background(), cfg.Node.Name)
	} else {
		v, e = client.BindRelayPath(context.Background(), relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: *id, ExpectedGeneration: *gen, NodeID: cfg.Node.Name, PathID: *path, PublicKey: *key})
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(v)
}
