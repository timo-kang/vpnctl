// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

func runControllerRelayRecipient(args []string) error {
	fs := flag.NewFlagSet("controller relay "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "controller YAML configuration")
	id := fs.String("controller-id", "", "identity from relay status")
	gen := fs.Uint64("generation", 0, "expected current catalog generation")
	relay := fs.String("relay-id", "", "approved relay ID")
	principal := fs.String("principal", "", "enrolled identity allowed to receive this relay's peer metadata")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if len(fs.Args()) != 0 || *id == "" || *gen == 0 || *relay == "" {
		return fmt.Errorf("grant/withdraw require --controller-id, --generation and --relay-id with no positional arguments")
	}
	if args[0] == "grant" && *principal == "" || args[0] == "withdraw" && *principal != "" {
		return fmt.Errorf("--principal is required for grant and forbidden for withdraw")
	}
	cfg, e := loadConfig(*cfgPath)
	if e != nil {
		return e
	}
	if cfg.Controller == nil {
		return fmt.Errorf("controller config required")
	}
	response, e := api.Admin(context.Background(), cfg.Controller.DataDir, api.AdminRequest{Operation: "relay.recipient.set", RelayRecipient: &relaycatalog.RecipientUpdate{
		ControllerID: *id, ExpectedGeneration: *gen, RelayID: *relay, PrincipalID: *principal,
	}})
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(response)
}

// Relay commands separate approval reads, PKI synchronization and owned peers.
func runRelayRecipient(args []string) error {
	if len(args) > 0 && args[0] == "supervise" {
		return runRelaySupervise(args[1:])
	}
	if len(args) > 0 && (args[0] == "prepare" || args[0] == "apply" || args[0] == "inspect" || args[0] == "release" || args[0] == "recover") {
		return runRelayPeerApply(args)
	}
	if len(args) > 0 && (args[0] == "refresh" || args[0] == "status") {
		return runRelayDeploymentCache(args)
	}
	if len(args) == 0 || args[0] != "catalog" && args[0] != "sync-credentials" {
		return fmt.Errorf("relay catalog|sync-credentials|refresh|status|prepare|apply|inspect|release|recover|supervise required")
	}
	fs := flag.NewFlagSet("relay "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "enrolled identity YAML configuration")
	relay := fs.String("relay-id", "", "explicitly authorized relay ID")
	timeout := fs.Duration("timeout", 20*time.Second, "request deadline, at most 20s")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if len(fs.Args()) != 0 || *timeout <= 0 || *timeout > 20*time.Second {
		return fmt.Errorf("relay commands require timeout in (0,20s] with no positional arguments")
	}
	if args[0] == "catalog" && *relay == "" || args[0] == "sync-credentials" && *relay != "" {
		return fmt.Errorf("--relay-id is required for catalog and forbidden for sync-credentials")
	}
	cfg, e := loadConfig(*cfgPath)
	if e != nil {
		return e
	}
	if cfg.Node == nil || cfg.Node.Name == "" || cfg.Node.Controller == "" || cfg.Node.PKIDir == "" {
		return fmt.Errorf("enrolled identity, controller and pki_dir required")
	}
	client := api.NewCredentialClient(cfg.Node.Controller, cfg.Node.PKIDir)
	defer client.CloseIdleConnections()
	parent, stop := signalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	if args[0] == "sync-credentials" {
		if e := client.SyncCredentials(ctx, cfg.Node.PKIDir, cfg.Node.Name); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			PrincipalID   string `json:"principal_id"`
			State         string `json:"state"`
		}{1, cfg.Node.Name, "credentials_synchronized"})
	}
	view, e := client.RelayDeployment(ctx, cfg.Node.Name, *relay)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(view)
}
