// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
	"vpnctl/internal/history"
)

func runFleetStorage(args []string) error {
	fs := flag.NewFlagSet("fleet storage", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "node client YAML")
	asJSON := fs.Bool("json", false, "cached storage observation as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || fs.NArg() != 0 {
		return fmt.Errorf("--config required; positional arguments not accepted")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Node == nil {
		return fmt.Errorf("node config required")
	}
	client := newAPIClient(cfg.Node)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := client.FleetStorage(ctx)
	if err != nil {
		return err
	}
	return printFleetStorage(os.Stdout, result, *asJSON)
}
func printFleetStorage(w io.Writer, h history.StorageHealth, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(h)
	}
	if _, err := fmt.Fprintf(w, "Storage collection: %s reason=%s stale=%t observed=%v last-success=%v\n", h.Validity, h.Reason, h.Stale, h.ObservedAt, h.LastSuccessAt); err != nil {
		return err
	}
	if h.Validity != "observed" || h.Stale || h.Values == nil {
		return nil
	}
	// The full bounded values object avoids omitting reclamation ranges or units
	// from the operator view; JSON mode preserves the full envelope as well.
	out := json.NewEncoder(w)
	out.SetIndent("", "  ")
	return out.Encode(h.Values)
}
