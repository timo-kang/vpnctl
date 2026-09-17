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
	"vpnctl/internal/uplink"
)

func runNodeDiagnose(args []string) error {
	fs := flag.NewFlagSet("node diagnose", flag.ContinueOnError)
	path := fs.String("config", "", "node YAML with uplink_observation")
	submit := fs.Bool("submit", false, "submit this snapshot to the controller")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("--config required")
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if cfg.Node == nil || cfg.Node.UplinkObservation == nil {
		return fmt.Errorf("node.uplink_observation required")
	}
	c := cfg.Node.UplinkObservation
	if err = c.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	observer := uplink.Observer{Config: *c, Collector: uplink.LinuxCollector{}, Prober: uplink.NetworkProber{}}
	snapshot := observer.Collect(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if *submit {
		client := newAPIClient(cfg.Node)
		defer client.CloseIdleConnections()
		if err = client.SubmitUplink(ctx, api.UplinkRequest{NodeID: cfg.Node.Name, Snapshot: snapshot}); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(snapshot)
}
