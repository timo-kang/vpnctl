// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/controller"
	"vpnctl/internal/history"
)

func printFleetStatus(w io.Writer, resp api.FleetStatusResponse, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(resp)
	}
	output := bufio.NewWriter(w)
	fmt.Fprintln(output, "NAME  VPN_IP  CONTACT  QUALITY  STALE  PEER  REPORTED_PATH  RELAY  UPLINK  RTT_MS  LOSS%  REASON  LAST_SEEN")
	for _, n := range resp.Nodes {
		fmt.Fprintf(output, "%s  %s  %s  %s  %t  %s  %s  %s  %s  %s  %s  %s  %s\n", n.Name, n.VPNIP, n.Status, n.Quality, n.Stale, n.PeerID, n.Path, n.RelayID, n.Uplink, history.FormatNumber(n.RTTMs), history.FormatNumber(n.LossPct), n.ErrorReason, n.LastSeen)
	}
	return output.Flush()
}
func printFleetHistory(w io.Writer, resp api.FleetHistoryResponse, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(resp)
	}
	output := bufio.NewWriter(w)
	fmt.Fprintf(output, "Window (%s, %s], buckets %.0fs; availability = successful probes / attempts\n", resp.Start.Format(time.RFC3339), resp.End.Format(time.RFC3339), resp.BucketSeconds)
	for _, n := range resp.Nodes {
		fmt.Fprintf(output, "Node: %s (%s)\n", n.Name, n.NodeID)
		fmt.Fprintln(output, "TIME  PEER  REPORTED_PATH  RELAY  UPLINK  SAMPLES  AVAILABLE%  AVG_RTT_MS  P95_RTT_MS  LOSS%")
		for _, b := range n.Buckets {
			fmt.Fprintf(output, "%s  %s  %s  %s  %s  %d  %s  %s  %s  %s\n", b.Time.Format(time.RFC3339), b.PeerID, b.Path, b.RelayID, b.Uplink, b.Count, history.FormatNumber(b.AvailabilityPct), history.FormatNumber(b.AvgRTTMs), history.FormatNumber(b.P95RTTMs), history.FormatNumber(b.LossPct))
		}
	}
	return output.Flush()
}

func runControllerHistory(args []string) error {
	if len(args) == 0 || (args[0] != "backup" && args[0] != "restore") {
		return fmt.Errorf("history subcommand required: backup|restore (controller must be stopped)")
	}
	fs := flag.NewFlagSet("controller history "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "controller YAML configuration")
	out := fs.String("out", "", "new backup output file")
	in := fs.String("file", "", "history backup to restore into an absent history.db")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("--config required")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Controller == nil {
		return fmt.Errorf("controller config required")
	}
	config.ApplyDefaults(&cfg)
	if args[0] == "backup" && *out == "" || args[0] == "restore" && *in == "" {
		return fmt.Errorf("backup requires --out; restore requires --file")
	}
	lock, err := controller.AcquireStateLock(cfg.Controller.DataDir)
	if err != nil {
		return fmt.Errorf("stop controller before history maintenance: %w", err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	path := filepath.Join(cfg.Controller.DataDir, "history.db")
	if args[0] == "backup" {
		return history.Backup(ctx, path, *out)
	}
	return history.Restore(ctx, *in, path, time.Now())
}
