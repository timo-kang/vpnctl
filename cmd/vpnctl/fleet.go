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
	"os"
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
	fmt.Fprintln(output, "NAME  VPN_IP  CONTACT  QUALITY  STALE  PEER  REPORTED_PATH  RELAY  UPLINK  SOURCE  RTT_MS  LOSS%  REASON  LAST_SEEN")
	for _, n := range resp.Nodes {
		fmt.Fprintf(output, "%s  %s  %s  %s  %t  %s  %s  %s  %s  %s  %s  %s  %s  %s\n", n.Name, n.VPNIP, n.Status, n.Quality, n.Stale, n.PeerID, n.Path, n.RelayID, n.Uplink, n.Source, history.FormatNumber(n.RTTMs), history.FormatNumber(n.LossPct), n.ErrorReason, n.LastSeen)
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
		fmt.Fprintln(output, "TIME  PEER  REPORTED_PATH  RELAY  UPLINK  SOURCE  SAMPLES  UNKNOWN  AVAILABLE%  AVG_RTT_MS  P95_RTT_MS  LOSS%")
		for _, b := range n.Buckets {
			fmt.Fprintf(output, "%s  %s  %s  %s  %s  %s  %d  %d  %s  %s  %s  %s\n", b.Time.Format(time.RFC3339), b.PeerID, b.Path, b.RelayID, b.Uplink, b.Source, b.Count, b.UnknownCount, history.FormatNumber(b.AvailabilityPct), history.FormatNumber(b.AvgRTTMs), history.FormatNumber(b.P95RTTMs), history.FormatNumber(b.LossPct))
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

func runFleetUplinks(args []string) error {
	fs := flag.NewFlagSet("fleet uplinks", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "node client YAML")
	node := fs.String("node", "", "node identity (required)")
	window := fs.String("window", "1h", "history window, at most 7d")
	limit := fs.Int("limit", 100, "recent diagnostic snapshots, 1..1000")
	asJSON := fs.Bool("json", false, "full staged observations and history")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *node == "" {
		return fmt.Errorf("--config and --node required")
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.FleetUplinks(ctx, *node, *window, *limit)
	if err != nil {
		return err
	}
	return printFleetUplinks(os.Stdout, result, *asJSON)
}
func runFleetEvents(args []string) error {
	fs := flag.NewFlagSet("fleet events", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "node client YAML")
	node := fs.String("node", "", "node identity (or --controller)")
	controller := fs.Bool("controller", false, "controller PKI event stream")
	window := fs.String("window", "24h", "event window, at most 7d")
	limit := fs.Int("limit", 500, "recent events, 1..1000")
	asJSON := fs.Bool("json", false, "full event history as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || (*node != "") == *controller {
		return fmt.Errorf("--config and exactly one of --node or --controller required")
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.FleetEvents(ctx, *node, *window, *limit)
	if err != nil {
		return err
	}
	return printFleetEvents(os.Stdout, result, *asJSON)
}

func printFleetEvents(w io.Writer, result history.EventHistory, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(result)
	}
	out := bufio.NewWriter(w)
	fmt.Fprintf(out, "Events (%s, %s], truncated=%t\n", result.Start.Format(time.RFC3339), result.End.Format(time.RFC3339), result.Truncated)
	fmt.Fprintln(out, "TIME  KIND  TARGET  SEVERITY  PREVIOUS  CURRENT  SOURCE  MESSAGE")
	for _, e := range result.Events {
		fmt.Fprintf(out, "%s  %s  %s  %s  %s  %s  %s  %s\n", e.Timestamp.Format(time.RFC3339), e.Kind, e.Target, e.Severity, e.Previous, e.Current, e.Source, e.Message)
	}
	return out.Flush()
}

func runFleetAlerts(args []string) error {
	fs := flag.NewFlagSet("fleet alerts", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "node client YAML")
	node := fs.String("node", "", "node identity (required)")
	asJSON := fs.Bool("json", false, "alerts as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *node == "" {
		return fmt.Errorf("--config and --node required")
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	alerts, err := client.FleetAlerts(ctx, *node)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(alerts)
	}
	return printFleetAlerts(os.Stdout, alerts)
}

func printFleetAlerts(w io.Writer, alerts []history.Alert) error {
	out := bufio.NewWriter(w)
	fmt.Fprintln(out, "CODE  ACTIVE  SEVERITY  LAST_SEEN  REASON")
	for _, a := range alerts {
		fmt.Fprintf(out, "%s  %t  %s  %s  %s\n", a.Code, a.Active, a.Severity, a.LastSeen.Format(time.RFC3339), a.Reason)
	}
	return out.Flush()
}

func printFleetUplinks(w io.Writer, result history.UplinkHistory, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(result)
	}
	out := bufio.NewWriter(w)
	fmt.Fprintln(out, "TARGET  PROTOCOL  SUCCESS  FAILURE  UNKNOWN  AVAILABLE%  AVG_RTT_MS")
	for _, v := range result.Summaries {
		fmt.Fprintf(out, "%s  %s  %d  %d  %d  %s  %s\n", v.TargetID, v.Protocol, v.Successes, v.Failures, v.Unknown, history.FormatNumber(v.AvailabilityPct), history.FormatNumber(v.AvgRTTMs))
	}
	if len(result.Snapshots) > 0 {
		s := result.Snapshots[0]
		fmt.Fprintf(out, "Latest: %s stale=%t underlay=%s reason=%s dropped=%d\n", s.At.Format(time.RFC3339), s.Stale, s.Underlay.State, s.Underlay.Reason, s.Dropped)
		for _, l := range s.Links {
			fmt.Fprintf(out, "Link %s (%s/%s): %s/%s modem=%s/%s controller=%s/%s\n", l.ID, l.Interface, l.Kind, l.State, l.Reason, l.Modem.State, l.Modem.Reason, l.Controller.State, l.Controller.Reason)
		}
		for _, t := range s.Targets {
			fmt.Fprintf(out, "Target %s: service=%s/%s failure_stage=%s route=%s/%s source=%s gateway=%s expected_relay=%s relay_probe=%s/%s\n", t.ID, t.Service.State, t.Service.Reason, t.FailureStage, t.Route.State, t.Route.Interface, t.Route.Source, t.Route.Gateway, t.ExpectedRelayID, t.Relay.State, t.Relay.Reason)
			fmt.Fprintf(out, "  Transport: %s/%s source=%s gateway=%s peer_fingerprint=%s\n", t.TransportRoute.State, t.TransportRoute.Interface, t.TransportRoute.Source, t.TransportRoute.Gateway, t.RelayPeerFingerprint)
		}
	}
	return out.Flush()
}
