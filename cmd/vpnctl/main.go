// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crypto/tls"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vpnctl/internal/addrutil"
	"vpnctl/internal/agent"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/controller"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/model"
	"vpnctl/internal/monitor"
	"vpnctl/internal/peersource"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
	"vpnctl/internal/stunutil"
	"vpnctl/internal/wireguard"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

const usage = `vpnctl - minimal VPN control-plane + metrics (MVP)

Usage:
  vpnctl version
  vpnctl controller init --config <path>
  vpnctl controller status --config <path>
  vpnctl controller token create|list|revoke --config <path>
  vpnctl node join --config <path> [--token <bootstrap-token>]
  vpnctl node serve --config <path>
  vpnctl node run --config <path>
  vpnctl node sync-config --config <path>
  vpnctl direct serve --config <path> [--listen :0]
  vpnctl direct test --config <path> --peer <name>
  vpnctl discover --config <path>
  vpnctl ping --config <path> --peer <name>|--all [--path auto|direct|relay]
  vpnctl perf --config <path> --peer <name> [--path auto|direct|relay]
 vpnctl stats --config <path> [--window 5m]
 vpnctl export csv --config <path> --out <file>
 vpnctl up --config <path> [--wg-config <path>] [--dry-run]
 vpnctl down --config <path> [--wg-config <path>]
 vpnctl status --config <path> [--iface <name>]
 vpnctl doctor --config <path> [--iface <name>]
  vpnctl monitor --interface <iface> [--watch] [--interval 5s] [--peers ip1,ip2]
  vpnctl fleet status --config <path> | --interface <iface>
  vpnctl fleet history --config <path> | --interface <iface> [--window 1h]

`

func setupLogging() {
	logLevel := os.Getenv("VPNCTL_LOG_LEVEL")
	logFormat := os.Getenv("VPNCTL_LOG_FORMAT")

	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(logFormat) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func main() {
	setupLogging()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
	case "version", "--version":
		fmt.Printf("vpnctl %s (commit %s, built %s)\n", version, commit, buildTime)
	case "controller":
		handleController(os.Args[2:])
	case "node":
		handleNode(os.Args[2:])
	case "direct":
		handleDirect(os.Args[2:])
	case "discover":
		handleDiscover(os.Args[2:])
	case "ping":
		handlePing(os.Args[2:])
	case "perf":
		handlePerf(os.Args[2:])
	case "stats":
		handleStats(os.Args[2:])
	case "export":
		handleExport(os.Args[2:])
	case "up":
		handleUp(os.Args[2:])
	case "down":
		handleDown(os.Args[2:])
	case "status":
		handleStatus(os.Args[2:])
	case "doctor":
		handleDoctor(os.Args[2:])
	case "monitor":
		handleMonitor(os.Args[2:])
	case "fleet":
		handleFleet(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func handleController(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "controller subcommand required\n")
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		controllerInit(args[1:])
	case "status":
		controllerStatus(args[1:])
	case "token":
		controllerToken(args[1:])
	case "remove-node":
		controllerRemoveNode(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown controller subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func controllerInit(args []string) {
	fs := flag.NewFlagSet("controller init", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	listen := fs.String("listen", "", "listen address")
	dataDir := fs.String("data-dir", "", "data directory")
	metricsPath := fs.String("metrics-path", "", "metrics CSV path")
	stunList := fs.String("stun", "", "comma-separated STUN servers")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Controller == nil {
		cfg.Controller = &config.ControllerConfig{}
	}

	overrideController(cfg.Controller, *listen, *dataDir, *metricsPath, *stunList)
	config.ApplyDefaults(&cfg)
	if err := config.Validate(cfg); err != nil {
		fatal(err)
	}

	srv, err := controller.NewServer(*cfg.Controller)
	if err != nil {
		fatal(err)
	}

	if cfg.Controller.PKI != nil {
		token, err := srv.InitPKI()
		if err != nil {
			fatal(err)
		}
		if token != "" {
			fmt.Fprintf(os.Stdout, "bootstrap token: %s\n", token)
		}
	}

	fatal(srv.ListenAndServe())
}

func controllerStatus(args []string) {
	fs := flag.NewFlagSet("controller status", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Controller == nil {
		fatal(errors.New("controller config required"))
	}
	config.ApplyDefaults(&cfg)
	if cfg.Controller.DataDir == "" {
		fatal(errors.New("controller.data_dir is required"))
	}

	regPath := filepath.Join(cfg.Controller.DataDir, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		fatal(err)
	}
	if reg == nil || len(reg.Nodes) == 0 {
		fmt.Fprintln(os.Stdout, "no registered nodes")
		return
	}

	wgEndpoints := map[string]string{}
	if cfg.Controller.WGInterface != "" {
		if m, err := wireguard.PeerEndpoints(cfg.Controller.WGInterface); err == nil {
			wgEndpoints = m
		}
	}

	fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-22s  %-10s  %-6s  %-20s  %-8s\n",
		"NAME", "VPN_IP", "WG_ENDPOINT", "PUBLIC_ADDR", "NAT", "PORT", "LAST_SEEN", "STATUS")
	for _, node := range reg.Nodes {
		lastSeen := ""
		if !node.LastSeenAt.IsZero() {
			lastSeen = node.LastSeenAt.UTC().Format(time.RFC3339)
		}
		wgEP := ""
		if node.PubKey != "" {
			wgEP = wgEndpoints[node.PubKey]
		}
		fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-22s  %-10s  %-6d  %-20s  %-8s\n",
			node.Name, node.VPNIP, wgEP, node.PublicAddr, node.NATType, node.ProbePort, lastSeen, node.Status)
	}
}

func controllerToken(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "controller token subcommand required (create|list|revoke)\n")
		os.Exit(2)
	}

	sub := args[0]
	fs := flag.NewFlagSet("controller token "+sub, flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	_ = fs.Parse(args[1:])

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Controller == nil {
		fatal(errors.New("controller config required"))
	}
	config.ApplyDefaults(&cfg)
	if cfg.Controller.DataDir == "" {
		fatal(errors.New("controller.data_dir is required"))
	}

	tokenPath := filepath.Join(cfg.Controller.DataDir, "pki", "bootstrap-tokens.json")
	ts, err := pki.OpenTokenStore(tokenPath)
	if err != nil {
		fatal(err)
	}

	switch sub {
	case "create":
		token := ts.Create()
		fmt.Fprintln(os.Stdout, token)
	case "list":
		tokens := ts.List()
		if len(tokens) == 0 {
			fmt.Fprintln(os.Stdout, "no active tokens")
			return
		}
		for _, t := range tokens {
			fmt.Fprintln(os.Stdout, t)
		}
	case "revoke":
		remaining := fs.Args()
		if len(remaining) == 0 {
			fatal(errors.New("token value is required"))
		}
		ts.Revoke(remaining[0])
		fmt.Fprintln(os.Stdout, "token revoked")
	default:
		fmt.Fprintf(os.Stderr, "unknown token subcommand %q\n", sub)
		os.Exit(2)
	}
}

func controllerRemoveNode(args []string) {
	fs := flag.NewFlagSet("controller remove-node", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	name := fs.String("name", "", "node name to remove")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "error: --name is required")
		os.Exit(2)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Controller == nil || cfg.Controller.DataDir == "" {
		fatal(fmt.Errorf("controller.data_dir required"))
	}
	config.ApplyDefaults(&cfg)

	regPath := filepath.Join(cfg.Controller.DataDir, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		fatal(err)
	}

	found := false
	filtered := make([]store.NodeInfo, 0, len(reg.Nodes))
	for _, n := range reg.Nodes {
		if n.Name == *name {
			found = true
			continue
		}
		filtered = append(filtered, n)
	}

	if !found {
		fmt.Fprintf(os.Stderr, "node %q not found\n", *name)
		os.Exit(1)
	}

	reg.Nodes = filtered
	if err := store.SaveRegistry(regPath, reg); err != nil {
		fatal(err)
	}

	fmt.Printf("removed node %q\n", *name)
}

func handleNode(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "node subcommand required\n")
		os.Exit(2)
	}
	switch args[0] {
	case "join":
		nodeJoin(args[1:])
	case "serve":
		nodeServe(args[1:])
	case "run":
		nodeRun(args[1:])
	case "sync-config":
		nodeSyncConfig(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown node subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func nodeJoin(args []string) {
	fs := flag.NewFlagSet("node join", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	name := fs.String("name", "", "node name")
	controllerAddr := fs.String("controller", "", "controller host:port")
	pubKey := fs.String("pubkey", "", "WireGuard public key")
	vpnIP := fs.String("vpn-ip", "", "WireGuard VPN IP")
	directMode := fs.String("direct", "", "direct mode: auto|off")
	stunList := fs.String("stun", "", "comma-separated STUN servers")
	token := fs.String("token", "", "bootstrap token for mTLS enrollment")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		cfg.Node = &config.NodeConfig{}
	}

	overrideNode(cfg.Node, *name, *controllerAddr, *pubKey, *vpnIP, *directMode, *stunList)
	config.ApplyDefaults(&cfg)
	if err := config.Validate(cfg); err != nil {
		fatal(err)
	}

	// Token-based bootstrap flow: generate CSR, call /bootstrap, save certs.
	if *token != "" && cfg.Node.Controller != "" {
		if cfg.Node.Name == "" {
			fatal(errors.New("node.name is required for bootstrap"))
		}

		csrPEM, keyPEM, err := pki.GenerateCSR(cfg.Node.Name)
		if err != nil {
			fatal(fmt.Errorf("generate CSR: %w", err))
		}

		// Use an insecure TLS client for bootstrap — we don't have the CA cert yet.
		baseURL := normalizeBootstrapURL(cfg.Node.Controller)
		insecureClient := api.NewTLSClient(baseURL, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // bootstrap phase
			MinVersion:         tls.VersionTLS13,
		})

		ctx := context.Background()
		resp, err := insecureClient.Bootstrap(ctx, api.BootstrapRequest{
			Token: *token,
			Name:  cfg.Node.Name,
			CSR:   string(csrPEM),
		})
		if err != nil {
			fatal(fmt.Errorf("bootstrap: %w", err))
		}

		// Save certificates to pki_dir.
		pkiDir := cfg.Node.PKIDir
		if pkiDir == "" {
			pkiDir = filepath.Join(filepath.Dir(*configPath), "pki")
		}
		if err := os.MkdirAll(pkiDir, 0o755); err != nil {
			fatal(err)
		}

		if err := os.WriteFile(filepath.Join(pkiDir, "ca.crt"), []byte(resp.CACert), 0o644); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkiDir, "client.key"), keyPEM, 0o600); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkiDir, "client.crt"), []byte(resp.ClientCert), 0o644); err != nil {
			fatal(err)
		}

		// Write pki_dir back to config.
		cfg.Node.PKIDir = pkiDir
		if cfg.Node.VPNIP == "" && resp.VPNIP != "" {
			cfg.Node.VPNIP = resp.VPNIP
		}
		if *configPath != "" {
			if err := config.Save(*configPath, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to save config: %v\n", err)
			}
		}

		fmt.Fprintf(os.Stdout, "bootstrap ok node_id=%s vpn_ip=%s pki_dir=%s\n", resp.NodeID, resp.VPNIP, pkiDir)
		return
	}

	if cfg.Node.WGPublicKey == "" {
		fatal(errors.New("wg_public_key is required"))
	}

	client := newAPIClient(cfg.Node)

	ctx := context.Background()
	resp, err := client.Register(ctx, api.RegisterRequest{
		Name:       cfg.Node.Name,
		PubKey:     cfg.Node.WGPublicKey,
		VPNIP:      cfg.Node.VPNIP,
		Endpoint:   cfg.Node.AdvertiseWGEndpoint,
		PublicAddr: cfg.Node.AdvertisePublicAddr,
		NATType:    "",
		DirectMode: cfg.Node.DirectMode,
		ProbePort:  cfg.Node.ProbePort,
	})
	if err != nil {
		fatal(err)
	}

	if cfg.Node.VPNIP == "" && resp.VPNIP != "" {
		cfg.Node.VPNIP = resp.VPNIP
	}
	fmt.Fprintf(os.Stdout, "registered node_id=%s peers=%d vpn_ip=%s\n", resp.NodeID, len(resp.Peers), cfg.Node.VPNIP)
	if err := writeBackVPNIP(*configPath, &cfg, cfg.Node.VPNIP); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to persist vpn_ip: %v\n", err)
	}

	if cfg.Node.DirectMode != "off" && len(cfg.Node.STUNServers) > 0 {
		publicAddr, natType, err := stunutil.Probe(ctx, cfg.Node.STUNServers, 5*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "STUN probe failed: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stdout, "stun public_addr=%s nat=%s\n", publicAddr, natType)

		err = client.SubmitNATProbe(ctx, api.NATProbeRequest{
			NodeID:     resp.NodeID,
			NATType:    natType,
			PublicAddr: publicAddr,
		})
		if err != nil {
			fatal(err)
		}
	}
}

func nodeRun(args []string) {
	fs := flag.NewFlagSet("node run", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)
	if err := config.Validate(cfg); err != nil {
		fatal(err)
	}
	if cfg.Node.WGPublicKey == "" {
		fatal(errors.New("wg_public_key is required"))
	}

	ctx, cancel := signalContext()
	defer cancel()

	if cfg.Node.VPNIP == "" && cfg.Node.Controller != "" {
		client := newAPIClient(cfg.Node)
		resp, err := client.Register(ctx, api.RegisterRequest{
			Name:       cfg.Node.Name,
			PubKey:     cfg.Node.WGPublicKey,
			VPNIP:      cfg.Node.VPNIP,
			Endpoint:   cfg.Node.AdvertiseWGEndpoint,
			PublicAddr: cfg.Node.AdvertisePublicAddr,
			NATType:    "",
			DirectMode: cfg.Node.DirectMode,
			ProbePort:  cfg.Node.ProbePort,
		})
		if err != nil {
			fatal(err)
		}
		cfg.Node.VPNIP = resp.VPNIP
		if err := writeBackVPNIP(*configPath, &cfg, cfg.Node.VPNIP); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist vpn_ip: %v\n", err)
		}
	}

	if err := agent.Run(ctx, *cfg.Node); err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
	}
}

func nodeServe(args []string) {
	fs := flag.NewFlagSet("node serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	retryDelay := fs.Duration("retry-delay", 2*time.Second, "initial retry delay")
	retryMaxDelay := fs.Duration("retry-max-delay", 30*time.Second, "max retry delay")
	_ = fs.Parse(args)

	if *configPath == "" {
		fatal(errors.New("--config is required"))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)
	if err := config.Validate(cfg); err != nil {
		fatal(err)
	}

	ctx, cancel := signalContext()
	defer cancel()

	delay := *retryDelay
	if delay <= 0 {
		delay = 2 * time.Second
	}
	maxDelay := *retryMaxDelay
	if maxDelay < delay {
		maxDelay = delay
	}

	for {
		// Refresh config each loop so operator edits (or write-back vpn_ip) are picked up.
		cfg, err = loadConfig(*configPath)
		if err != nil {
			fatal(err)
		}
		if cfg.Node == nil {
			fatal(errors.New("node config required"))
		}
		config.ApplyDefaults(&cfg)

		if err := syncConfigOnce(*configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "sync-config failed: %v\n", err)
			goto retry
		}
		if err := upOnce(*configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "wg up failed: %v\n", err)
			goto retry
		}

		if err := agent.Run(ctx, *cfg.Node); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			fmt.Fprintf(os.Stderr, "agent exited: %v\n", err)
			if errors.Is(err, agent.ErrTunnelDead) {
				fmt.Fprintf(os.Stderr, "tunnel dead, recovering...\n")
				delay = *retryDelay
				if delay <= 0 {
					delay = 2 * time.Second
				}
			}
			goto retry
		}
		return

	retry:
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = delay * 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}
}

func syncConfigOnce(configPath string, cfg *config.Config) error {
	if cfg == nil || cfg.Node == nil {
		return errors.New("node config required")
	}
	if cfg.Node.Controller == "" {
		// Server fields might be pre-provisioned; if so, skip controller calls.
		if cfg.Node.ServerPublicKey != "" && cfg.Node.ServerEndpoint != "" && len(cfg.Node.ServerAllowedIPs) > 0 {
			return nil
		}
		return errors.New("node.controller is required")
	}

	client := newAPIClient(cfg.Node)
	ctx := context.Background()

	updated := false
	if cfg.Node.WGPublicKey != "" {
		resp, err := client.Register(ctx, api.RegisterRequest{
			Name:       cfg.Node.Name,
			PubKey:     cfg.Node.WGPublicKey,
			VPNIP:      cfg.Node.VPNIP,
			Endpoint:   cfg.Node.AdvertiseWGEndpoint,
			PublicAddr: cfg.Node.AdvertisePublicAddr,
			NATType:    "",
			DirectMode: cfg.Node.DirectMode,
			ProbePort:  cfg.Node.ProbePort,
		})
		if err != nil {
			return err
		}
		if cfg.Node.VPNIP == "" && resp.VPNIP != "" {
			cfg.Node.VPNIP = resp.VPNIP
			updated = true
		}
	}

	if cfg.Node.ServerPublicKey == "" || cfg.Node.ServerEndpoint == "" || len(cfg.Node.ServerAllowedIPs) == 0 {
		resp, err := client.WGConfig(ctx, cfg.Node.Name)
		if err != nil {
			return err
		}
		if cfg.Node.ServerPublicKey == "" {
			cfg.Node.ServerPublicKey = resp.ServerPublicKey
			updated = true
		}
		if cfg.Node.ServerEndpoint == "" {
			cfg.Node.ServerEndpoint = resp.ServerEndpoint
			updated = true
		}
		if len(cfg.Node.ServerAllowedIPs) == 0 {
			cfg.Node.ServerAllowedIPs = resp.ServerAllowedIPs
			updated = true
		}
		if cfg.Node.ServerKeepaliveSec == 0 && resp.ServerKeepaliveSec > 0 {
			cfg.Node.ServerKeepaliveSec = resp.ServerKeepaliveSec
			updated = true
		}
		if cfg.Node.ServerProbePort == 0 && resp.ServerProbePort > 0 {
			cfg.Node.ServerProbePort = resp.ServerProbePort
			updated = true
		}
	}

	if updated && configPath != "" {
		return config.Save(configPath, *cfg)
	}
	return nil
}

func upOnce(configPath string, cfg *config.Config) error {
	if cfg == nil || cfg.Node == nil {
		return errors.New("node config required")
	}
	// Ensure server fields are present (controller-driven config generation).
	if err := fillServerConfig(cfg.Node); err != nil {
		return err
	}
	if cfg.Node.VPNIP == "" {
		return errors.New("node.vpn_ip is required (run sync-config/join first)")
	}
	conf, err := wireguard.RenderNode(*cfg.Node)
	if err != nil {
		return err
	}
	if err := wireguard.WriteConfig(cfg.Node.WGConfigPath, conf); err != nil {
		return err
	}
	setConf, err := wireguard.RenderSetConf(*cfg.Node, nil)
	if err != nil {
		return err
	}
	return wireguard.Up(*cfg.Node, setConf)
}

func nodeSyncConfig(args []string) {
	fs := flag.NewFlagSet("node sync-config", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	_ = fs.Parse(args)

	if *configPath == "" {
		fatal(errors.New("--config is required"))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)
	if cfg.Node.Controller == "" {
		fatal(errors.New("node.controller is required"))
	}

	client := newAPIClient(cfg.Node)
	ctx := context.Background()

	updated := false
	if cfg.Node.WGPublicKey != "" {
		resp, err := client.Register(ctx, api.RegisterRequest{
			Name:       cfg.Node.Name,
			PubKey:     cfg.Node.WGPublicKey,
			VPNIP:      cfg.Node.VPNIP,
			Endpoint:   "",
			PublicAddr: "",
			NATType:    "",
			DirectMode: cfg.Node.DirectMode,
			ProbePort:  cfg.Node.ProbePort,
		})
		if err != nil {
			fatal(err)
		}
		if cfg.Node.VPNIP == "" && resp.VPNIP != "" {
			cfg.Node.VPNIP = resp.VPNIP
			updated = true
		}
	}

	if cfg.Node.ServerPublicKey == "" || cfg.Node.ServerEndpoint == "" || len(cfg.Node.ServerAllowedIPs) == 0 {
		resp, err := client.WGConfig(ctx, cfg.Node.Name)
		if err != nil {
			fatal(err)
		}
		if cfg.Node.ServerPublicKey == "" {
			cfg.Node.ServerPublicKey = resp.ServerPublicKey
			updated = true
		}
		if cfg.Node.ServerEndpoint == "" {
			cfg.Node.ServerEndpoint = resp.ServerEndpoint
			updated = true
		}
		if len(cfg.Node.ServerAllowedIPs) == 0 {
			cfg.Node.ServerAllowedIPs = resp.ServerAllowedIPs
			updated = true
		}
		if cfg.Node.ServerKeepaliveSec == 0 && resp.ServerKeepaliveSec > 0 {
			cfg.Node.ServerKeepaliveSec = resp.ServerKeepaliveSec
			updated = true
		}
		if cfg.Node.ServerProbePort == 0 && resp.ServerProbePort > 0 {
			cfg.Node.ServerProbePort = resp.ServerProbePort
			updated = true
		}
	}

	if updated {
		if err := config.Save(*configPath, cfg); err != nil {
			fatal(err)
		}
		fmt.Fprintln(os.Stdout, "config updated")
		return
	}
	fmt.Fprintln(os.Stdout, "config already up to date")
}

func handleDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	iface := fs.String("iface", "", "wireguard interface name")
	ifaceFlag := fs.String("interface", "", "WireGuard interface (alternative to --config)")
	_ = fs.Parse(args)

	if *configPath != "" && *ifaceFlag != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}

	// --interface mode: skip config-dependent checks, show interface status only.
	if *ifaceFlag != "" {
		fmt.Fprintf(os.Stdout, "iface=%s\n", *ifaceFlag)
		if out, err := wireguard.Status(*ifaceFlag); err == nil {
			fmt.Fprintln(os.Stdout, out)
		} else {
			fmt.Fprintf(os.Stdout, "wg status error: %v\n", err)
		}
		return
	}

	if *configPath == "" {
		fatal(errors.New("--config or --interface is required"))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	config.ApplyDefaults(&cfg)

	if *iface == "" {
		if cfg.Node != nil && cfg.Node.WGInterface != "" {
			*iface = cfg.Node.WGInterface
		} else if cfg.Controller != nil && cfg.Controller.WGInterface != "" {
			*iface = cfg.Controller.WGInterface
		} else {
			*iface = config.DefaultWGInterface
		}
	}

	fmt.Fprintf(os.Stdout, "iface=%s\n", *iface)
	if out, err := wireguard.Status(*iface); err == nil {
		fmt.Fprintln(os.Stdout, out)
	} else {
		fmt.Fprintf(os.Stdout, "wg status error: %v\n", err)
	}

	// Routing / policy diagnostics.
	if cfg.Node != nil {
		if config.PolicyRoutingEnabled(cfg.Node) {
			fmt.Fprintf(os.Stdout, "policy_routing enabled=true table=%d priority=%d cidr=%s\n",
				cfg.Node.PolicyRoutingTable, cfg.Node.PolicyRoutingPriority, cfg.Node.PolicyRoutingCIDR)
		} else {
			fmt.Fprintln(os.Stdout, "policy_routing enabled=false")
		}
		if cfg.Node.ProbePort > 0 {
			fmt.Fprintf(os.Stdout, "probe_port=%d\n", cfg.Node.ProbePort)
		}
		if out, err := outputCmd("ip", "rule", "show"); err == nil && out != "" {
			fmt.Fprintln(os.Stdout, "ip rule:")
			fmt.Fprintln(os.Stdout, out)
		}
		if config.PolicyRoutingEnabled(cfg.Node) && cfg.Node.PolicyRoutingTable > 0 {
			out, err := outputCmd("ip", "route", "show", "table", fmt.Sprintf("%d", cfg.Node.PolicyRoutingTable))
			if err == nil && out != "" {
				fmt.Fprintf(os.Stdout, "ip route table %d:\n", cfg.Node.PolicyRoutingTable)
				fmt.Fprintln(os.Stdout, out)
				// Heuristic warning for the most common failure: rule exists but baseline route is missing.
				if cfg.Node.PolicyRoutingCIDR != "" && !strings.Contains(out, cfg.Node.PolicyRoutingCIDR) {
					fmt.Fprintf(os.Stdout, "warning: policy routing table %d has no route for %s (VPN traffic may blackhole until wg up applies baseline route)\n",
						cfg.Node.PolicyRoutingTable, cfg.Node.PolicyRoutingCIDR)
				}
			}
		}
		if cfg.Node.ServerAllowedIPs != nil {
			for _, cidr := range cfg.Node.ServerAllowedIPs {
				if cidr == "0.0.0.0/0" || cidr == "::/0" {
					fmt.Fprintf(os.Stdout, "warning: server_allowed_ips includes default route (%s) which may break host internet\n", cidr)
				}
			}
		}
	}
}

func outputCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return "", errors.New(strings.TrimSpace(buf.String()))
	}
	return strings.TrimSpace(buf.String()), nil
}

func handleDirect(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "direct subcommand required\n")
		os.Exit(2)
	}

	switch args[0] {
	case "serve":
		directServe(args[1:])
	case "test":
		directTest(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown direct subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func directServe(args []string) {
	fs := flag.NewFlagSet("direct serve", flag.ExitOnError)
	listen := fs.String("listen", ":0", "local UDP listen address")
	_ = fs.Parse(args)

	resp, err := direct.StartResponder(*listen)
	if err != nil {
		fatal(err)
	}
	defer resp.Close()

	fmt.Fprintf(os.Stdout, "direct responder listening on %s\n", resp.LocalAddr())
	waitForSignal()
}

func directTest(args []string) {
	fs := flag.NewFlagSet("direct test", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	peer := fs.String("peer", "", "peer name or ID")
	localAddr := fs.String("local", ":0", "local UDP address")
	timeout := fs.Duration("timeout", 3*time.Second, "probe timeout")
	_ = fs.Parse(args)

	if *peer == "" {
		fatal(errors.New("--peer is required"))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)

	client := newAPIClient(cfg.Node)
	ctx := context.Background()
	candidates, err := client.Candidates(ctx, cfg.Node.Name)
	if err != nil {
		fatal(err)
	}

	peerAddr, peerID := selectPeer(*peer, candidates.Peers)
	if peerAddr == "" {
		fatal(fmt.Errorf("peer %q not found or missing probe address (need probe_port and either public_addr or wg_endpoint)", *peer))
	}

	rtt, err := direct.ProbePeer(ctx, *localAddr, peerAddr, *timeout)
	if err != nil {
		_ = client.SubmitDirectResult(ctx, api.DirectResultRequest{
			NodeID:  cfg.Node.Name,
			PeerID:  peerID,
			Success: false,
			RTTMs:   0,
			Reason:  err.Error(),
		})
		fatal(err)
	}

	fmt.Fprintf(os.Stdout, "direct probe ok peer=%s rtt=%s\n", peerAddr, rtt)
	_ = client.SubmitDirectResult(ctx, api.DirectResultRequest{
		NodeID:  cfg.Node.Name,
		PeerID:  peerID,
		Success: true,
		RTTMs:   float64(rtt.Microseconds()) / 1000.0,
		Reason:  "",
	})
}

func handleDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	ifaceFlag := fs.String("interface", "", "WireGuard interface (alternative to --config)")
	probePort := fs.Int("probe-port", 51900, "echo responder port on peers")
	_ = fs.Parse(args)

	if *configPath != "" && *ifaceFlag != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}

	// --interface mode: discover peers directly from the live WireGuard interface.
	if *ifaceFlag != "" {
		src := peersource.NewWgSource(*ifaceFlag, *probePort)
		peers, err := src.Discover()
		if err != nil {
			fatal(err)
		}
		if len(peers) == 0 {
			fmt.Fprintln(os.Stdout, "no peers")
			return
		}
		fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-6s  %-22s\n",
			"NAME", "VPN_IP", "WG_ENDPOINT", "PORT", "LAST_HANDSHAKE")
		for _, p := range peers {
			lastHS := ""
			if !p.LastHandshake.IsZero() {
				lastHS = p.LastHandshake.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-6d  %-22s\n",
				p.Name, p.VPNIP, p.Endpoint, p.ProbePort, lastHS)
		}
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)

	client := newAPIClient(cfg.Node)
	ctx := context.Background()
	resp, err := client.Candidates(ctx, cfg.Node.Name)
	if err != nil {
		fatal(err)
	}

	if len(resp.Peers) == 0 {
		fmt.Fprintln(os.Stdout, "no peers")
		return
	}

	fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-6s  %-4s  %-22s  %-22s  %-18s\n",
		"NAME", "VPN_IP", "WG_ENDPOINT", "PORT", "P2P", "DIRECT_ADDR", "PUBLIC_ADDR", "NAT_TYPE")
	for _, peer := range resp.Peers {
		p2p := ""
		if peer.P2PReady {
			p2p = "yes"
		} else {
			p2p = "no"
		}
		directAddr, _ := addrutil.ProbeAddr(peer.PublicAddr, peer.Endpoint, peer.ProbePort)
		fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-6d  %-4s  %-22s  %-22s  %-18s\n",
			peer.Name, peer.VPNIP, peer.Endpoint, peer.ProbePort, p2p, directAddr, peer.PublicAddr, peer.NATType)
	}
}

func handlePing(args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	peer := fs.String("peer", "", "peer name or ID")
	all := fs.Bool("all", false, "ping all peers")
	count := fs.Int("count", 5, "number of probes")
	interval := fs.Duration("interval", 500*time.Millisecond, "probe interval")
	timeout := fs.Duration("timeout", 2*time.Second, "probe timeout")
	submit := fs.Bool("submit", true, "submit metrics to controller")
	path := fs.String("path", "auto", "path selection: auto|direct|relay")
	ifaceFlag := fs.String("interface", "", "WireGuard interface (alternative to --config)")
	probePort := fs.Int("probe-port", 51900, "echo responder port on peers")
	_ = fs.Parse(args)

	if *configPath != "" && *ifaceFlag != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}

	if !*all && *peer == "" {
		fatal(errors.New("--peer or --all is required"))
	}

	// --interface mode: discover peers from the live WireGuard interface.
	if *ifaceFlag != "" {
		src := peersource.NewWgSource(*ifaceFlag, *probePort)
		wgPeers, err := src.Discover()
		if err != nil {
			fatal(err)
		}
		ctx := context.Background()
		var matched []peersource.Peer
		if *all {
			matched = wgPeers
		} else {
			for _, p := range wgPeers {
				if p.Name == *peer || p.VPNIP == *peer {
					matched = append(matched, p)
					break
				}
			}
		}
		if len(matched) == 0 {
			fatal(errors.New("no peers matched"))
		}
		for _, p := range matched {
			peerAddr := fmt.Sprintf("%s:%d", p.VPNIP, p.ProbePort)
			results := make([]float64, 0, *count)
			for i := 0; i < *count; i++ {
				rtt, err := direct.ProbePeer(ctx, ":0", peerAddr, *timeout)
				if err == nil {
					results = append(results, float64(rtt.Microseconds())/1000.0)
					fmt.Fprintf(os.Stdout, "ping %s seq=%d rtt=%.2fms\n", p.Name, i+1, results[len(results)-1])
				} else {
					fmt.Fprintf(os.Stdout, "ping %s seq=%d timeout\n", p.Name, i+1)
				}
				time.Sleep(*interval)
			}
			metric := summarizePing(*ifaceFlag, p.PublicKey, "relay", results, *count, 0)
			fmt.Fprintf(os.Stdout, "ping summary peer=%s avg=%.2fms loss=%.2f%%\n", p.Name, metric.RTTMs, metric.LossPct)
		}
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)

	client := newAPIClient(cfg.Node)
	ctx := context.Background()
	resp, err := client.Candidates(ctx, cfg.Node.Name)
	if err != nil {
		fatal(err)
	}

	peers := filterPeers(resp.Peers, *peer, *all)
	if len(peers) == 0 {
		fatal(errors.New("no peers matched"))
	}

	for _, p := range peers {
		peerAddr, pathLabel := selectProbeAddr(p, *path)
		if peerAddr == "" {
			fmt.Fprintf(os.Stdout, "peer %s missing address\n", p.Name)
			continue
		}

		results := make([]float64, 0, *count)
		for i := 0; i < *count; i++ {
			rtt, err := direct.ProbePeer(ctx, ":0", peerAddr, *timeout)
			if err == nil {
				results = append(results, float64(rtt.Microseconds())/1000.0)
				fmt.Fprintf(os.Stdout, "ping %s seq=%d rtt=%.2fms\n", p.Name, i+1, results[len(results)-1])
			} else {
				fmt.Fprintf(os.Stdout, "ping %s seq=%d timeout\n", p.Name, i+1)
			}
			time.Sleep(*interval)
		}

		metric := summarizePing(cfg.Node.Name, p.ID, pathLabel, results, *count, cfg.Node.MTU)
		if cfg.Node.MetricsPath != "" {
			if err := metrics.AppendCSV(cfg.Node.MetricsPath, []model.Metric{metric}); err != nil {
				fmt.Fprintf(os.Stderr, "append metrics failed: %v\n", err)
			}
		}
		if *submit {
			_ = client.SubmitMetrics(ctx, api.MetricsRequest{NodeID: cfg.Node.Name, Samples: []model.Metric{metric}})
		}
		fmt.Fprintf(os.Stdout, "ping summary peer=%s avg=%.2fms loss=%.2f%%\n", p.Name, metric.RTTMs, metric.LossPct)
	}
}

func handlePerf(args []string) {
	fs := flag.NewFlagSet("perf", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	peer := fs.String("peer", "", "peer name or ID")
	count := fs.Int("count", 200, "packet count")
	packetSize := fs.Int("size", 1200, "packet size in bytes")
	timeout := fs.Duration("timeout", 5*time.Second, "probe timeout")
	submit := fs.Bool("submit", true, "submit metrics to controller")
	path := fs.String("path", "auto", "path selection: auto|direct|relay")
	ifaceFlag := fs.String("interface", "", "WireGuard interface (alternative to --config)")
	probePort := fs.Int("probe-port", 51900, "echo responder port on peers")
	_ = fs.Parse(args)

	if *configPath != "" && *ifaceFlag != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}

	if *peer == "" {
		fatal(errors.New("--peer is required"))
	}

	// --interface mode: discover peers from the live WireGuard interface.
	if *ifaceFlag != "" {
		src := peersource.NewWgSource(*ifaceFlag, *probePort)
		wgPeers, err := src.Discover()
		if err != nil {
			fatal(err)
		}
		var matched *peersource.Peer
		for i := range wgPeers {
			if wgPeers[i].Name == *peer || wgPeers[i].VPNIP == *peer {
				matched = &wgPeers[i]
				break
			}
		}
		if matched == nil {
			fatal(fmt.Errorf("peer %q not found or missing address", *peer))
		}
		peerAddr := fmt.Sprintf("%s:%d", matched.VPNIP, matched.ProbePort)
		ctx := context.Background()
		throughput, lossPct, err := direct.PerfProbe(ctx, ":0", peerAddr, *packetSize, *count, *timeout)
		if err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stdout, "perf peer=%s throughput=%.2f Mbps loss=%.2f%%\n", *peer, throughput, lossPct)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)

	client := newAPIClient(cfg.Node)
	ctx := context.Background()
	resp, err := client.Candidates(ctx, cfg.Node.Name)
	if err != nil {
		fatal(err)
	}

	peerAddr, peerID, pathLabel := selectProbeAddrByName(*peer, resp.Peers, *path)
	if peerAddr == "" {
		fatal(fmt.Errorf("peer %q not found or missing address", *peer))
	}

	throughput, lossPct, err := direct.PerfProbe(ctx, ":0", peerAddr, *packetSize, *count, *timeout)
	if err != nil {
		fatal(err)
	}

	metric := model.Metric{
		Timestamp:      time.Now().UTC(),
		NodeID:         cfg.Node.Name,
		PeerID:         peerID,
		Path:           pathLabel,
		RTTMs:          0,
		JitterMs:       0,
		LossPct:        lossPct,
		ThroughputMbps: throughput,
		MTU:            cfg.Node.MTU,
	}
	if cfg.Node.MetricsPath != "" {
		if err := metrics.AppendCSV(cfg.Node.MetricsPath, []model.Metric{metric}); err != nil {
			fmt.Fprintf(os.Stderr, "append metrics failed: %v\n", err)
		}
	}
	if *submit {
		_ = client.SubmitMetrics(ctx, api.MetricsRequest{NodeID: cfg.Node.Name, Samples: []model.Metric{metric}})
	}

	fmt.Fprintf(os.Stdout, "perf peer=%s throughput=%.2f Mbps loss=%.2f%%\n", *peer, throughput, lossPct)
}

func handleStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	window := fs.Duration("window", 5*time.Minute, "time window")
	path := fs.String("path", "", "metrics CSV path override")
	ifaceFlag := fs.String("interface", "", "WireGuard interface (alternative to --config)")
	_ = fs.String("probe-port", "", "") // accepted but unused for stats
	_ = fs.Parse(args)

	if *configPath != "" && *ifaceFlag != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}

	// --interface mode: read from local monitor store (~/.vpnctl/monitor.db).
	if *ifaceFlag != "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fatal(err)
		}
		dbPath := filepath.Join(home, ".vpnctl", "monitor.db")
		st, err := monitor.OpenStore(dbPath)
		if err != nil {
			fatal(fmt.Errorf("open monitor store %s: %w", dbPath, err))
		}
		defer st.Close()
		summaries, err := st.Summarize(*window)
		if err != nil {
			fatal(err)
		}
		if len(summaries) == 0 {
			fmt.Fprintln(os.Stdout, "no samples in window")
			return
		}
		fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-8s  %-10s  %-10s  %-10s  %-8s  %-22s\n",
			"PEER_KEY", "PEER_IP", "COUNT", "AVG_RTT_us", "MIN_RTT_us", "MAX_RTT_us", "LOSS%", "LAST_SEEN")
		for _, s := range summaries {
			fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-8d  %-10d  %-10d  %-10d  %-8.2f  %-22s\n",
				s.PeerKey, s.PeerIP, s.Count, s.AvgRTTus, s.MinRTTus, s.MaxRTTus, s.LossPct,
				s.LastSeen.Format(time.RFC3339))
		}
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}

	metricsPath := selectMetricsPath(cfg, *path)
	if metricsPath == "" {
		fatal(errors.New("metrics path required"))
	}

	items, err := metrics.ReadCSV(metricsPath)
	if err != nil {
		fatal(err)
	}

	cutoff := time.Now().UTC().Add(-*window)
	summary := metrics.Summarize(items, cutoff)
	if summary.Count == 0 {
		fmt.Fprintln(os.Stdout, "no samples in window")
		return
	}

	fmt.Fprintf(os.Stdout, "samples=%d from=%s to=%s\n", summary.Count, summary.From.Format(time.RFC3339), summary.To.Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "rtt avg=%.2fms p95=%.2fms min=%.2fms max=%.2fms\n", summary.AvgRTTMs, summary.P95RTTMs, summary.MinRTTMs, summary.MaxRTTMs)
	fmt.Fprintf(os.Stdout, "jitter avg=%.2fms loss avg=%.2f%% throughput avg=%.2f Mbps\n", summary.AvgJitterMs, summary.AvgLossPct, summary.AvgThroughputMbps)
}

func handleExport(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "export subcommand required\n")
		os.Exit(2)
	}
	if args[0] != "csv" {
		fmt.Fprintf(os.Stderr, "unknown export format %q\n", args[0])
		os.Exit(2)
	}

	fs := flag.NewFlagSet("export csv", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	out := fs.String("out", "", "output file")
	path := fs.String("path", "", "metrics CSV path override")
	_ = fs.Parse(args[1:])

	if *out == "" {
		fatal(errors.New("--out is required"))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}

	metricsPath := selectMetricsPath(cfg, *path)
	if metricsPath == "" {
		fatal(errors.New("metrics path required"))
	}

	if err := copyFile(metricsPath, *out); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stdout, "exported %s\n", *out)
}

func handleUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	wgConfig := fs.String("wg-config", "", "wireguard config path override")
	dryRun := fs.Bool("dry-run", false, "print config and exit")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)
	if err := config.Validate(cfg); err != nil {
		fatal(err)
	}
	if *wgConfig != "" {
		cfg.Node.WGConfigPath = *wgConfig
	}
	if err := fillServerConfig(cfg.Node); err != nil {
		fatal(err)
	}
	if cfg.Node.VPNIP == "" && cfg.Node.Controller != "" {
		client := newAPIClient(cfg.Node)
		resp, err := client.Register(context.Background(), api.RegisterRequest{
			Name:       cfg.Node.Name,
			PubKey:     cfg.Node.WGPublicKey,
			VPNIP:      cfg.Node.VPNIP,
			Endpoint:   cfg.Node.AdvertiseWGEndpoint,
			PublicAddr: cfg.Node.AdvertisePublicAddr,
			NATType:    "",
			DirectMode: cfg.Node.DirectMode,
			ProbePort:  cfg.Node.ProbePort,
		})
		if err != nil {
			fatal(err)
		}
		cfg.Node.VPNIP = resp.VPNIP
		if err := writeBackVPNIP(*configPath, &cfg, cfg.Node.VPNIP); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist vpn_ip: %v\n", err)
		}
	}

	conf, err := wireguard.RenderNode(*cfg.Node)
	if err != nil {
		fatal(err)
	}
	if *dryRun {
		fmt.Fprint(os.Stdout, conf)
		return
	}
	if err := wireguard.WriteConfig(cfg.Node.WGConfigPath, conf); err != nil {
		fatal(err)
	}
	setConf, err := wireguard.RenderSetConf(*cfg.Node, nil)
	if err != nil {
		fatal(err)
	}
	fatal(wireguard.Up(*cfg.Node, setConf))
}

func handleDown(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	wgConfig := fs.String("wg-config", "", "wireguard config path override")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)
	if err := config.Validate(cfg); err != nil {
		fatal(err)
	}
	if *wgConfig != "" {
		cfg.Node.WGConfigPath = *wgConfig
	}

	fatal(wireguard.Down(*cfg.Node))
}

func handleStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config")
	iface := fs.String("iface", "", "wireguard interface name")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node != nil {
		config.ApplyDefaults(&cfg)
	}

	if *iface == "" {
		if cfg.Node == nil {
			fatal(errors.New("--iface required when node config is missing"))
		}
		*iface = cfg.Node.WGInterface
	}

	out, err := wireguard.Status(*iface)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintln(os.Stdout, out)
}

func loadConfig(path string) (config.Config, error) {
	if path == "" {
		return config.Config{}, nil
	}
	return config.Load(path)
}

func overrideController(cfg *config.ControllerConfig, listen, dataDir, metricsPath, stunList string) {
	if listen != "" {
		cfg.Listen = listen
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if metricsPath != "" {
		cfg.MetricsPath = metricsPath
	}
	if stunList != "" {
		cfg.STUNServers = splitList(stunList)
	}
}

func overrideNode(cfg *config.NodeConfig, name, controllerAddr, pubKey, vpnIP, directMode, stunList string) {
	if name != "" {
		cfg.Name = name
	}
	if controllerAddr != "" {
		cfg.Controller = controllerAddr
	}
	if pubKey != "" {
		cfg.WGPublicKey = pubKey
	}
	if vpnIP != "" {
		cfg.VPNIP = vpnIP
	}
	if directMode != "" {
		cfg.DirectMode = directMode
	}
	if stunList != "" {
		cfg.STUNServers = splitList(stunList)
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeBaseURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}

// normalizeBootstrapURL ensures the controller URL uses https for bootstrap.
func normalizeBootstrapURL(addr string) string {
	if strings.HasPrefix(addr, "https://") {
		return addr
	}
	if strings.HasPrefix(addr, "http://") {
		return "https://" + strings.TrimPrefix(addr, "http://")
	}
	return "https://" + addr
}

// newAPIClient creates an API client, using mTLS if PKI credentials exist.
func newAPIClient(cfg *config.NodeConfig) *api.Client {
	baseURL := normalizeBaseURL(cfg.Controller)

	if cfg.PKIDir != "" {
		caCert := filepath.Join(cfg.PKIDir, "ca.crt")
		clientCert := filepath.Join(cfg.PKIDir, "client.crt")
		clientKey := filepath.Join(cfg.PKIDir, "client.key")

		// Check if all cert files exist.
		if fileExists(caCert) && fileExists(clientCert) && fileExists(clientKey) {
			tlsCfg, err := pki.ClientTLSConfig(caCert, clientCert, clientKey)
			if err != nil {
				slog.Warn("mTLS config failed, falling back to plain HTTP", "err", err)
				return api.NewClient(baseURL)
			}
			// Switch to HTTPS.
			baseURL = normalizeBootstrapURL(cfg.Controller)
			return api.NewTLSClient(baseURL, tlsCfg)
		}
	}

	return api.NewClient(baseURL)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func selectPeer(peer string, candidates []api.PeerCandidate) (string, string) {
	for _, cand := range candidates {
		if cand.ID == peer || cand.Name == peer {
			// Prefer the stable probe address (host + probe_port). This works for
			// port-forwarded nodes even when STUN reports an ephemeral port.
			if addr, ok := addrutil.ProbeAddr(cand.PublicAddr, cand.Endpoint, cand.ProbePort); ok {
				return addr, cand.ID
			}
			return "", cand.ID
		}
	}
	return "", ""
}

func selectProbeAddr(peer api.PeerCandidate, path string) (string, string) {
	switch path {
	case "direct":
		if addr, ok := addrutil.ProbeAddr(peer.PublicAddr, peer.Endpoint, peer.ProbePort); ok {
			return addr, "direct"
		}
		return "", "direct"
	case "relay":
		if peer.VPNIP != "" && peer.ProbePort > 0 {
			return fmt.Sprintf("%s:%d", stripCIDR(peer.VPNIP), peer.ProbePort), "relay"
		}
		return "", "relay"
	default:
		if addr, ok := addrutil.ProbeAddr(peer.PublicAddr, peer.Endpoint, peer.ProbePort); ok {
			return addr, "direct"
		}
		if peer.VPNIP != "" && peer.ProbePort > 0 {
			return fmt.Sprintf("%s:%d", stripCIDR(peer.VPNIP), peer.ProbePort), "relay"
		}
	}
	return "", path
}

func selectProbeAddrByName(name string, candidates []api.PeerCandidate, path string) (string, string, string) {
	for _, cand := range candidates {
		if cand.ID == name || cand.Name == name {
			addr, pathLabel := selectProbeAddr(cand, path)
			return addr, cand.ID, pathLabel
		}
	}
	return "", "", path
}

func stripCIDR(value string) string {
	if i := strings.IndexByte(value, '/'); i >= 0 {
		return value[:i]
	}
	return value
}

func filterPeers(candidates []api.PeerCandidate, peer string, all bool) []api.PeerCandidate {
	if all {
		return candidates
	}
	for _, cand := range candidates {
		if cand.ID == peer || cand.Name == peer {
			return []api.PeerCandidate{cand}
		}
	}
	return nil
}

func summarizePing(nodeID, peerID, path string, samples []float64, count int, mtu int) model.Metric {
	if len(samples) == 0 {
		return model.Metric{
			Timestamp: time.Now().UTC(),
			NodeID:    nodeID,
			PeerID:    peerID,
			Path:      path,
			RTTMs:     0,
			JitterMs:  0,
			LossPct:   100,
			MTU:       mtu,
		}
	}

	sum := 0.0
	for _, v := range samples {
		sum += v
	}
	avg := sum / float64(len(samples))

	jitter := 0.0
	if len(samples) > 1 {
		prev := samples[0]
		for _, v := range samples[1:] {
			jitter += absFloat(v - prev)
			prev = v
		}
		jitter = jitter / float64(len(samples)-1)
	}

	lossPct := 100.0 * float64(count-len(samples)) / float64(count)

	return model.Metric{
		Timestamp: time.Now().UTC(),
		NodeID:    nodeID,
		PeerID:    peerID,
		Path:      path,
		RTTMs:     avg,
		JitterMs:  jitter,
		LossPct:   lossPct,
		MTU:       mtu,
	}
}

func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func selectMetricsPath(cfg config.Config, override string) string {
	if override != "" {
		return override
	}
	if cfg.Node != nil && cfg.Node.MetricsPath != "" {
		return cfg.Node.MetricsPath
	}
	if cfg.Controller != nil {
		return cfg.Controller.MetricsPath
	}
	return ""
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func writeBackVPNIP(path string, cfg *config.Config, vpnIP string) error {
	if path == "" || cfg == nil || cfg.Node == nil || vpnIP == "" {
		return nil
	}
	if cfg.Node.VPNIP == vpnIP {
		return nil
	}
	cfg.Node.VPNIP = vpnIP
	return config.Save(path, *cfg)
}

func fillServerConfig(node *config.NodeConfig) error {
	if node == nil {
		return errors.New("node config required")
	}
	if node.ServerPublicKey != "" && node.ServerEndpoint != "" && len(node.ServerAllowedIPs) > 0 {
		if node.PolicyRoutingCIDR == "" {
			node.PolicyRoutingCIDR = firstScopedCIDR(node.ServerAllowedIPs)
		}
		return nil
	}
	if node.Controller == "" {
		return errors.New("node.controller required to fetch server config")
	}
	client := newAPIClient(node)
	resp, err := client.WGConfig(context.Background(), node.Name)
	if err != nil {
		return err
	}
	node.ServerPublicKey = resp.ServerPublicKey
	node.ServerEndpoint = resp.ServerEndpoint
	node.ServerAllowedIPs = resp.ServerAllowedIPs
	node.ServerKeepaliveSec = resp.ServerKeepaliveSec
	if node.PolicyRoutingCIDR == "" {
		node.PolicyRoutingCIDR = firstScopedCIDR(node.ServerAllowedIPs)
	}
	return nil
}

func firstScopedCIDR(values []string) string {
	for _, value := range values {
		if value == "" {
			continue
		}
		if value == "0.0.0.0/0" || value == "::/0" {
			continue
		}
		return value
	}
	return ""
}

func waitForSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		cancel()
	}()
	return ctx, cancel
}

func fatal(err error) {
	if err == nil {
		return
	}
	slog.Error("fatal", "err", err)
	os.Exit(1)
}

func defaultMonitorDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fatal(fmt.Errorf("cannot determine home directory: %w", err))
	}
	return filepath.Join(home, ".vpnctl", "monitor.db")
}

func handleFleet(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "fleet subcommand required (status|history)\n")
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		fleetStatus(args[1:])
	case "history":
		fleetHistory(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown fleet subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func fleetStatus(args []string) {
	fs := flag.NewFlagSet("fleet status", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config (controller API)")
	iface := fs.String("interface", "", "WireGuard interface (local monitor store)")
	dataPath := fs.String("data", "", "SQLite store path (default: ~/.vpnctl/monitor.db)")
	_ = fs.Parse(args)

	if *configPath != "" && *iface != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}
	if *configPath == "" && *iface == "" {
		fmt.Fprintln(os.Stderr, "error: --config or --interface is required")
		os.Exit(2)
	}

	if *configPath != "" {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			fatal(err)
		}
		if cfg.Node == nil {
			fatal(errors.New("node config required"))
		}
		config.ApplyDefaults(&cfg)

		client := newAPIClient(cfg.Node)
		ctx := context.Background()
		resp, err := client.FleetStatus(ctx)
		if err != nil {
			fatal(err)
		}

		fmt.Printf("%-16s  %-18s  %-10s  %-8s  %-8s  %-10s  %-20s\n",
			"NAME", "VPN_IP", "PATH", "RTT_MS", "LOSS%", "NAT", "LAST_SEEN")
		for _, n := range resp.Nodes {
			fmt.Printf("%-16s  %-18s  %-10s  %-8.2f  %-8.2f  %-10s  %-20s\n",
				n.Name, n.VPNIP, n.Path, n.RTTMs, n.LossPct, n.NATType, n.LastSeen)
		}
		return
	}

	// --interface: read from local monitor store
	if *dataPath == "" {
		*dataPath = defaultMonitorDBPath()
	}

	st, err := monitor.OpenStore(*dataPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	summaries, err := st.Summarize(time.Hour)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("%-16s  %-18s  %-8s  %-8s  %-20s\n",
		"PEER_KEY", "PEER_IP", "RTT_MS", "LOSS%", "LAST_SEEN")
	for _, s := range summaries {
		rttMs := float64(s.AvgRTTus) / 1000.0
		fmt.Printf("%-16s  %-18s  %-8.2f  %-8.2f  %-20s\n",
			s.PeerKey, s.PeerIP, rttMs, s.LossPct, s.LastSeen.Format(time.RFC3339))
	}
}

func fleetHistory(args []string) {
	fs := flag.NewFlagSet("fleet history", flag.ExitOnError)
	configPath := fs.String("config", "", "path to YAML config (controller API)")
	iface := fs.String("interface", "", "WireGuard interface (local monitor store)")
	dataPath := fs.String("data", "", "SQLite store path (default: ~/.vpnctl/monitor.db)")
	window := fs.String("window", "1h", "time window (e.g. 1h, 30m)")
	_ = fs.Parse(args)

	if *configPath != "" && *iface != "" {
		fmt.Fprintln(os.Stderr, "error: specify --config or --interface, not both")
		os.Exit(2)
	}
	if *configPath == "" && *iface == "" {
		fmt.Fprintln(os.Stderr, "error: --config or --interface is required")
		os.Exit(2)
	}

	if *configPath != "" {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			fatal(err)
		}
		if cfg.Node == nil {
			fatal(errors.New("node config required"))
		}
		config.ApplyDefaults(&cfg)

		client := newAPIClient(cfg.Node)
		ctx := context.Background()
		resp, err := client.FleetHistory(ctx, *window)
		if err != nil {
			fatal(err)
		}

		for _, n := range resp.Nodes {
			fmt.Printf("Node: %s\n", n.Name)
			fmt.Printf("  %-20s  %-8s  %-8s\n", "TIME", "ONLINE%", "AVG_RTT_MS")
			for _, b := range n.Buckets {
				fmt.Printf("  %-20s  %-8.1f  %-8.2f\n", b.Time, b.OnlinePct, b.AvgRTTMs)
			}
		}
		return
	}

	// --interface: read from local monitor store
	if *dataPath == "" {
		*dataPath = defaultMonitorDBPath()
	}

	dur, err := time.ParseDuration(*window)
	if err != nil {
		fatal(fmt.Errorf("invalid --window %q: %w", *window, err))
	}

	st, err := monitor.OpenStore(*dataPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	summaries, err := st.Summarize(dur)
	if err != nil {
		fatal(err)
	}

	for _, s := range summaries {
		onlinePct := 100.0 - s.LossPct
		barLen := int(onlinePct / 5.0)
		if barLen > 20 {
			barLen = 20
		}
		if barLen < 0 {
			barLen = 0
		}
		bar := strings.Repeat("█", barLen) + strings.Repeat("░", 20-barLen)
		rttMs := float64(s.AvgRTTus) / 1000.0
		fmt.Printf("%-16s  [%s] %.1f%% online  %.2f ms avg RTT\n",
			s.PeerIP, bar, onlinePct, rttMs)
	}
}

func handleMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	iface := fs.String("interface", "", "WireGuard interface to monitor")
	peersFlag := fs.String("peers", "", "comma-separated VPN IPs to filter")
	interval := fs.Duration("interval", 5*time.Second, "probe interval")
	watch := fs.Bool("watch", false, "plain text output instead of TUI")
	dataPath := fs.String("data", "", "SQLite store path (default: ~/.vpnctl/monitor.db)")
	retention := fs.Duration("retention", 7*24*time.Hour, "data retention period")
	probePort := fs.Int("probe-port", 51900, "echo responder port on peers")
	metricsPort := fs.Int("metrics-port", 0, "Prometheus metrics port (0 = disabled)")
	_ = fs.Parse(args)

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "error: --interface is required")
		os.Exit(2)
	}

	if *dataPath == "" {
		*dataPath = defaultMonitorDBPath()
	}
	if err := os.MkdirAll(filepath.Dir(*dataPath), 0o755); err != nil {
		fatal(err)
	}

	src := peersource.NewWgSource(*iface, *probePort)

	store, err := monitor.OpenStore(*dataPath)
	if err != nil {
		fatal(err)
	}
	defer store.Close()

	if removed, err := store.Cleanup(*retention); err == nil && removed > 0 {
		fmt.Fprintf(os.Stderr, "cleaned up %d old probe records\n", removed)
	}

	var peerFilter []string
	if *peersFlag != "" {
		peerFilter = strings.Split(*peersFlag, ",")
	}

	mon := monitor.New(monitor.Config{
		Source:   src,
		Store:    store,
		Interval: *interval,
		Peers:    peerFilter,
	})

	if *metricsPort > 0 {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/network/quality", func(w http.ResponseWriter, r *http.Request) {
				snap := mon.Latest()
				var qualities []monitor.PeerQuality
				for _, ps := range snap.Peers {
					rttMs := float64(ps.RTTus) / 1000.0
					lossPct := 0.0
					if !ps.Success {
						lossPct = 100.0
					}
					qualities = append(qualities, monitor.PeerQuality{
						PeerIP:  ps.Peer.VPNIP,
						Quality: ps.Quality.String(),
						RTTMs:   rttMs,
						LossPct: lossPct,
						Level:   ps.Quality,
					})
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(qualities)
			})
			addr := fmt.Sprintf(":%d", *metricsPort)
			slog.Info("metrics server listening", "addr", addr)
			if err := http.ListenAndServe(addr, mux); err != nil {
				slog.Error("metrics server failed", "err", err)
			}
		}()
	}

	ctx, cancel := signalContext()
	defer cancel()

	if *watch {
		ww := monitor.NewWatchWriter(os.Stdout)
		sub := mon.Subscribe()
		go mon.Run(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case snap := <-sub:
				ww.Write(snap)
			}
		}
	} else {
		// Suppress slog output during TUI mode to avoid corrupting the display.
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		sub := mon.Subscribe()
		go mon.Run(ctx)
		tuiModel := monitor.NewTUIModel(*iface, sub)
		p := tea.NewProgram(tuiModel)
		if _, err := p.Run(); err != nil {
			fatal(err)
		}
	}
}
