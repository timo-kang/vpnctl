package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"vpnctl/internal/agent"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/controller"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/model"
	"vpnctl/internal/store"
	"vpnctl/internal/stunutil"
	"vpnctl/internal/wireguard"
)

const usage = `vpnctl - minimal VPN control-plane + metrics (MVP)

Usage:
  vpnctl controller init --config <path>
  vpnctl controller status --config <path>
  vpnctl node join --config <path>
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

Planned:
 vpnctl node add
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
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
	case "add":
		fmt.Fprintln(os.Stderr, "node add not implemented yet")
		os.Exit(2)
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
	if cfg.Node.WGPublicKey == "" {
		fatal(errors.New("wg_public_key is required"))
	}

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))

	ctx := context.Background()
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
		client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
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

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
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

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
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
	_ = fs.Parse(args)

	if *configPath == "" {
		fatal(errors.New("--config is required"))
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
		if cfg.Node.ServerAllowedIPs != nil {
			for _, cidr := range cfg.Node.ServerAllowedIPs {
				if cidr == "0.0.0.0/0" || cidr == "::/0" {
					fmt.Fprintf(os.Stdout, "warning: server_allowed_ips includes default route (%s) which may break host internet\n", cidr)
				}
			}
		}
	}
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

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
	ctx := context.Background()
	candidates, err := client.Candidates(ctx, cfg.Node.Name)
	if err != nil {
		fatal(err)
	}

	peerAddr, peerID := selectPeer(*peer, candidates.Peers)
	if peerAddr == "" {
		fatal(fmt.Errorf("peer %q not found or missing public_addr", *peer))
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
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
	ctx := context.Background()
	resp, err := client.Candidates(ctx, cfg.Node.Name)
	if err != nil {
		fatal(err)
	}

	if len(resp.Peers) == 0 {
		fmt.Fprintln(os.Stdout, "no peers")
		return
	}

	fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-6s  %-22s  %-18s\n", "NAME", "VPN_IP", "WG_ENDPOINT", "PORT", "PUBLIC_ADDR", "NAT_TYPE")
	for _, peer := range resp.Peers {
		fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-6d  %-22s  %-18s\n", peer.Name, peer.VPNIP, peer.Endpoint, peer.ProbePort, peer.PublicAddr, peer.NATType)
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
	_ = fs.Parse(args)

	if !*all && *peer == "" {
		fatal(errors.New("--peer or --all is required"))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Node == nil {
		fatal(errors.New("node config required"))
	}
	config.ApplyDefaults(&cfg)

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
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

	client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
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
	_ = fs.Parse(args)

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
		client := api.NewClient(normalizeBaseURL(cfg.Node.Controller))
		resp, err := client.Register(context.Background(), api.RegisterRequest{
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

func selectPeer(peer string, candidates []api.PeerCandidate) (string, string) {
	for _, cand := range candidates {
		if cand.ID == peer || cand.Name == peer {
			if cand.PublicAddr != "" {
				return cand.PublicAddr, cand.ID
			}
			if cand.Endpoint != "" {
				return cand.Endpoint, cand.ID
			}
			return "", cand.ID
		}
	}
	return "", ""
}

func selectProbeAddr(peer api.PeerCandidate, path string) (string, string) {
	switch path {
	case "direct":
		if peer.PublicAddr != "" {
			return peer.PublicAddr, "direct"
		}
		return "", "direct"
	case "relay":
		if peer.VPNIP != "" && peer.ProbePort > 0 {
			return fmt.Sprintf("%s:%d", stripCIDR(peer.VPNIP), peer.ProbePort), "relay"
		}
		return "", "relay"
	default:
		if peer.PublicAddr != "" {
			return peer.PublicAddr, "direct"
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
	client := api.NewClient(normalizeBaseURL(node.Controller))
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
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
