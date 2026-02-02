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
	"vpnctl/internal/stunutil"
)

const usage = `vpnctl - minimal VPN control-plane + metrics (MVP)

Usage:
  vpnctl controller init --config <path>
  vpnctl node join --config <path>
  vpnctl node run --config <path>
  vpnctl direct serve --config <path> [--listen :0]
  vpnctl direct test --config <path> --peer <name>
  vpnctl discover --config <path>
  vpnctl ping --config <path> --peer <name>|--all
  vpnctl perf --config <path> --peer <name>
  vpnctl stats --config <path> [--window 5m]
  vpnctl export csv --config <path> --out <file>

Planned:
  vpnctl node add
  vpnctl up
  vpnctl down
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

func handleNode(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "node subcommand required\n")
		os.Exit(2)
	}
	switch args[0] {
	case "join":
		nodeJoin(args[1:])
	case "run":
		nodeRun(args[1:])
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
	})
	if err != nil {
		fatal(err)
	}

	fmt.Fprintf(os.Stdout, "registered node_id=%s peers=%d\n", resp.NodeID, len(resp.Peers))

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

	fatal(agent.Run(ctx, *cfg.Node))
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
		RTTMs:   float64(rtt.Milliseconds()),
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

	fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-18s\n", "NAME", "VPN_IP", "PUBLIC_ADDR", "NAT_TYPE")
	for _, peer := range resp.Peers {
		fmt.Fprintf(os.Stdout, "%-12s  %-15s  %-22s  %-18s\n", peer.Name, peer.VPNIP, peer.PublicAddr, peer.NATType)
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
		path := "direct"
		peerAddr := p.PublicAddr
		if peerAddr == "" {
			peerAddr = p.Endpoint
			path = "relay"
		}
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

		metric := summarizePing(cfg.Node.Name, p.ID, path, results, *count, cfg.MTU)
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

	peerAddr, peerID := selectPeer(*peer, resp.Peers)
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
		Path:           "direct",
		RTTMs:          0,
		JitterMs:       0,
		LossPct:        lossPct,
		ThroughputMbps: throughput,
		MTU:            cfg.MTU,
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
