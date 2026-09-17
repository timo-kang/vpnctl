// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/stunutil"
	"vpnctl/internal/wireguard"
)

// Run starts the long-running node agent loop.
func Run(ctx context.Context, cfg config.NodeConfig) error {
	client := newClient(cfg)
	defer client.CloseIdleConnections()
	if cfg.PKIDir != "" {
		renewalCtx, cancelRenewal := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); client.MaintainCredentials(renewalCtx, cfg.PKIDir, cfg.Name) }()
		defer func() { cancelRenewal(); <-done }()
	}

	return runSession(ctx, cfg, client)
}

// RunSession runs one agent attempt. Its supervisor owns credential maintenance
// across registration failures, tunnel restoration and retry backoff.
func RunSession(ctx context.Context, cfg config.NodeConfig) error {
	client := newClient(cfg)
	defer client.CloseIdleConnections()
	return runSession(ctx, cfg, client)
}

func runSession(ctx context.Context, cfg config.NodeConfig, client *api.Client) error {

	nodeID, vpnIP, err := register(ctx, client, cfg)
	if err != nil {
		return err
	}
	if cfg.VPNIP == "" && vpnIP != "" {
		cfg.VPNIP = vpnIP
	}

	var shared *direct.Shared
	if cfg.ProbePort > 0 {
		shared, err = direct.ListenShared(fmt.Sprintf(":%d", cfg.ProbePort))
		if err != nil {
			return err
		}
		defer shared.Close()
		slog.Info("probe responder started", "addr", shared.LocalAddr())
	}

	if err := fillServerConfig(ctx, client, &cfg); err != nil {
		slog.Warn("server config fetch failed", "err", err)
	}
	// Independent owners prevent slow controller requests, STUN or a silent fleet
	// from delaying heartbeat and tunnel health. Shutdown cancels and joins all I/O.
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancelWorkers(); workers.Wait() }()
	start := func(fn func()) { workers.Add(1); go func() { defer workers.Done(); fn() }() }
	var snapshots directSnapshots
	updates := make(chan directSnapshot, 1)
	start(func() {
		periodic(workerCtx, cfg.KeepaliveIntervalSec, func() {
			if _, _, err := register(workerCtx, client, cfg); err != nil && workerCtx.Err() == nil {
				slog.Warn("keepalive register failed", "err", err)
			}
		})
	})
	if cfg.DirectMode != "off" {
		start(func() {
			periodic(workerCtx, cfg.CandidatesIntervalSec, func() {
				resp, err := client.Candidates(workerCtx, nodeID)
				if err != nil {
					if workerCtx.Err() == nil {
						slog.Warn("candidates fetch failed", "err", err)
					}
					return
				}
				snapshots.update(updates, func(s *directSnapshot) { s.peers = resp.Peers })
			})
		})
		if shared != nil && len(cfg.STUNServers) > 0 {
			start(func() {
				periodic(workerCtx, cfg.STUNIntervalSec, func() {
					addr, nat, err := probeShared(workerCtx, shared, cfg.STUNServers, 5*time.Second)
					if err != nil {
						if workerCtx.Err() == nil {
							slog.Warn("STUN probe failed", "err", err)
						}
						return
					}
					snapshots.update(updates, func(s *directSnapshot) { s.publicAddr = addr; s.natType = nat })
					if err := client.SubmitNATProbe(workerCtx, api.NATProbeRequest{NodeID: nodeID, NATType: nat, PublicAddr: addr}); err != nil && workerCtx.Err() == nil {
						slog.Warn("NAT probe submit failed", "err", err)
					}
				})
			})
		}
		start(func() {
			runDirect(workerCtx, client, cfg, nodeID, shared, updates, func(peers []wireguard.Peer) error {
				return wireguard.DefaultManager().WithContext(workerCtx).ApplyPeers(cfg, peers)
			})
		})
	}
	// Health check ticker — detect dead tunnels.
	// Must be computed AFTER fillServerConfig which populates ServerAllowedIPs and ServerProbePort.
	// When disabled, healthC stays nil so the select case blocks forever (no-op).
	var healthC <-chan time.Time
	hubProbeAddr := hubProbeAddress(cfg)
	if hubProbeAddr != "" && cfg.HealthCheckIntervalSec > 0 {
		healthTicker := time.NewTicker(time.Duration(cfg.HealthCheckIntervalSec) * time.Second)
		defer healthTicker.Stop()
		healthC = healthTicker.C
		slog.Info("health check enabled", "interval_sec", cfg.HealthCheckIntervalSec, "failures", cfg.HealthCheckFailures, "timeout_sec", cfg.HealthCheckTimeoutSec, "hub", hubProbeAddr)
	} else if cfg.HealthCheckIntervalSec > 0 && cfg.HealthCheckFailures > 0 {
		slog.Warn("health check probe address undetermined", "server_allowed_ips", cfg.ServerAllowedIPs, "server_probe_port", cfg.ServerProbePort)
	}
	healthFailures := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-healthC:
			timeout := time.Duration(cfg.HealthCheckTimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 2 * time.Second
			}
			ok, hErr := checkTunnelHealth(ctx, hubProbeAddr, timeout)
			if hErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Infrastructure error (local socket, etc.) — don't count as tunnel failure.
				slog.Warn("health check error (not counted)", "hub", hubProbeAddr, "err", hErr)
				break
			}
			if ok {
				healthFailures = 0
			} else {
				healthFailures++
				slog.Warn("health check failed", "failures", healthFailures, "threshold", cfg.HealthCheckFailures, "hub", hubProbeAddr)
				if healthFailures >= cfg.HealthCheckFailures {
					return ErrTunnelDead
				}
			}
		}
	}
}

// Delay after completion: no overlapping work or accumulated ticker backlog.
func periodic(ctx context.Context, seconds int, fn func()) {
	interval := time.Duration(seconds) * time.Second
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if ctx.Err() != nil {
				return
			}
			fn()
			timer.Reset(interval)
		}
	}
}

func probeShared(ctx context.Context, shared *direct.Shared, servers []string, timeout time.Duration) (string, string, error) {
	results := make([]string, 0, len(servers))
	var lastErr error
	for _, server := range servers {
		addr, err := shared.ProbeSTUN(ctx, server, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		results = append(results, addr)
	}
	if len(results) == 0 {
		if lastErr != nil {
			return "", stunutil.NATTypeUnknown, lastErr
		}
		return "", stunutil.NATTypeUnknown, fmt.Errorf("stun probe failed")
	}
	return results[0], stunutil.Classify(results), nil
}

func register(ctx context.Context, client *api.Client, cfg config.NodeConfig) (string, string, error) {
	resp, err := client.Register(ctx, api.RegisterRequest{
		Name:       cfg.Name,
		PubKey:     cfg.WGPublicKey,
		VPNIP:      cfg.VPNIP,
		Endpoint:   cfg.AdvertiseWGEndpoint,
		PublicAddr: cfg.AdvertisePublicAddr,
		NATType:    "",
		DirectMode: cfg.DirectMode,
		ProbePort:  cfg.ProbePort,
	})
	if err != nil {
		return "", "", err
	}
	return resp.NodeID, resp.VPNIP, nil
}

func normalizeBaseURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}

func newClient(cfg config.NodeConfig) *api.Client {
	if cfg.PKIDir != "" {
		return api.NewCredentialClient(cfg.Controller, cfg.PKIDir)
	}
	return api.NewClient(normalizeBaseURL(cfg.Controller))
}

func fillServerConfig(ctx context.Context, client *api.Client, cfg *config.NodeConfig) error {
	if cfg == nil {
		return fmt.Errorf("node config required")
	}
	if cfg.ServerPublicKey != "" && cfg.ServerEndpoint != "" && len(cfg.ServerAllowedIPs) > 0 {
		if cfg.PolicyRoutingCIDR == "" {
			cfg.PolicyRoutingCIDR = firstScopedCIDR(cfg.ServerAllowedIPs)
		}
		return nil
	}
	if cfg.Controller == "" {
		return fmt.Errorf("node.controller required to fetch server config")
	}
	resp, err := client.WGConfig(ctx, cfg.Name)
	if err != nil {
		return err
	}
	cfg.ServerPublicKey = resp.ServerPublicKey
	cfg.ServerEndpoint = resp.ServerEndpoint
	cfg.ServerAllowedIPs = resp.ServerAllowedIPs
	cfg.ServerKeepaliveSec = resp.ServerKeepaliveSec
	cfg.ServerProbePort = resp.ServerProbePort
	if cfg.PolicyRoutingCIDR == "" {
		cfg.PolicyRoutingCIDR = firstScopedCIDR(cfg.ServerAllowedIPs)
	}
	return nil
}

func normalizeHostIP(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "/") {
		return value
	}
	return value + "/32"
}

func directKeepalive(cfg config.NodeConfig, natType string) int {
	switch natType {
	case "":
		fallthrough
	case stunutil.NATTypeSymmetric:
		if cfg.DirectKeepaliveSymmetricSec > 0 {
			return cfg.DirectKeepaliveSymmetricSec
		}
	case stunutil.NATTypeUnknown:
		if cfg.DirectKeepaliveUnknownSec > 0 {
			return cfg.DirectKeepaliveUnknownSec
		}
	default:
		if cfg.DirectKeepaliveSec > 0 {
			return cfg.DirectKeepaliveSec
		}
	}
	if cfg.DirectKeepaliveSec > 0 {
		return cfg.DirectKeepaliveSec
	}
	return cfg.KeepaliveSec
}

func peersEqual(a, b map[string]wireguard.Peer) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		other, ok := b[k]
		if !ok {
			return false
		}
		if v.PublicKey != other.PublicKey || v.Endpoint != other.Endpoint || v.KeepaliveSec != other.KeepaliveSec {
			return false
		}
		if !stringSlicesEqual(v.AllowedIPs, other.AllowedIPs) {
			return false
		}
	}
	return true
}

func peersFromMap(m map[string]wireguard.Peer) []wireguard.Peer {
	peers := make([]wireguard.Peer, 0, len(m))
	for _, peer := range m {
		peers = append(peers, peer)
	}
	return peers
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

// hubProbeAddress returns the hub VPN IP + probe port for health checks.
// The hub VPN IP is the first usable address in ServerAllowedIPs (e.g. 10.7.0.0/24 -> 10.7.0.1).
func hubProbeAddress(cfg config.NodeConfig) string {
	if cfg.HealthCheckIntervalSec <= 0 || cfg.HealthCheckFailures <= 0 {
		return ""
	}
	probePort := cfg.ServerProbePort
	if probePort == 0 {
		probePort = config.DefaultProbePort
	}
	for _, cidr := range cfg.ServerAllowedIPs {
		if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		hubIP := prefix.Masked().Addr().Next()
		return fmt.Sprintf("%s:%d", hubIP.String(), probePort)
	}
	return ""
}
