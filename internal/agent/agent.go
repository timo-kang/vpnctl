// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpnctl/internal/addrutil"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/model"
	"vpnctl/internal/pki"
	"vpnctl/internal/stunutil"
	"vpnctl/internal/wireguard"
)

// Run starts the long-running node agent loop.
func Run(ctx context.Context, cfg config.NodeConfig) error {
	client := newClient(cfg)

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

	keepaliveTicker := time.NewTicker(time.Duration(cfg.KeepaliveIntervalSec) * time.Second)
	defer keepaliveTicker.Stop()
	stunTicker := time.NewTicker(time.Duration(cfg.STUNIntervalSec) * time.Second)
	defer stunTicker.Stop()
	candidatesTicker := time.NewTicker(time.Duration(cfg.CandidatesIntervalSec) * time.Second)
	defer candidatesTicker.Stop()
	directTicker := time.NewTicker(time.Duration(cfg.DirectIntervalSec) * time.Second)
	defer directTicker.Stop()

	var candidates []api.PeerCandidate
	var publicAddr string
	var natType string
	activePeers := map[string]wireguard.Peer{}
	if err := fillServerConfig(ctx, client, &cfg); err != nil {
		slog.Warn("server config fetch failed", "err", err)
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
		case <-keepaliveTicker.C:
			_, _, err := register(ctx, client, cfg)
			if err != nil {
				slog.Warn("keepalive register failed", "err", err)
			}
		case <-stunTicker.C:
			if cfg.DirectMode == "off" || len(cfg.STUNServers) == 0 {
				break
			}
			if shared == nil {
				break
			}
			addr, nat, err := probeShared(ctx, shared, cfg.STUNServers, 5*time.Second)
			if err != nil {
				slog.Warn("STUN probe failed", "err", err)
				break
			}
			publicAddr = addr
			natType = nat
			if err := client.SubmitNATProbe(ctx, api.NATProbeRequest{
				NodeID:     nodeID,
				NATType:    natType,
				PublicAddr: publicAddr,
			}); err != nil {
				slog.Warn("NAT probe submit failed", "err", err)
			}
		case <-candidatesTicker.C:
			resp, err := client.Candidates(ctx, nodeID)
			if err != nil {
				slog.Warn("candidates fetch failed", "err", err)
				break
			}
			candidates = resp.Peers
		case <-directTicker.C:
			if cfg.DirectMode == "off" {
				break
			}
			desired := map[string]wireguard.Peer{}
			allowedOwner := map[string]string{}
			for _, peer := range candidates {
				inject := peer.P2PReady
				// P2P WireGuard injection needs the peer's wg endpoint (as observed by the controller).
				// PublicAddr from STUN is for the probe socket, not wg, and must not be used for wg endpoints.
				wgEndpoint := peer.Endpoint
				allowedIP := normalizeHostIP(peer.VPNIP)
				if inject && allowedIP != "" {
					if prev, ok := allowedOwner[allowedIP]; ok && prev != peer.ID {
						// Overlapping AllowedIPs are invalid in WireGuard. Skip duplicates so one bad/stale
						// registry entry doesn't block all peer injection.
						slog.Warn("skip peer injection: duplicate allowed_ip", "name", peer.Name, "id", peer.ID, "vpn_ip", peer.VPNIP, "owner", prev)
						inject = false
					} else {
						allowedOwner[allowedIP] = peer.ID
					}
				}
				if inject && allowedIP != "" && peer.PubKey != "" && wgEndpoint != "" {
					desired[peer.ID] = wireguard.Peer{
						PublicKey:    peer.PubKey,
						Endpoint:     wgEndpoint,
						AllowedIPs:   []string{allowedIP},
						KeepaliveSec: directKeepalive(cfg, peer.NATType),
					}
				}

				// Record a direct UDP reachability datapoint to the peer's probe port.
				// Use the host from PublicAddr or (fallback) from Endpoint, and always target ProbePort.
				if shared == nil {
					continue
				}
				peerAddr, ok := addrutil.ProbeAddr(peer.PublicAddr, peer.Endpoint, peer.ProbePort)
				if !ok {
					continue
				}
				path := "direct"

				rtt, err := shared.ProbePeer(ctx, peerAddr, 2*time.Second)
				success := err == nil
				if !success {
					_ = client.SubmitDirectResult(ctx, api.DirectResultRequest{
						NodeID:  nodeID,
						PeerID:  peer.ID,
						Success: false,
						RTTMs:   0,
						Reason:  err.Error(),
					})
					continue
				}

				rttMs := float64(rtt.Microseconds()) / 1000.0
				_ = client.SubmitDirectResult(ctx, api.DirectResultRequest{
					NodeID:  nodeID,
					PeerID:  peer.ID,
					Success: true,
					RTTMs:   rttMs,
					Reason:  "",
				})

				sample := model.Metric{
					Timestamp:  time.Now().UTC(),
					NodeID:     nodeID,
					PeerID:     peer.ID,
					Path:       path,
					RTTMs:      rttMs,
					JitterMs:   0,
					LossPct:    0,
					MTU:        cfg.MTU,
					NATType:    natType,
					PublicAddr: publicAddr,
				}

				if cfg.MetricsPath != "" {
					if err := metrics.AppendCSV(cfg.MetricsPath, []model.Metric{sample}); err != nil {
						slog.Warn("append metrics failed", "err", err)
					}
				}
				if err := client.SubmitMetrics(ctx, api.MetricsRequest{NodeID: nodeID, Samples: []model.Metric{sample}}); err != nil {
					slog.Warn("submit metrics failed", "err", err)
				}
			}

			if cfg.ServerPublicKey != "" && cfg.ServerEndpoint != "" && len(cfg.ServerAllowedIPs) > 0 {
				if !peersEqual(activePeers, desired) {
					peerList := peersFromMap(desired)
					slog.Info("injecting wg peers", "count", len(peerList))
					if err := wireguard.ApplyPeers(cfg, peerList); err != nil {
						slog.Error("apply peers failed", "err", err)
					} else {
						slog.Info("wg peers injected", "count", len(peerList))
						activePeers = desired
					}
				}
			}
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
	baseURL := normalizeBaseURL(cfg.Controller)

	if cfg.PKIDir != "" {
		caCert := filepath.Join(cfg.PKIDir, "ca.crt")
		clientCert := filepath.Join(cfg.PKIDir, "client.crt")
		clientKey := filepath.Join(cfg.PKIDir, "client.key")

		if fileExists(caCert) && fileExists(clientCert) && fileExists(clientKey) {
			tlsCfg, err := pki.ClientTLSConfig(caCert, clientCert, clientKey)
			if err != nil {
				slog.Warn("mTLS config failed, falling back to plain HTTP", "err", err)
				return api.NewClient(baseURL)
			}
			if !strings.HasPrefix(baseURL, "https://") {
				baseURL = strings.Replace(baseURL, "http://", "https://", 1)
			}
			return api.NewTLSClient(baseURL, tlsCfg)
		}
	}

	return api.NewClient(baseURL)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

