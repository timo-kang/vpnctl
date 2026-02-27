package agent

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"vpnctl/internal/addrutil"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/model"
	"vpnctl/internal/stunutil"
	"vpnctl/internal/wireguard"
)

// Run starts the long-running node agent loop.
func Run(ctx context.Context, cfg config.NodeConfig) error {
	client := api.NewClient(normalizeBaseURL(cfg.Controller))

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
		log.Printf("probe responder on %s", shared.LocalAddr())
	}

	keepaliveTicker := time.NewTicker(time.Duration(cfg.KeepaliveIntervalSec) * time.Second)
	defer keepaliveTicker.Stop()
	stunTicker := time.NewTicker(time.Duration(cfg.STUNIntervalSec) * time.Second)
	defer stunTicker.Stop()
	candidatesTicker := time.NewTicker(time.Duration(cfg.CandidatesIntervalSec) * time.Second)
	defer candidatesTicker.Stop()
	directTicker := time.NewTicker(time.Duration(cfg.DirectIntervalSec) * time.Second)
	defer directTicker.Stop()

	// Health check ticker — detect dead tunnels.
	var healthC <-chan time.Time
	hubProbeAddr := hubProbeAddress(cfg)
	if hubProbeAddr != "" && cfg.HealthCheckIntervalSec > 0 {
		healthTicker := time.NewTicker(time.Duration(cfg.HealthCheckIntervalSec) * time.Second)
		defer healthTicker.Stop()
		healthC = healthTicker.C
	}
	healthFailures := 0

	var candidates []api.PeerCandidate
	var publicAddr string
	var natType string
	activePeers := map[string]wireguard.Peer{}
	if err := fillServerConfig(ctx, client, &cfg); err != nil {
		log.Printf("server config fetch failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-keepaliveTicker.C:
			_, _, err := register(ctx, client, cfg)
			if err != nil {
				log.Printf("keepalive register failed: %v", err)
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
				log.Printf("STUN probe failed: %v", err)
				break
			}
			publicAddr = addr
			natType = nat
			if err := client.SubmitNATProbe(ctx, api.NATProbeRequest{
				NodeID:     nodeID,
				NATType:    natType,
				PublicAddr: publicAddr,
			}); err != nil {
				log.Printf("NAT probe submit failed: %v", err)
			}
		case <-candidatesTicker.C:
			resp, err := client.Candidates(ctx, nodeID)
			if err != nil {
				log.Printf("candidates fetch failed: %v", err)
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
						log.Printf("skip peer injection name=%s id=%s vpn_ip=%s: duplicate allowed_ip (already owned by %s)", peer.Name, peer.ID, peer.VPNIP, prev)
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
						log.Printf("append metrics failed: %v", err)
					}
				}
				if err := client.SubmitMetrics(ctx, api.MetricsRequest{NodeID: nodeID, Samples: []model.Metric{sample}}); err != nil {
					log.Printf("submit metrics failed: %v", err)
				}
			}

			if cfg.ServerPublicKey != "" && cfg.ServerEndpoint != "" && len(cfg.ServerAllowedIPs) > 0 {
				if !peersEqual(activePeers, desired) {
					peerList := peersFromMap(desired)
					log.Printf("inject wg peers count=%d", len(peerList))
					if err := wireguard.ApplyPeers(cfg, peerList); err != nil {
						log.Printf("apply peers failed: %v", err)
					} else {
						log.Printf("inject wg peers ok count=%d", len(peerList))
						activePeers = desired
					}
				}
			}
		case <-healthC:
			timeout := time.Duration(cfg.HealthCheckTimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 2 * time.Second
			}
			if checkTunnelHealth(ctx, hubProbeAddr, timeout) {
				healthFailures = 0
			} else {
				healthFailures++
				log.Printf("health check failed (%d/%d) hub=%s", healthFailures, cfg.HealthCheckFailures, hubProbeAddr)
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
	for _, cidr := range cfg.ServerAllowedIPs {
		if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		hubIP := addOne(prefix.Masked().Addr())
		return fmt.Sprintf("%s:%d", hubIP.String(), config.DefaultProbePort)
	}
	return ""
}

func addOne(addr netip.Addr) netip.Addr {
	v := addr.As4()
	val := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	val++
	return netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
}
