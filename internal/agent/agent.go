package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/metrics"
	"vpnctl/internal/model"
	"vpnctl/internal/stunutil"
)

// Run starts the long-running node agent loop.
func Run(ctx context.Context, cfg config.NodeConfig) error {
	client := api.NewClient(normalizeBaseURL(cfg.Controller))

	nodeID, err := register(ctx, client, cfg)
	if err != nil {
		return err
	}

	var shared *direct.Shared
	if cfg.DirectMode != "off" {
		shared, err = direct.ListenShared(":0")
		if err != nil {
			return err
		}
		defer shared.Close()
		log.Printf("direct responder on %s", shared.LocalAddr())
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-keepaliveTicker.C:
			_, err := register(ctx, client, cfg)
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
			for _, peer := range candidates {
				peerAddr := peer.PublicAddr
				path := "direct"
				if peerAddr == "" {
					peerAddr = peer.Endpoint
					path = "relay"
				}
				if peerAddr == "" {
					continue
				}

				rtt, err := direct.ProbePeer(ctx, ":0", peerAddr, 2*time.Second)
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

func register(ctx context.Context, client *api.Client, cfg config.NodeConfig) (string, error) {
	resp, err := client.Register(ctx, api.RegisterRequest{
		Name:       cfg.Name,
		PubKey:     cfg.WGPublicKey,
		VPNIP:      cfg.VPNIP,
		Endpoint:   "",
		PublicAddr: "",
		NATType:    "",
		DirectMode: cfg.DirectMode,
	})
	if err != nil {
		return "", err
	}
	return resp.NodeID, nil
}

func normalizeBaseURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}
