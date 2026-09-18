// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"

	"vpnctl/internal/addrutil"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/history"
	"vpnctl/internal/metrics"
	"vpnctl/internal/model"
	"vpnctl/internal/observation"
	"vpnctl/internal/wireguard"
)

const directBatchSize = 8
const directRoundPeers = 32

type directSnapshot struct {
	peers               []api.PeerCandidate
	publicAddr, natType string
}
type directSnapshots struct {
	mu      sync.Mutex
	current directSnapshot
}

func (s *directSnapshots) update(out chan directSnapshot, change func(*directSnapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.current
	change(&next)
	if slices.Equal(next.peers, s.current.peers) && next.publicAddr == s.current.publicAddr && next.natType == s.current.natType {
		return
	}
	s.current = next
	// A single latest snapshot replaces any unconsumed update. No unbounded queue.
	select {
	case <-out:
	default:
	}
	out <- next
}

// This is the only owner of WG peer application. Probe results never apply WG
// state. New input cancels and drains the old measurement before replacing it.
func runDirect(ctx context.Context, client *api.Client, cfg config.NodeConfig, nodeID string, shared *direct.Shared, updates <-chan directSnapshot, applyPeers func([]wireguard.Peer) error) {
	interval := time.Duration(cfg.DirectIntervalSec) * time.Second
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	var snapshot directSnapshot
	active := map[string]wireguard.Peer{}
	var stop context.CancelFunc
	var done chan struct{}
	drain := func() {
		if stop != nil {
			stop()
			<-done
			stop = nil
			done = nil
		}
	}
	defer drain()
	cursor := 0
	apply := func() {
		desired := desiredDirectPeers(cfg, snapshot.peers)
		if cfg.ServerPublicKey == "" || cfg.ServerEndpoint == "" || len(cfg.ServerAllowedIPs) == 0 || peersEqual(active, desired) {
			return
		}
		if err := applyPeers(peersFromMap(desired)); err != nil {
			slog.Error("apply peers failed", "err", err)
		} else {
			active = desired
			slog.Info("wg peers injected", "count", len(desired))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case next := <-updates:
			wasRunning := stop != nil
			drain()
			snapshot = next
			apply()
			if wasRunning {
				timer.Reset(interval)
			}
		case <-done:
			stop()
			stop = nil
			done = nil
			timer.Reset(interval)
		case <-timer.C:
			apply()
			if shared == nil || len(snapshot.peers) == 0 {
				timer.Reset(interval)
				continue
			}
			// Up to 32 peers per round, eight concurrent probes/reports. A 15s
			// round budget bounds work independently of fleet size. History delivery is separate.
			count := min(directRoundPeers, len(snapshot.peers))
			batch := make([]api.PeerCandidate, count)
			for i := range batch {
				batch[i] = snapshot.peers[(cursor+i)%len(snapshot.peers)]
			}
			cursor = (cursor + count) % len(snapshot.peers)
			work, cancel := context.WithCancel(ctx)
			stop = cancel
			done = make(chan struct{})
			completed, current := done, snapshot
			go func() { defer close(completed); measureDirect(work, client, cfg, nodeID, shared, current, batch) }()
		}
	}
}

func desiredDirectPeers(cfg config.NodeConfig, candidates []api.PeerCandidate) map[string]wireguard.Peer {
	desired := map[string]wireguard.Peer{}
	allowedOwner := map[string]string{}
	for _, peer := range candidates {
		allowed := normalizeHostIP(peer.VPNIP)
		// The WG endpoint must never be replaced by the STUN probe socket address.
		if !peer.P2PReady || allowed == "" || peer.PubKey == "" || peer.Endpoint == "" {
			continue
		}
		if owner, ok := allowedOwner[allowed]; ok && owner != peer.ID {
			slog.Warn("skip duplicate allowed IP", "peer", peer.ID, "owner", owner)
			continue
		}
		allowedOwner[allowed] = peer.ID
		desired[peer.ID] = wireguard.Peer{PublicKey: peer.PubKey, Endpoint: peer.Endpoint, AllowedIPs: []string{allowed}, KeepaliveSec: directKeepalive(cfg, peer.NATType)}
	}
	return desired
}

func measureDirect(ctx context.Context, client *api.Client, cfg config.NodeConfig, nodeID string, shared *direct.Shared, snapshot directSnapshot, batch []api.PeerCandidate) {
	budget, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	samples := make(chan model.Metric, len(batch))
	var group sync.WaitGroup
	jobs := make(chan api.PeerCandidate, len(batch))
	for _, peer := range batch {
		jobs <- peer
	}
	close(jobs)
	for i := 0; i < min(directBatchSize, len(batch)); i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for peer := range jobs {
				if ctx.Err() != nil {
					return
				}
				if budget.Err() != nil {
					observation.Emit(ctx, unknownDirect(peer.ID, "round_budget_exhausted"))
					continue
				}
				addr, ok := addrutil.ProbeAddr(peer.PublicAddr, peer.Endpoint, peer.ProbePort)
				if !ok || peer.ProbePort > 65535 {
					observation.Emit(ctx, unknownDirect(peer.ID, "invalid_probe_target"))
					continue
				}
				func() {
					attempt, stop := context.WithTimeout(budget, 3*time.Second)
					defer stop()
					rtt, err := shared.ProbePeer(attempt, addr, 2*time.Second)
					if ctx.Err() != nil {
						return
					} // Shutdown/superseded work is not link failure.
					o := directObservation(peer.ID, rtt, err)
					observation.Emit(ctx, o)
					if attempt.Err() != nil {
						return
					}
					// Keep the existing conservative readiness decision independent of
					// the history denominator: local errors still invalidate readiness.
					result := api.DirectResultRequest{NodeID: nodeID, PeerID: peer.ID, Success: err == nil}
					if err != nil {
						result.Reason = err.Error()
					} else {
						result.RTTMs = float64(rtt.Microseconds()) / 1000
					}
					if err := client.SubmitDirectResult(attempt, result); err != nil && attempt.Err() == nil {
						slog.Warn("direct result submit failed", "err", err)
					}
					if !result.Success || attempt.Err() != nil {
						return
					}
					samples <- model.Metric{Timestamp: time.Now().UTC(), NodeID: nodeID, PeerID: peer.ID, Path: "direct", RTTMs: result.RTTMs, MTU: cfg.MTU, NATType: snapshot.natType, PublicAddr: snapshot.publicAddr}
				}()
			}
		}()
	}

	group.Wait()
	close(samples)
	if ctx.Err() != nil {
		return
	}
	collected := make([]model.Metric, 0, len(batch))
	for sample := range samples {
		collected = append(collected, sample)
	}
	if len(collected) == 0 {
		return
	}
	if cfg.MetricsPath != "" {
		if err := metrics.AppendCSV(cfg.MetricsPath, collected); err != nil {
			slog.Warn("append metrics failed", "err", err)
		}
	}
}

func unknownDirect(peer, reason string) history.Observation {
	return history.Observation{PeerID: peer, Path: "direct", Source: "agent-direct", Timestamp: time.Now().UTC(), Validity: "unknown", Reason: reason}
}

// This tests the candidate's public UDP responder, not the WireGuard data path.
// Local collector/socket failures do not enter the network-attempt denominator.
func directObservation(peer string, rtt time.Duration, err error) history.Observation {
	o := unknownDirect(peer, "collector_unavailable")
	if err == nil {
		yes, ms := true, float64(rtt.Microseconds())/1000
		o.Success, o.RTTMs, o.Validity, o.Reason = &yes, &ms, "observed", ""
		return o
	}
	var probeErr *direct.ProbeError
	if errors.As(err, &probeErr) && !probeErr.Sent && !errors.Is(err, syscall.ENETUNREACH) && !errors.Is(err, syscall.EHOSTUNREACH) && !errors.Is(err, syscall.ECONNREFUSED) {
		return o
	}
	reason := ""
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		reason = "probe_timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		reason = "responder_unavailable"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		reason = "route_unreachable"
	case errors.As(err, &netErr) && netErr.Timeout():
		reason = "probe_timeout"
	}
	if reason != "" {
		no := false
		o.Success, o.Validity, o.Reason = &no, "observed", reason
	}
	return o
}
