// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package monitor provides a periodic probing loop that discovers VPN peers,
// measures round-trip latency via UDP echo, and records results into a Store.
package monitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"vpnctl/internal/metrics"
	"vpnctl/internal/peersource"
)

// Config holds configuration for a Monitor instance.
type Config struct {
	Source   peersource.PeerSource
	Store    *Store
	Interval time.Duration // default 5s if <= 0
	Peers    []string      // VPN IP filter; empty = all
}

// Snapshot is the result of a single probe cycle.
type Snapshot struct {
	Time  time.Time
	Peers []PeerState
}

// PeerState holds the result of probing a single peer.
type PeerState struct {
	Peer    peersource.Peer
	RTTus   int64
	Success bool
}

// Monitor runs a periodic probe loop over discovered VPN peers.
type Monitor struct {
	cfg       Config
	latest    Snapshot
	listeners []chan Snapshot
}

// New creates a new Monitor with the given config.
// If cfg.Interval is <= 0, it defaults to 5 seconds.
func New(cfg Config) *Monitor {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Monitor{cfg: cfg}
}

// Subscribe returns a buffered channel (capacity 1) that receives a Snapshot
// after each probe cycle completes. Callers should read from the channel
// promptly; slow consumers will miss snapshots (non-blocking send).
func (m *Monitor) Subscribe() chan Snapshot {
	ch := make(chan Snapshot, 1)
	m.listeners = append(m.listeners, ch)
	return ch
}

// Run blocks until ctx is cancelled. It calls probeAll immediately and then
// again on each tick of cfg.Interval.
func (m *Monitor) Run(ctx context.Context) {
	m.probeAll(ctx)

	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeAll(ctx)
		}
	}
}

// probeAll discovers peers, probes each one, stores results, and notifies listeners.
func (m *Monitor) probeAll(ctx context.Context) {
	peers, err := m.cfg.Source.Discover()
	if err != nil {
		return
	}

	if len(m.cfg.Peers) > 0 {
		peers = filterPeers(peers, m.cfg.Peers)
	}

	now := time.Now().UTC()
	states := make([]PeerState, len(peers))

	var wg sync.WaitGroup
	for i, peer := range peers {
		wg.Add(1)
		go func(idx int, p peersource.Peer) {
			defer wg.Done()
			rttUs, success := probePeer(ctx, p)
			states[idx] = PeerState{
				Peer:    p,
				RTTus:   rttUs,
				Success: success,
			}
			if m.cfg.Store != nil {
				_ = m.cfg.Store.Insert(ProbeResult{
					Timestamp: now,
					PeerKey:   p.PublicKey,
					PeerIP:    p.VPNIP,
					RTTus:     rttUs,
					Success:   success,
				})
			}
			peerLabel := p.VPNIP
			if peerLabel == "" {
				peerLabel = p.PublicKey[:8]
			}
			if success {
				metrics.ProbeRTTSeconds.WithLabelValues(peerLabel).Set(float64(rttUs) / 1e6)
				metrics.ProbeSuccess.WithLabelValues(peerLabel).Set(1)
				metrics.ProbeTotal.WithLabelValues(peerLabel, "success").Inc()
			} else {
				metrics.ProbeSuccess.WithLabelValues(peerLabel).Set(0)
				metrics.ProbeTotal.WithLabelValues(peerLabel, "failure").Inc()
			}
		}(i, peer)
	}
	wg.Wait()

	snap := Snapshot{
		Time:  now,
		Peers: states,
	}
	m.latest = snap

	for _, ch := range m.listeners {
		select {
		case ch <- snap:
		default:
		}
	}
}

// probePeer sends a vpnctl-echo UDP probe to the peer's VPNIP:ProbePort and
// returns the round-trip time in microseconds and whether the probe succeeded.
// It uses a 2-second per-probe timeout. The parent context can cancel early.
// On any error, it returns (0, false).
func probePeer(ctx context.Context, peer peersource.Peer) (rttUs int64, success bool) {
	addr := fmt.Sprintf("%s:%d", peer.VPNIP, peer.ProbePort)

	// Create a per-probe context with a 2-second timeout, derived from the
	// parent so it also cancels when the parent does.
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "udp", addr)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	// Close the connection when the probe context is done to unblock any reads.
	go func() {
		<-probeCtx.Done()
		_ = conn.Close()
	}()

	msg := fmt.Sprintf("vpnctl-echo:monitor-%d", time.Now().UnixNano())
	payload := []byte(msg)

	dl, _ := probeCtx.Deadline()
	if err := conn.SetDeadline(dl); err != nil {
		return 0, false
	}

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, false
	}

	buf := make([]byte, len(payload)+64)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, false
	}

	if string(buf[:n]) != msg {
		return 0, false
	}

	return time.Since(start).Microseconds(), true
}

// filterPeers returns only those peers whose VPNIP is in the ips set.
// If ips is empty, all peers are returned unmodified.
func filterPeers(peers []peersource.Peer, ips []string) []peersource.Peer {
	if len(ips) == 0 {
		return peers
	}
	set := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		set[ip] = struct{}{}
	}
	out := make([]peersource.Peer, 0, len(peers))
	for _, p := range peers {
		if _, ok := set[p.VPNIP]; ok {
			out = append(out, p)
		}
	}
	return out
}
