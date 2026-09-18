// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package monitor provides a periodic probing loop that discovers VPN peers,
// measures round-trip latency via UDP echo, and records results into a Store.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"vpnctl/internal/metrics"
	"vpnctl/internal/peersource"
)

// Config holds configuration for a Monitor instance.
type Config struct {
	Source    peersource.PeerSource
	Store     *Store
	Interval  time.Duration // default 5s if zero
	Retention time.Duration // local probe retention; default 24h if zero
	Peers     []string      // VPN IP filter; empty = all
	Quality   QualityConfig
}

// Snapshot is the result of a single probe cycle.
type Snapshot struct {
	Time         time.Time
	Peers        []PeerState
	Stale        bool
	ErrorReason  string
	StorageError string
}

// PeerState holds the result of probing a single peer.
type PeerState struct {
	Peer    peersource.Peer
	RTTus   int64
	Success bool
	Quality PeerQuality
}

// Monitor runs a periodic probe loop over discovered VPN peers.
type Monitor struct {
	mu        sync.RWMutex
	cfg       Config
	latest    Snapshot
	listeners []chan Snapshot
	windows   map[peerID]*qualityWindow
}

type peerID struct {
	key, ip string
	port    int
}

func identify(p peersource.Peer) peerID { return peerID{p.PublicKey, p.VPNIP, p.ProbePort} }

// New validates the live quality contract. Zero config values select defaults.
func New(cfg Config) (*Monitor, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Interval < 0 {
		return nil, fmt.Errorf("monitor interval must be positive")
	}
	if cfg.Retention == 0 {
		cfg.Retention = 24 * time.Hour
	}
	if cfg.Retention < time.Minute {
		return nil, fmt.Errorf("monitor retention must be at least one minute")
	}
	var err error
	cfg.Quality, err = cfg.Quality.Normalized(cfg.Interval)
	if err != nil {
		return nil, err
	}
	cfg.Peers = slices.Clone(cfg.Peers)
	return &Monitor{cfg: cfg, windows: make(map[peerID]*qualityWindow)}, nil
}

// Subscribe returns a buffered channel (capacity 1) that receives a Snapshot
// after each probe cycle completes. Callers should read from the channel
// promptly; slow consumers will miss snapshots (non-blocking send).
func (m *Monitor) Subscribe() <-chan Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := make(chan Snapshot, 1)
	m.listeners = append(m.listeners, ch)
	return ch
}

// Run blocks until ctx is cancelled. It calls probeAll immediately and then
// again on each tick of cfg.Interval.
func (m *Monitor) Run(ctx context.Context) {
	maintenanceDone := make(chan struct{})
	if m.cfg.Store != nil {
		go func() {
			defer close(maintenanceDone)
			m.maintain(ctx)
			interval := time.Minute
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					m.maintain(ctx)
				}
			}
		}()
	} else {
		close(maintenanceDone)
	}

	m.probeAll(ctx)
	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()
	defer func() { <-maintenanceDone }()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeAll(ctx)
		}
	}
}

func (m *Monitor) maintain(ctx context.Context) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if removed, err := m.cfg.Store.CleanupContext(ctx, m.cfg.Retention); err != nil {
		if parent.Err() == nil {
			logMaintenanceError(err)
		}
	} else if removed > 0 {
		slog.Debug("monitor history retention", "removed", removed)
	}
}

// probeAll discovers peers, probes each one, stores results, and notifies listeners.
func (m *Monitor) probeAll(ctx context.Context) {
	peers, err := peersource.Discover(ctx, m.cfg.Source)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		m.recordCycle(time.Now().UTC(), nil, nil, "discovery_failed", "")
		return
	}
	peers = filterPeers(peers, m.cfg.Peers)
	seen := make(map[string]bool)
	for _, p := range peers {
		if seen[p.VPNIP] {
			m.recordCycle(time.Now().UTC(), nil, nil, "discovery_conflict", "")
			return
		}
		seen[p.VPNIP] = true
	}
	outcomes := make([]probeOutcome, len(peers))
	var wg sync.WaitGroup
	for i, peer := range peers {
		wg.Add(1)
		go func(i int, peer peersource.Peer) { defer wg.Done(); outcomes[i] = probePeer(ctx, peer) }(i, peer)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	} // Shutdown is not a network failure sample.
	now := time.Now().UTC()
	storageError := ""
	for i, p := range peers {
		result := outcomes[i]
		if result.reason == "invalid_probe_target" {
			continue
		} // No network attempt was made.
		if m.cfg.Store != nil {
			if err := m.cfg.Store.InsertContext(ctx, ProbeResult{Timestamp: now, PeerKey: p.PublicKey, PeerIP: p.VPNIP, RTTus: result.rtt, Success: result.success}); err != nil {
				if storageError == "" {
					slog.Warn("monitor history write failed", "error", err)
				}
				storageError = "store_write_failed"
			}
		}
		outcome := "failure"
		if result.success {
			outcome = "success"
		}
		metrics.ProbeTotal.WithLabelValues(p.VPNIP, outcome).Inc()
	}
	m.recordCycle(now, peers, outcomes, "", storageError)
}

// recordCycle owns the only quality calculation; persistence is not its source.
func (m *Monitor) recordCycle(now time.Time, peers []peersource.Peer, outcomes []probeOutcome, discoveryError, storageError string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := Snapshot{Time: now, Peers: make([]PeerState, 0, len(peers)), StorageError: storageError}
	if discoveryError != "" {
		snap.Peers = cloneSnapshot(m.latest).Peers
		snap.ErrorReason, snap.Stale = discoveryError, true
		for i := range snap.Peers {
			snap.Peers[i].Quality.SetLevel(QualityUnknown)
			snap.Peers[i].Quality.Stale = true
			snap.Peers[i].Quality.ErrorReason = discoveryError
		}
		for _, w := range m.windows {
			if w.state != nil {
				w.state.ResetAssessment()
			}
		}
	} else {
		if len(peers) == 0 {
			snap.ErrorReason = "no_peers"
		}
		active := make(map[peerID]*qualityWindow, len(peers))
		for i, p := range peers {
			id := identify(p)
			w := m.windows[id]
			if w == nil {
				w = &qualityWindow{}
			}
			q := w.observe(now, outcomes[i], m.cfg.Quality)
			q.PeerIP = p.VPNIP
			snap.Peers = append(snap.Peers, PeerState{Peer: p, RTTus: outcomes[i].rtt, Success: outcomes[i].success, Quality: q})
			active[id] = w
		}
		m.windows = active // Removed or reassigned identities never inherit old quality.
	}
	m.publishLocked(snap)
}

func (m *Monitor) publish(snap Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publishLocked(snap)
}

func (m *Monitor) publishLocked(snap Snapshot) {
	m.latest = cloneSnapshot(snap)

	for _, ch := range m.listeners {
		select {
		case ch <- cloneSnapshot(snap):
		default:
			// Replace an unread older publication with the newest state.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- cloneSnapshot(snap):
			default:
			}
		}
	}
}

type probeOutcome struct {
	rtt     int64
	success bool
	reason  string
}

// probePeer validates an exact UDP echo within two seconds. Timeouts alone cannot
// distinguish a failed tunnel from an unavailable remote responder.
func probePeer(ctx context.Context, peer peersource.Peer) probeOutcome {
	if net.ParseIP(peer.VPNIP) == nil || peer.ProbePort <= 0 || peer.ProbePort > 65535 {
		return probeOutcome{reason: "invalid_probe_target"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	failure := func(err error) probeOutcome {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return probeOutcome{reason: "probe_timeout"}
		}
		return probeOutcome{reason: probeError(err)}
	}
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "udp", net.JoinHostPort(peer.VPNIP, strconv.Itoa(peer.ProbePort)))
	if err != nil {
		return failure(err)
	}
	defer conn.Close()
	stop := context.AfterFunc(probeCtx, func() { _ = conn.Close() })
	defer stop()
	dl, _ := probeCtx.Deadline()
	if err := conn.SetDeadline(dl); err != nil {
		return failure(err)
	}
	payload := []byte(fmt.Sprintf("vpnctl-echo:monitor-%d", time.Now().UnixNano()))
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return failure(err)
	}
	buf := make([]byte, len(payload)+64)
	n, err := conn.Read(buf)
	if err != nil {
		return failure(err)
	}
	if string(buf[:n]) != string(payload) {
		return probeOutcome{reason: "invalid_response"}
	}
	return probeOutcome{rtt: time.Since(start).Microseconds(), success: true}
}

func probeError(err error) string {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "responder_unavailable"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "route_unreachable"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "probe_timeout"
	}
	return "probe_error"
}

// Latest applies freshness at read time, even if discovery or storage is stuck.
func (m *Monitor) Latest() Snapshot { return m.latestAt(time.Time{}) }
func (m *Monitor) latestAt(now time.Time) Snapshot {
	m.mu.RLock()
	snap := cloneSnapshot(m.latest)
	// Read the clock after the snapshot: a concurrent newer publication must not
	// be mistaken for a backwards clock step. Explicit test clocks are unchanged.
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.RUnlock()
	if snap.Time.IsZero() {
		snap.Stale, snap.ErrorReason = true, "not_started"
	} else if now.Before(snap.Time) {
		snap.Stale, snap.ErrorReason = true, "clock_regressed"
	} else if !now.Before(snap.Time.Add(m.cfg.Quality.StaleAfter)) {
		snap.Stale = true
		if snap.ErrorReason == "" || snap.ErrorReason == "no_peers" {
			snap.ErrorReason = "stale"
		}
	}
	for i := range snap.Peers {
		q := &snap.Peers[i].Quality
		if snap.Stale || q.ObservedAt == nil || !now.Before(q.ObservedAt.Add(m.cfg.Quality.StaleAfter)) {
			q.Stale = true
			q.SetLevel(QualityUnknown)
			if snap.ErrorReason == "clock_regressed" {
				q.ErrorReason = "clock_regressed"
			} else if q.ErrorReason == "" || q.ErrorReason == "insufficient_samples" || q.ErrorReason == "recovering" {
				q.ErrorReason = "stale"
			}
		}
	}
	return snap
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

func cloneSnapshot(s Snapshot) Snapshot {
	s.Peers = slices.Clone(s.Peers)
	for i := range s.Peers {
		s.Peers[i].Quality = s.Peers[i].Quality.Clone()
	}
	return s
}

func logMaintenanceError(err error) {
	slog.Warn("monitor history retention failed", "error", err)
}
