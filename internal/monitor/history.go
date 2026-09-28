// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package monitor

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
	"vpnctl/internal/metrics"
	"vpnctl/internal/observation"
	"vpnctl/internal/peersource"
	"vpnctl/internal/pki"
)

const historyBindingTTL = 15 * time.Second

type HistoryStatus struct {
	Enabled           bool              `json:"enabled"`
	MappingReady      bool              `json:"mapping_ready"`
	MappingObservedAt *time.Time        `json:"mapping_observed_at,omitempty"`
	ErrorReason       string            `json:"error_reason,omitempty"`
	MappingDropped    uint64            `json:"mapping_dropped"`
	LastMappingDrop   string            `json:"last_mapping_drop,omitempty"`
	Delivery          observation.Stats `json:"delivery"`
}

// HistoryReporter owns one bounded delivery queue and independent catalog and
// credential loops. Run has one owner; create a new reporter after it stops.
type HistoryReporter struct {
	client    *api.Client
	node, dir string
	queue     *observation.Queue
	mu        sync.Mutex
	peers     map[string]api.MonitorPeer
	observed  time.Time
	reason    string
	dropped   uint64
	lastDrop  string
}

func NewHistoryReporter(controller, node, dir string) (*HistoryReporter, error) {
	u, err := url.Parse(controller)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("monitor history requires an explicit https controller URL")
	}
	if _, err := pki.NodeIdentityURI(node); err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, fmt.Errorf("monitor history requires pki_dir")
	}
	creds, err := pki.LoadCredentials(dir)
	if err != nil {
		return nil, err
	}
	if err = creds.ValidateForInstall(node); err != nil {
		return nil, err
	}
	return &HistoryReporter{client: api.NewCredentialClient(strings.TrimRight(controller, "/"), dir), node: node, dir: dir, queue: observation.New(), reason: "not_started"}, nil
}
func (h *HistoryReporter) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.client.MaintainCredentials(ctx, h.dir, h.node) }()
	go func() {
		defer wg.Done()
		h.queue.Run(ctx, func(context.Context, history.Observation) (bool, error) {
			return false, fmt.Errorf("missing monitor binding")
		})
	}()
	defer func() { wg.Wait(); h.client.CloseIdleConnections() }()
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		h.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
func (h *HistoryReporter) refresh(ctx context.Context) {
	work, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	catalog, err := h.client.MonitorPeers(work, h.node)
	peers := make(map[string]api.MonitorPeer, len(catalog.Peers))
	seenIDs, seenIPs := map[string]bool{}, map[string]bool{}
	if err == nil {
		for _, p := range catalog.Peers {
			ip, e := netip.ParseAddr(p.VPNIP)
			_, identityErr := pki.NodeIdentityURI(p.NodeID)
			epoch, epochErr := hex.DecodeString(p.Epoch)
			if e != nil || identityErr != nil || p.NodeID == h.node || p.PublicKey == "" || len(p.PublicKey) > 128 || epochErr != nil || (len(epoch) != 16 && len(epoch) != 32) || seenIDs[p.NodeID] || peers[p.PublicKey].NodeID != "" {
				err = fmt.Errorf("invalid or ambiguous monitor catalog")
				break
			}
			p.VPNIP = ip.String()
			// Reject duplicate addresses as well as duplicate public keys/IDs.
			if seenIPs[p.VPNIP] {
				err = fmt.Errorf("duplicate monitor peer address")
				break
			}
			seenIDs[p.NodeID], seenIPs[p.VPNIP] = true, true
			peers[p.PublicKey] = p
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		if h.reason != "catalog_unavailable" {
			slog.Warn("monitor history mapping unavailable", "error", err)
		}
		h.peers = nil
		h.reason = "catalog_unavailable"
		return
	}
	h.peers, h.observed, h.reason = peers, time.Now().UTC(), ""
}
func (h *HistoryReporter) Status() HistoryStatus {
	if h == nil {
		return HistoryStatus{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := HistoryStatus{Enabled: true, MappingReady: h.reason == "" && time.Since(h.observed) >= 0 && time.Since(h.observed) <= historyBindingTTL, ErrorReason: h.reason, MappingDropped: h.dropped, LastMappingDrop: h.lastDrop, Delivery: h.queue.Stats()}
	if !h.observed.IsZero() {
		s.MappingObservedAt = ptr(h.observed)
	}
	if s.ErrorReason == "" && !s.MappingReady {
		s.ErrorReason = "catalog_stale"
	}
	return s
}

// bind runs before the network attempt. Its closure captures the exact mapping
// for retries; refreshing the catalog cannot rename a queued observation.
func (h *HistoryReporter) bind(peer peersource.Peer) func(time.Time, probeOutcome) {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	p, exists := h.peers[peer.PublicKey]
	reason := ""
	switch {
	case h.reason != "" || h.observed.IsZero() || time.Since(h.observed) < 0 || time.Since(h.observed) > historyBindingTTL:
		reason = "catalog_unavailable"
	case !exists:
		reason = "peer_not_registered"
	case p.VPNIP != peer.VPNIP:
		reason = "peer_binding_mismatch"
	}
	if reason != "" {
		h.dropped++
		if h.lastDrop != reason {
			slog.Warn("monitor observation cannot be uploaded", "reason", reason)
		}
		h.lastDrop = reason
		metrics.MonitorHistoryMappingDroppedTotal.WithLabelValues(reason).Inc()
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()
	return func(at time.Time, out probeOutcome) {
		o := history.Observation{Timestamp: at, PeerID: p.NodeID, Source: "monitor-overlay", Path: "unknown", Reason: out.reason}
		if out.unknown || out.reason == "invalid_probe_target" {
			o.Validity = "unknown"
		} else {
			o.Success = ptr(out.success)
			if out.success {
				o.RTTMs = ptr(float64(out.rtt) / 1000)
			}
		}
		h.queue.EmitTo(o, func(ctx context.Context, e history.Observation) (bool, error) {
			return api.HistoryDeliveryResult(h.client.SubmitMonitorMetrics(ctx, api.MonitorMetricsRequest{NodeID: h.node, Peer: p, Observation: e}))
		})
	}
}
func (m *Monitor) reportDiscoveryFailure(reason string) {
	if m.cfg.History == nil {
		return
	}
	// Use only previously discovered peers; no new identities or network attempts
	// are invented during discovery failure. The server still revalidates them.
	for _, p := range m.Latest().Peers {
		if send := m.cfg.History.bind(p.Peer); send != nil {
			send(time.Now().UTC(), probeOutcome{unknown: true, reason: reason})
		}
	}
}
