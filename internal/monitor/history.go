// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package monitor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"vpnctl/internal/wgstats"
)

const historyBindingTTL = 15 * time.Second

type HistoryStatus struct {
	WireGuardDelivery        observation.Stats `json:"wireguard_delivery"`
	WireGuardIntervalSeconds float64           `json:"wireguard_interval_seconds"`
	Enabled                  bool              `json:"enabled"`
	MappingReady             bool              `json:"mapping_ready"`
	MappingObservedAt        *time.Time        `json:"mapping_observed_at,omitempty"`
	ErrorReason              string            `json:"error_reason,omitempty"`
	MappingDropped           uint64            `json:"mapping_dropped"`
	LastMappingDrop          string            `json:"last_mapping_drop,omitempty"`
	Delivery                 observation.Stats `json:"delivery"`
}

// HistoryReporter owns one bounded delivery queue and independent catalog and
// credential loops. Run has one owner; create a new reporter after it stops.
type HistoryReporter struct {
	client    *api.Client
	node, dir string
	queue     *observation.Queue
	wgqueue   *observation.Queue
	self      api.MonitorPeer
	wgLast    time.Time
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
	return &HistoryReporter{client: api.NewCredentialClient(strings.TrimRight(controller, "/"), dir), node: node, dir: dir, queue: observation.New(), wgqueue: observation.NewWireGuard(), reason: "not_started"}, nil
}
func (h *HistoryReporter) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	if h.wgqueue != nil {
		wg.Add(1)
		go func() { defer wg.Done(); h.wgqueue.Run(ctx, nil) }()
	}
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
		h.peers = nil
		h.reason = "catalog_unavailable"
		return
	}
	h.peers, h.observed, h.reason = peers, time.Now().UTC(), ""
	h.self = catalog.Self
}
func (h *HistoryReporter) Status() HistoryStatus {
	if h == nil {
		return HistoryStatus{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := HistoryStatus{Enabled: true, MappingReady: h.reason == "" && time.Since(h.observed) >= 0 && time.Since(h.observed) <= historyBindingTTL, ErrorReason: h.reason, MappingDropped: h.dropped, LastMappingDrop: h.lastDrop, Delivery: h.queue.Stats()}
	s.WireGuardIntervalSeconds = wgstats.ReportInterval.Seconds()
	if h.wgqueue != nil {
		s.WireGuardDelivery = h.wgqueue.Stats()
	}
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
		// This executes on the probe loop. Report through status/metrics rather
		// than a synchronous log sink that can block both probes and readers.
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
func (m *Monitor) reportDiscoveryFailure(reason string, wgReason ...string) {
	if m.cfg.History == nil {
		return
	}
	// Use only previously discovered peers; no new identities or network attempts
	// are invented during discovery failure. The server still revalidates them.
	known := m.Latest().Peers
	peers := make([]peersource.Peer, 0, len(known))
	at := time.Now().UTC()
	for _, p := range known {
		failure := reason
		if len(wgReason) > 0 {
			failure = wgReason[0]
		}
		p.Peer.WireGuard = wgstats.Unknown(at, failure)
		peers = append(peers, p.Peer)
	}
	failure := reason
	if len(wgReason) > 0 {
		failure = wgReason[0]
	}
	m.cfg.History.reportWireGuard(peers, m.cfg.Source.InterfaceName(), failure)
	for _, p := range known {
		if send := m.cfg.History.bind(p.Peer); send != nil {
			send(time.Now().UTC(), probeOutcome{unknown: true, reason: reason})
		}
	}
}

// reportWireGuard captures both bindings before enqueue, outside probe delivery.
// Minute sampling bounds central storage; local observations retain loop cadence.
func (h *HistoryReporter) reportWireGuard(peers []peersource.Peer, iface string, reason ...string) {
	if h == nil || h.wgqueue == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now().UTC()
	if !h.wgLast.IsZero() && now.Sub(h.wgLast) >= 0 && now.Sub(h.wgLast) < wgstats.ReportInterval {
		return
	}
	if h.reason != "" || now.Before(h.observed) || now.Sub(h.observed) > historyBindingTTL || h.self.Validate() != nil {
		h.dropped++
		h.lastDrop = "wireguard_catalog_unavailable"
		return
	}
	r := wgstats.Report{ID: wgstats.ID(), ObservedAt: now, Reporter: h.self, Interface: iface, Peers: []wgstats.Reading{}}
	if len(reason) > 0 {
		r.CollectionReason = reason[0]
	}
	for _, p := range peers {
		if p.WireGuard.ObservedAt.IsZero() {
			continue
		}
		r.ObservedAt = p.WireGuard.ObservedAt
		break
	}
	for _, p := range peers {
		if p.WireGuard.Validity == "observed" && p.LocalPublicKey != h.self.PublicKey {
			h.dropped++
			h.lastDrop = "wireguard_reporter_binding_mismatch"
			return
		}
		b, ok := h.peers[p.PublicKey]
		if !ok || b.VPNIP != p.VPNIP || !p.WireGuard.ObservedAt.Equal(r.ObservedAt) {
			r.Unmapped++
			continue
		}
		r.Peers = append(r.Peers, wgstats.Reading{Peer: b, Sample: p.WireGuard.Clone()})
	}
	if err := r.Validate(now); err != nil {
		h.dropped++
		h.lastDrop = "wireguard_invalid_report"
		return
	}
	payload, e := json.Marshal(r)
	if e != nil || len(payload) > wgstats.MaxReportBytes {
		h.dropped++
		h.lastDrop = "wireguard_report_too_large"
		return
	}
	h.wgLast = now
	h.wgqueue.Do(func(ctx context.Context, _ string) (bool, error) {
		return api.HistoryDeliveryResult(h.client.SubmitWireGuard(ctx, r))
	})
}
