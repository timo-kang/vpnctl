// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"io"
	"time"

	"vpnctl/internal/peersource"
)

// WatchWriter writes one line per peer per snapshot in plain text format.
type WatchWriter struct {
	w io.Writer
}

// NewWatchWriter creates a new WatchWriter that writes to w.
func NewWatchWriter(w io.Writer) *WatchWriter {
	return &WatchWriter{w: w}
}

// Write outputs one line per peer in the snapshot.
// Format: [HH:MM:SS] %-12s %-15s %6s %5s  %s
func (ww *WatchWriter) Write(snap Snapshot) {
	ts := snap.Time.Local().Format("15:04:05")
	if h := snap.History; h.Enabled {
		fmt.Fprintf(ww.w, "[%s] central history: mapping=%t delivered=%d pending=%d dropped=%d quota_dropped=%d mapping_dropped=%d reason=%s last_mapping_drop=%s\n", ts, h.MappingReady, h.Delivery.Delivered, h.Delivery.Pending, h.Delivery.Dropped, h.Delivery.QuotaDropped, h.MappingDropped, h.ErrorReason, h.LastMappingDrop)
	}
	if snap.ErrorReason != "" || snap.StorageError != "" {
		fmt.Fprintf(ww.w, "[%s] collection=%s stale=%t storage=%s\n", ts, snap.ErrorReason, snap.Stale, snap.StorageError)
	}
	for _, ps := range snap.Peers {
		name := FormatPeerName(ps.Peer)
		ip := ps.Peer.VPNIP

		rtt, loss := formatQuality(ps.Quality)

		hs := formatHandshake(ps.Peer.LastHandshake)

		fmt.Fprintf(ww.w, "[%s] %-12s %-15s %6s %5s  %-8s %s %s\n",
			ts, name, ip, rtt, loss, ps.Quality.Quality, hs+" "+ps.Quality.ErrorReason, formatPercentiles(ps.Quality))
	}
}

// FormatPeerName returns the peer's Name if set, otherwise the first 8 characters
// of the PublicKey.
func FormatPeerName(p peersource.Peer) string {
	if p.Name != "" {
		return p.Name
	}
	if len(p.PublicKey) >= 8 {
		return p.PublicKey[:8]
	}
	return p.PublicKey
}

// formatHandshake returns a human-readable relative time string for t.
// Returns "never" if t is zero.
func formatHandshake(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}

func formatQuality(q PeerQuality) (string, string) {
	rtt, loss := "-", "-"
	if q.RTTMs != nil {
		rtt = fmt.Sprintf("%.2fms", *q.RTTMs)
	}
	if q.LossPct != nil {
		loss = fmt.Sprintf("%.1f%%", *q.LossPct)
	}
	return rtt, loss
}

func formatPercentiles(q PeerQuality) string {
	value := func(v *float64) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprintf("%.2f", *v)
	}
	return fmt.Sprintf("p50/p95/p99(ms)=%s/%s/%s", value(q.P50RTTMs), value(q.P95RTTMs), value(q.P99RTTMs))
}
