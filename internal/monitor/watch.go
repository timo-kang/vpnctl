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
	for _, ps := range snap.Peers {
		name := FormatPeerName(ps.Peer)
		ip := ps.Peer.VPNIP

		var rtt, loss string
		if ps.Success {
			ms := ps.RTTus / 1000
			rtt = fmt.Sprintf("%dms", ms)
			loss = "0.0%"
		} else {
			rtt = "-"
			loss = "100%"
		}

		hs := formatHandshake(ps.Peer.LastHandshake)

		fmt.Fprintf(ww.w, "[%s] %-12s %-15s %6s %5s  %-8s %s\n",
			ts, name, ip, rtt, loss, ps.Quality.String(), hs)
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
