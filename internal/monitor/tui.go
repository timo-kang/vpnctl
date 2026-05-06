// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// lipgloss styles used by the TUI.
var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	failStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

// qualityStyle returns the lipgloss style for the given link quality level.
func qualityStyle(q LinkQuality) lipgloss.Style {
	switch q {
	case QualityGood:
		return okStyle
	case QualityDegraded:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	default:
		return failStyle
	}
}

// snapshotMsg is a bubbletea message carrying a new Snapshot.
type snapshotMsg Snapshot

// waitForSnapshot returns a Cmd that blocks until a Snapshot arrives on sub.
func waitForSnapshot(sub chan Snapshot) tea.Cmd {
	return func() tea.Msg {
		snap := <-sub
		return snapshotMsg(snap)
	}
}

// TUIModel is a bubbletea model for the live monitor dashboard.
type TUIModel struct {
	iface    string
	snap     Snapshot
	quitting bool
	sub      chan Snapshot
}

// NewTUIModel creates a TUIModel subscribed to the given snapshot channel.
func NewTUIModel(iface string, sub chan Snapshot) TUIModel {
	return TUIModel{
		iface: iface,
		sub:   sub,
	}
}

// Init returns the initial command: wait for the first snapshot.
func (m TUIModel) Init() tea.Cmd {
	return waitForSnapshot(m.sub)
}

// Update handles incoming messages and key presses.
func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}
	case snapshotMsg:
		m.snap = Snapshot(msg)
		return m, waitForSnapshot(m.sub)
	}
	return m, nil
}

// View renders the dashboard.
func (m TUIModel) View() string {
	if m.quitting {
		return ""
	}

	var sb strings.Builder

	// Header line
	peerCount := len(m.snap.Peers)
	timeStr := ""
	if !m.snap.Time.IsZero() {
		timeStr = m.snap.Time.Local().Format("15:04:05")
	}
	header := fmt.Sprintf("vpnctl monitor — %s — %d peers — %s", m.iface, peerCount, timeStr)
	sb.WriteString(headerStyle.Render(header))
	sb.WriteString("\n\n")

	// Column headers
	colHeader := fmt.Sprintf("  %-14s %-16s %6s  %5s  %-8s  %s", "PEER", "VPN IP", "RTT", "LOSS", "QUALITY", "HANDSHAKE")
	sb.WriteString(dimStyle.Render(colHeader))
	sb.WriteString("\n")

	separator := "  " + strings.Repeat("─", 62)
	sb.WriteString(dimStyle.Render(separator))
	sb.WriteString("\n")

	// Peer rows
	for _, ps := range m.snap.Peers {
		name := FormatPeerName(ps.Peer)
		ip := ps.Peer.VPNIP
		hs := formatHandshake(ps.Peer.LastHandshake)

		var rtt, loss string
		if ps.Success {
			ms := ps.RTTus / 1000
			rtt = fmt.Sprintf("%dms", ms)
			loss = "0.0%"
		} else {
			rtt = "-"
			loss = "100%"
		}

		prefix := fmt.Sprintf("  %-14s %-16s %6s  %5s  ", name, ip, rtt, loss)
		qualStr := fmt.Sprintf("%-8s", ps.Quality.String())
		suffix := fmt.Sprintf("  %s", hs)

		sb.WriteString(qualityStyle(ps.Quality).Render(prefix + qualityStyle(ps.Quality).Render(qualStr) + suffix))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  q: quit"))
	sb.WriteString("\n")

	return sb.String()
}
