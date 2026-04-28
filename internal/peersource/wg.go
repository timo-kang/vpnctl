// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package peersource

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const defaultProbePort = 51900

// WgSource implements PeerSource by reading live WireGuard state via `wg show dump`.
type WgSource struct {
	iface     string
	probePort int
}

// NewWgSource returns a WgSource for the given interface.
// If probePort is <= 0 it defaults to 51900.
func NewWgSource(iface string, probePort int) *WgSource {
	if probePort <= 0 {
		probePort = defaultProbePort
	}
	return &WgSource{iface: iface, probePort: probePort}
}

// InterfaceName returns the WireGuard interface name.
func (s *WgSource) InterfaceName() string { return s.iface }

// SelfIP returns the first IPv4 address assigned to the WireGuard interface.
func (s *WgSource) SelfIP() string {
	ip, _ := detectSelfIP(s.iface)
	return ip
}

// Discover runs `wg show <iface> dump` and returns the parsed set of peers.
func (s *WgSource) Discover() ([]Peer, error) {
	out, err := wgShowDump(s.iface)
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", s.iface, err)
	}
	return parseWgDump(out, s.probePort), nil
}

// wgShowDump executes `wg show <iface> dump` and returns the raw output.
func wgShowDump(iface string) (string, error) {
	cmd := exec.Command("wg", "show", iface, "dump")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// detectSelfIP reads the first IPv4 address on the given interface via `ip -4 addr show dev <iface>`.
func detectSelfIP(iface string) (string, error) {
	cmd := exec.Command("ip", "-4", "addr", "show", "dev", iface)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet ") {
			continue
		}
		// "inet 10.7.0.1/24 scope global wg0"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		addr := parts[1]
		// Strip prefix length if present.
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		return addr, nil
	}
	return "", fmt.Errorf("no IPv4 address found on %s", iface)
}

// parseWgDump parses the output of `wg show <iface> dump` and returns valid peers.
//
// Format (tab-separated):
//   - Line 1: interface info (private-key, public-key, listen-port, fwmark)
//   - Line 2+: public-key \t preshared-key \t endpoint \t allowed-ips \t
//     latest-handshake \t transfer-rx \t transfer-tx \t persistent-keepalive
//
// Peers with no valid endpoint (none, 0.0.0.0:0, [::]:0) are skipped.
func parseWgDump(dump string, probePort int) []Peer {
	var peers []Peer
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) == 0 {
		return peers
	}
	// Skip the first line — it contains interface-level info, not a peer.
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		pubKey := fields[0]
		endpoint := fields[2]
		allowedIPs := fields[3]
		lastHandshakeRaw := fields[4]

		// Skip peers that have no usable endpoint.
		if !isValidEndpoint(endpoint) {
			continue
		}

		vpnIP := extractVPNIP(allowedIPs)

		var lastHandshake time.Time
		if ts, err := strconv.ParseInt(lastHandshakeRaw, 10, 64); err == nil && ts > 0 {
			lastHandshake = time.Unix(ts, 0)
		}

		name := pubKey
		if len(name) > 8 {
			name = name[:8]
		}

		peers = append(peers, Peer{
			PublicKey:     pubKey,
			VPNIP:         vpnIP,
			Endpoint:      endpoint,
			Name:          name,
			ProbePort:     probePort,
			LastHandshake: lastHandshake,
		})
	}
	return peers
}

// isValidEndpoint returns true when the endpoint string represents a real remote address.
func isValidEndpoint(ep string) bool {
	if ep == "" || ep == "(none)" || ep == "0.0.0.0:0" || ep == "[::]:0" {
		return false
	}
	return true
}

// extractVPNIP picks the host address from a comma-separated list of AllowedIPs.
// It prefers entries with a /32 prefix; if none exists it falls back to the first entry.
func extractVPNIP(allowedIPs string) string {
	entries := strings.Split(allowedIPs, ",")

	var first string
	for _, cidr := range entries {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		host, prefix, ok := strings.Cut(cidr, "/")
		if !ok {
			// No slash — treat the whole value as an IP.
			if first == "" {
				first = cidr
			}
			continue
		}
		if first == "" {
			first = host
		}
		if prefix == "32" {
			return host
		}
	}
	return first
}
