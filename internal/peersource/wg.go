// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package peersource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"vpnctl/internal/execx"
	"vpnctl/internal/wgstats"
)

const defaultProbePort = 51900

// WgSource implements PeerSource by reading live WireGuard state via `wg show dump`.
type WgSource struct {
	mu              sync.Mutex
	members         map[string]string
	previous        map[string]wgstats.Sample
	now             func() time.Time
	device          string
	session         string
	iface           string
	probePort       int
	runner          execx.ContextRunner
	interfaceLookup func(string) (*net.Interface, error)
}

// NewWgSource returns a WgSource for the given interface.
// If probePort is <= 0 it defaults to 51900.
func NewWgSource(iface string, probePort int) *WgSource {
	if probePort <= 0 {
		probePort = defaultProbePort
	}
	return &WgSource{iface: iface, probePort: probePort, runner: execx.NewOSRunner(nil, nil)}
}

// InterfaceName returns the WireGuard interface name.
func (s *WgSource) InterfaceName() string { return s.iface }

// SelfIP returns the first IPv4 address assigned to the WireGuard interface.
func (s *WgSource) SelfIP() string {
	ip, _ := detectSelfIP(s.iface)
	return ip
}

// Discover runs `wg show <iface> dump` and returns the parsed set of peers.
func (s *WgSource) Discover() ([]Peer, error) { return s.DiscoverContext(context.Background()) }

func (s *WgSource) DiscoverContext(ctx context.Context) ([]Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lookup := s.interfaceLookup
	if lookup == nil {
		lookup = net.InterfaceByName
	}
	before, lookupErr := lookup(s.iface)
	out, err := s.runner.OutputContext(ctx, "wg", "show", s.iface, "dump")
	if err != nil {
		s.members = nil
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		reason := "command_failed"
		if lookupErr != nil {
			reason = "interface_unavailable"
		} else if strings.Contains(strings.ToLower(err.Error()), "not permitted") || strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			reason = "permission_denied"
		}
		return nil, &wireGuardError{reason}
	}
	at := time.Now().UTC()
	if s.now != nil {
		at = s.now()
	}
	peers, err := parseWgDumpStrict(out, s.probePort, at)
	if err != nil {
		s.members = nil
		return nil, &wireGuardError{"invalid_dump"}
	}
	iface, err := lookup(s.iface)
	if err != nil || lookupErr != nil || before.Index != iface.Index {
		s.members = nil
		return nil, &wireGuardError{"interface_unavailable"}
	}
	// Session changes on every collector/process restart; ifindex changes on
	// device recreation. Membership epochs change after absence or failed reads.
	if s.session == "" {
		s.session = wgstats.ID()
	}
	fields := strings.Split(strings.Split(strings.TrimSpace(out), "\n")[0], "\t")
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", s.session, iface.Index, fields[1])))
	device := hex.EncodeToString(sum[:16])
	if device != s.device {
		s.members = nil
		s.device = device
	}
	active := make(map[string]string, len(peers))
	previous := make(map[string]wgstats.Sample, len(peers))
	for i := range peers {
		p := &peers[i]
		binding := p.PublicKey + "/" + p.VPNIP
		epoch := s.members[binding]
		if old, ok := s.previous[binding]; ok && epoch != "" {
			candidate := p.WireGuard
			candidate.Generation = epoch
			if v := wgstats.Compare(candidate, &old); v.RateValidity != "inferred" {
				epoch = ""
			}
		}
		if epoch == "" {
			epoch = wgstats.ID()
		}
		active[binding] = epoch
		p.LocalPublicKey = fields[1]
		p.WireGuard.Generation = epoch
		previous[binding] = p.WireGuard.Clone()
	}
	s.members = active
	s.previous = previous
	return peers, nil
}

// detectSelfIP reads the first IPv4 address on the given interface via `ip -4 addr show dev <iface>`.
func detectSelfIP(iface string) (string, error) {
	out, err := execx.NewOSRunner(nil, nil).Output("ip", "-4", "addr", "show", "dev", iface)
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

// parseWgDump retains endpoint-less peers. The strict collector rejects an
// entire malformed dump, never publishing partial or fabricated zero counters.
func parseWgDump(dump string, probePort int) []Peer {
	peers, _ := parseWgDumpStrict(dump, probePort, time.Now().UTC())
	return peers
}
func parseWgDumpStrict(dump string, probePort int, at time.Time) ([]Peer, error) {
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(strings.Split(lines[0], "\t")) != 4 {
		return nil, fmt.Errorf("invalid WireGuard interface record")
	}
	if len(lines)-1 > wgstats.MaxPeers {
		return nil, fmt.Errorf("WireGuard peer capacity exceeded")
	}
	peers := make([]Peer, 0, len(lines)-1)
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 8 {
			return nil, fmt.Errorf("invalid WireGuard peer record")
		}
		key, e := base64.StdEncoding.DecodeString(fields[0])
		if e != nil || len(key) != 32 || seen[fields[0]] {
			return nil, fmt.Errorf("invalid or duplicate WireGuard peer key")
		}
		seen[fields[0]] = true
		hs, e := strconv.ParseInt(fields[4], 10, 64)
		if e != nil || hs < 0 || hs > 253402300799 {
			return nil, fmt.Errorf("invalid WireGuard handshake")
		}
		rx, e := strconv.ParseUint(fields[5], 10, 64)
		if e != nil {
			return nil, fmt.Errorf("invalid WireGuard RX counter")
		}
		tx, e := strconv.ParseUint(fields[6], 10, 64)
		if e != nil {
			return nil, fmt.Errorf("invalid WireGuard TX counter")
		}
		sample := wgstats.Sample{ObservedAt: at, Validity: "observed", Endpoint: isValidEndpoint(fields[2])}
		r, t := wgstats.Counter(rx), wgstats.Counter(tx)
		sample.RX = &r
		sample.TX = &t
		var handshake time.Time
		if hs > 0 {
			handshake = time.Unix(hs, 0).UTC()
			sample.Handshake = &handshake
		}
		peers = append(peers, Peer{PublicKey: fields[0], VPNIP: extractVPNIP(fields[3]), Endpoint: fields[2], Name: fields[0][:8], ProbePort: probePort, LastHandshake: handshake, WireGuard: sample})
	}
	return peers, nil
}

// isValidEndpoint returns true when the endpoint string represents a real remote address.
func isValidEndpoint(ep string) bool {
	if ep == "" || ep == "(none)" || ep == "0.0.0.0:0" || ep == "[::]:0" {
		return false
	}
	host, port, err := net.SplitHostPort(ep)
	ip, ipErr := netip.ParseAddr(host)
	n, portErr := strconv.Atoi(port)
	return err == nil && ipErr == nil && !ip.IsUnspecified() && portErr == nil && n > 0 && n <= 65535
}

// extractVPNIP picks the host address from a comma-separated list of AllowedIPs.
// It prefers entries with a /32 prefix; if none exists it falls back to the first entry.
func extractVPNIP(allowedIPs string) string {
	var first string
	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if addr, e := netip.ParseAddr(cidr); e == nil {
			if first == "" {
				first = addr.String()
			}
			continue
		}
		prefix, e := netip.ParsePrefix(cidr)
		if e != nil {
			continue
		}
		if first == "" {
			first = prefix.Addr().String()
		}
		if prefix.IsSingleIP() {
			return prefix.Addr().String()
		}
	}
	return first
}

type wireGuardError struct{ reason string }

func (e *wireGuardError) Error() string { return "WireGuard collection: " + e.reason }
func WireGuardFailureReason(err error) string {
	var e *wireGuardError
	if errors.As(err, &e) {
		return e.reason
	}
	return "discovery_failed"
}
