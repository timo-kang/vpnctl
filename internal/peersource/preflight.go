package peersource

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

// CheckContext diagnoses the actual command/backend permissions rather than
// assuming that an effective UID implies a usable WireGuard interface.
func (s *WgSource) CheckContext(ctx context.Context) (int, error) {
	if !interfaceName.MatchString(s.iface) {
		return 0, fmt.Errorf("invalid WireGuard interface name %q", s.iface)
	}
	if s.probePort < 1 || s.probePort > 65535 {
		return 0, fmt.Errorf("probe port must be in 1..65535")
	}
	addresses, err := s.runner.OutputContext(ctx, "ip", "-4", "addr", "show", "dev", s.iface)
	if err != nil {
		return 0, fmt.Errorf("monitor interface check: install iproute2 and verify interface %s exists: %w", s.iface, err)
	}
	found := false
	fields := strings.Fields(addresses)
	for i, field := range fields {
		if field == "inet" && i+1 < len(fields) {
			ip, _, err := net.ParseCIDR(fields[i+1])
			if err == nil && ip.To4() != nil {
				found = true
			}
		}
	}
	if !found {
		return 0, fmt.Errorf("interface %s has no IPv4 address; monitor currently requires IPv4 peer addresses", s.iface)
	}
	peers, err := s.DiscoverContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("monitor requires wg show dump access: install wireguard-tools and grant permission to read %s (Linux CAP_NET_ADMIN/root); Tailscale and Nebula peer adapters are not implemented: %w", s.iface, err)
	}
	return len(peers), nil
}
