package wireguard

import (
	"fmt"
	"strings"
)

// PeerEndpoints returns a map of peer public key -> endpoint as currently observed by WireGuard.
// This is the only reliable way to learn the NAT-mapped UDP port for wg traffic when the peer is behind NAT,
// since STUN performed on a different socket yields a different mapping.
func (m *Manager) PeerEndpoints(iface string) (map[string]string, error) {
	if iface == "" {
		return nil, fmt.Errorf("wg_interface is required")
	}
	out, err := m.output("wg", "show", iface, "dump")
	if err != nil {
		return nil, err
	}
	return ParseWgDumpEndpoints(out), nil
}

func PeerEndpoints(iface string) (map[string]string, error) {
	return DefaultManager().PeerEndpoints(iface)
}

func ParseWgDumpEndpoints(dump string) map[string]string {
	endpoints := map[string]string{}
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) == 0 {
		return endpoints
	}
	// First line is interface info.
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pubKey := fields[0]
		endpoint := fields[2]
		if pubKey == "" || endpoint == "" || endpoint == "(none)" || endpoint == "0.0.0.0:0" || endpoint == "[::]:0" {
			continue
		}
		endpoints[pubKey] = endpoint
	}
	return endpoints
}
