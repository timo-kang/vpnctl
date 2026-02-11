package addrutil

import (
	"net"
	"strconv"
	"strings"
)

// ProbeAddr builds a stable "direct probe" address for a peer.
//
// Direct probing uses a dedicated UDP probe port (probePort) which is not the same as the
// WireGuard transport port. STUN-derived public_addr often contains an ephemeral NAT-mapped
// port which is not suitable when the probe port is fixed (e.g. via port-forwarding).
//
// We therefore take the host from publicAddr (preferred) or from endpoint, and always
// join it with probePort.
func ProbeAddr(publicAddr, endpoint string, probePort int) (string, bool) {
	if probePort <= 0 {
		return "", false
	}

	host := hostFromAddr(publicAddr)
	if host == "" {
		host = hostFromAddr(endpoint)
	}
	if host == "" {
		return "", false
	}

	return net.JoinHostPort(host, strconv.Itoa(probePort)), true
}

func hostFromAddr(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}

	// Fast path: "host:port" (IPv4 or bracketed IPv6).
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}

	// Handle unbracketed IPv6 "host:port" by peeling off the last ":port".
	if strings.Count(a, ":") > 1 && !strings.HasPrefix(a, "[") {
		if last := strings.LastIndexByte(a, ':'); last > 0 && last < len(a)-1 {
			host := a[:last]
			port := a[last+1:]
			if _, err := strconv.Atoi(port); err == nil {
				return host
			}
		}
	}

	// If there's no port at all, accept raw IPs/hosts.
	if strings.Contains(a, ":") {
		// Likely raw IPv6 without port.
		return strings.Trim(a, "[]")
	}
	return a
}

