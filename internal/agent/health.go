package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrTunnelDead is returned by Run when the tunnel health check
// detects the WireGuard tunnel is no longer passing traffic.
var ErrTunnelDead = errors.New("tunnel health check failed")

// checkTunnelHealth sends a UDP packet with a unique vpnctl-echo payload to
// hubAddr (host:port) and waits for an identical reply. Returns (true, nil) only
// if the exact payload is echoed back within timeout. The context cancels the
// dial; the read/write deadline governs I/O.
//
// On read timeout (no reply), returns (false, nil) — the legitimate "tunnel dead" signal.
// On infrastructure errors (dial, write, set-deadline), returns (false, err) so
// the caller can distinguish local failures from tunnel failures.
func checkTunnelHealth(ctx context.Context, hubAddr string, timeout time.Duration) (bool, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", hubAddr)
	if err != nil {
		return false, fmt.Errorf("dial %s: %w", hubAddr, err)
	}
	defer conn.Close()

	msg := []byte(fmt.Sprintf("vpnctl-echo:health-%d", time.Now().UnixNano()))
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.Write(msg); err != nil {
		return false, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, len(msg)+64)
	n, err := conn.Read(buf)
	if err != nil {
		// Any read error after a successful write means the remote did not reply.
		// This includes timeout (no reply) and connection refused (ICMP port unreachable).
		// Both are legitimate "tunnel/remote unreachable" signals, not local infrastructure failures.
		return false, nil
	}
	return string(buf[:n]) == string(msg), nil
}
