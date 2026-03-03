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

// checkTunnelHealth sends a single UDP echo to hubAddr and waits for
// the response. Returns true if the echo was received within timeout.
// The context is used to cancel the dial; the read/write deadline handles I/O.
func checkTunnelHealth(ctx context.Context, hubAddr string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", hubAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := []byte(fmt.Sprintf("vpnctl-echo:health-%d", time.Now().UnixNano()))
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	if _, err := conn.Write(msg); err != nil {
		return false
	}

	buf := make([]byte, len(msg)+64)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	return string(buf[:n]) == string(msg)
}
