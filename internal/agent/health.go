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
// dial and interrupts in-flight I/O; the timeout bounds the complete check.
//
// On read timeout (no reply), returns (false, nil) — the legitimate "tunnel dead" signal.
// On infrastructure errors (dial, write, set-deadline), returns (false, err) so
// the caller can distinguish local failures from tunnel failures.
func checkTunnelHealth(ctx context.Context, hubAddr string, timeout time.Duration) (healthy bool, err error) {
	parent := ctx
	defer func() {
		parentErr := parent.Err()
		if deadline, ok := parent.Deadline(); parentErr == nil && ok && !time.Now().Before(deadline) {
			parentErr = context.DeadlineExceeded
		}
		if parentErr != nil {
			healthy, err = false, parentErr
		}
	}()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", hubAddr)
	if err != nil {
		return false, fmt.Errorf("dial %s: %w", hubAddr, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	msg := []byte(fmt.Sprintf("vpnctl-echo:health-%d", time.Now().UnixNano()))
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
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
