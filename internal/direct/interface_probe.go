// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ProbeInterface checks a VPN address through the specified interface/source.
// It cannot quietly use a different route or a DNS-resolved underlay address.
func ProbeInterface(parent context.Context, iface, source, target string, timeout time.Duration) (time.Duration, error) {
	local, err := netip.ParseAddr(source)
	if err != nil || !local.Is4() {
		return 0, errors.New("invalid overlay source")
	}
	remote, err := netip.ParseAddrPort(target)
	if err != nil || !remote.Addr().Is4() || remote.Port() == 0 || iface == "" {
		return 0, errors.New("invalid overlay target/interface")
	}
	ctx, cancel := probeContext(parent, timeout)
	defer cancel()
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IP(local.AsSlice())}, Control: func(_, _ string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return bindErr
	}}
	conn, err := d.DialContext(ctx, "udp4", remote.String())
	if err != nil {
		return 0, contextError(ctx, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	return probeConnected(ctx, conn)
}
