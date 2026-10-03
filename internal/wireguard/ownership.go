// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package wireguard

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
)

// LockInterface serializes vpnctl writers in this network namespace. It is
// advisory: kernel readback is still required to detect external managers.
// Abstract sockets disappear on process exit, including SIGKILL.
func LockInterface(iface string) (func(), error) {
	if iface == "" || len(iface) > 15 || strings.ContainsAny(iface, " /\\\t\r\n") {
		return nil, fmt.Errorf("invalid WireGuard interface")
	}
	sum := sha256.Sum256([]byte(iface))
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: fmt.Sprintf("@vpnctl.wg-owner.%x", sum[:16]), Net: "unixgram"})
	if err != nil {
		return nil, fmt.Errorf("WireGuard interface is owned by another vpnctl writer: %w", err)
	}
	return func() { conn.Close() }, nil
}
