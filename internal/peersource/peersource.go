// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package peersource provides abstractions for discovering WireGuard peers
// from various backends (live interface, config file, etc.).
package peersource

import "time"

// Peer holds the observable attributes of a single WireGuard peer.
type Peer struct {
	// PublicKey is the peer's WireGuard public key (base64-encoded).
	PublicKey string
	// VPNIP is the peer's VPN address (host part, no prefix length).
	VPNIP string
	// Endpoint is the peer's current UDP endpoint as seen by WireGuard (host:port).
	Endpoint string
	// Name is a short human-readable label (first 8 chars of PublicKey by default).
	Name string
	// ProbePort is the TCP port used for latency/health probing.
	ProbePort int
	// LastHandshake is the time of the most recent WireGuard handshake.
	LastHandshake time.Time
}

// PeerSource is the interface implemented by all peer discovery backends.
type PeerSource interface {
	// Discover returns the current set of known peers.
	Discover() ([]Peer, error)
	// SelfIP returns this node's VPN IP address.
	SelfIP() string
	// InterfaceName returns the WireGuard interface name.
	InterfaceName() string
}
