// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package peersource

import (
	"context"
	"strings"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
)

// ConfigSource implements PeerSource by querying the controller API using the
// settings found in a config file (i.e. when vpnctl is invoked with --config).
type ConfigSource struct {
	cfg    *config.Config
	client *api.Client // nil when no controller URL is configured
}

// NewConfigSource creates a ConfigSource from cfg.
// If cfg.Node.Controller is set, an api.Client is created for that URL.
func NewConfigSource(cfg *config.Config) *ConfigSource {
	cs := &ConfigSource{cfg: cfg}
	if cfg.Node != nil && cfg.Node.Controller != "" {
		cs.client = api.NewClient(cfg.Node.Controller)
	}
	return cs
}

// InterfaceName returns the WireGuard interface name.
// It checks cfg.Node.WGInterface first, then cfg.Controller.WGInterface,
// and falls back to "wg0" when neither is set.
func (cs *ConfigSource) InterfaceName() string {
	if cs.cfg.Node != nil && cs.cfg.Node.WGInterface != "" {
		return cs.cfg.Node.WGInterface
	}
	if cs.cfg.Controller != nil && cs.cfg.Controller.WGInterface != "" {
		return cs.cfg.Controller.WGInterface
	}
	return config.DefaultWGInterface
}

// SelfIP returns the node's VPN IP address from cfg.Node.VPNIP.
func (cs *ConfigSource) SelfIP() string {
	if cs.cfg.Node != nil {
		return cs.cfg.Node.VPNIP
	}
	return ""
}

// Discover fetches peer candidates from the controller and maps them to Peers.
// If no client was created (controller URL not configured), it returns nil, nil.
func (cs *ConfigSource) Discover() ([]Peer, error) {
	if cs.client == nil {
		return nil, nil
	}

	nodeName := ""
	if cs.cfg.Node != nil {
		nodeName = cs.cfg.Node.Name
	}

	resp, err := cs.client.Candidates(context.Background(), nodeName)
	if err != nil {
		return nil, err
	}

	peers := make([]Peer, 0, len(resp.Peers))
	for _, c := range resp.Peers {
		vpnIP := c.VPNIP
		// Strip /mask suffix if present (e.g. "10.7.0.2/24" → "10.7.0.2").
		if idx := strings.Index(vpnIP, "/"); idx >= 0 {
			vpnIP = vpnIP[:idx]
		}
		peers = append(peers, Peer{
			PublicKey: c.PubKey,
			VPNIP:     vpnIP,
			Endpoint:  c.Endpoint,
			Name:      c.Name,
			ProbePort: c.ProbePort,
		})
	}
	return peers, nil
}
