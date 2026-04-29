// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package peersource

import (
	"testing"

	"vpnctl/internal/config"
)

// TestConfigSource_BasicFields verifies that InterfaceName() and SelfIP()
// return the values from the config without requiring a live controller.
func TestConfigSource_BasicFields(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Node: &config.NodeConfig{
			WGInterface: "wg1",
			VPNIP:       "10.7.0.5",
			Name:        "node-a",
		},
	}

	cs := NewConfigSource(cfg)

	if got := cs.InterfaceName(); got != "wg1" {
		t.Errorf("InterfaceName() = %q, want %q", got, "wg1")
	}

	if got := cs.SelfIP(); got != "10.7.0.5" {
		t.Errorf("SelfIP() = %q, want %q", got, "10.7.0.5")
	}
}

// TestConfigSource_DefaultInterface verifies that InterfaceName() falls back to
// DefaultWGInterface ("wg0") when neither Node nor Controller specifies one.
func TestConfigSource_DefaultInterface(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Node: &config.NodeConfig{
			VPNIP: "10.7.0.6",
		},
	}

	cs := NewConfigSource(cfg)

	if got := cs.InterfaceName(); got != config.DefaultWGInterface {
		t.Errorf("InterfaceName() = %q, want %q", got, config.DefaultWGInterface)
	}
}

// TestConfigSource_ControllerInterface verifies that InterfaceName() falls back
// to cfg.Controller.WGInterface when cfg.Node.WGInterface is empty.
func TestConfigSource_ControllerInterface(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Node: &config.NodeConfig{
			VPNIP: "10.7.0.7",
			// WGInterface intentionally left empty
		},
		Controller: &config.ControllerConfig{
			WGInterface: "wg2",
		},
	}

	cs := NewConfigSource(cfg)

	if got := cs.InterfaceName(); got != "wg2" {
		t.Errorf("InterfaceName() = %q, want %q", got, "wg2")
	}
}

// TestConfigSource_NoControllerDiscoverReturnsNil verifies that Discover()
// returns nil, nil when no controller URL is configured.
func TestConfigSource_NoControllerDiscoverReturnsNil(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Node: &config.NodeConfig{
			WGInterface: "wg0",
			VPNIP:       "10.7.0.8",
		},
	}

	cs := NewConfigSource(cfg)

	peers, err := cs.Discover()
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	if peers != nil {
		t.Errorf("Discover() = %v, want nil", peers)
	}
}
