package agent

import (
	"context"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/direct"
)

func TestCheckTunnelHealth_Success(t *testing.T) {
	t.Parallel()
	// Start a real UDP responder, send health check to it, verify success
	resp, err := direct.StartResponder(":0")
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}
	defer resp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok := checkTunnelHealth(ctx, resp.LocalAddr(), 2*time.Second)
	if !ok {
		t.Fatal("expected health check to succeed")
	}
}

func TestCheckTunnelHealth_Timeout(t *testing.T) {
	t.Parallel()
	// Probe a port with no responder -- should timeout and return false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ok := checkTunnelHealth(ctx, "127.0.0.1:19999", 500*time.Millisecond)
	if ok {
		t.Fatal("expected health check to fail")
	}
}

func TestHubProbeAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    config.NodeConfig
		expect string
	}{
		{
			name: "standard /24 subnet",
			cfg: config.NodeConfig{
				HealthCheckIntervalSec: 3,
				HealthCheckFailures:    3,
				ServerAllowedIPs:       []string{"10.7.0.0/24"},
			},
			expect: "10.7.0.1:51900",
		},
		{
			name: "disabled (interval=0)",
			cfg: config.NodeConfig{
				HealthCheckIntervalSec: 0,
				HealthCheckFailures:    3,
				ServerAllowedIPs:       []string{"10.7.0.0/24"},
			},
			expect: "",
		},
		{
			name: "skips 0.0.0.0/0",
			cfg: config.NodeConfig{
				HealthCheckIntervalSec: 3,
				HealthCheckFailures:    3,
				ServerAllowedIPs:       []string{"0.0.0.0/0", "10.7.0.0/24"},
			},
			expect: "10.7.0.1:51900",
		},
		{
			name: "no allowed IPs",
			cfg: config.NodeConfig{
				HealthCheckIntervalSec: 3,
				HealthCheckFailures:    3,
				ServerAllowedIPs:       nil,
			},
			expect: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hubProbeAddress(tc.cfg)
			if got != tc.expect {
				t.Fatalf("hubProbeAddress()=%q, want %q", got, tc.expect)
			}
		})
	}
}
