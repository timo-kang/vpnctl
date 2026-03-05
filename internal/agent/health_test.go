package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/direct"
)

func TestCheckTunnelHealth_Success(t *testing.T) {
	t.Parallel()
	resp, err := direct.StartResponder(":0")
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}
	defer resp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, hErr := checkTunnelHealth(ctx, resp.LocalAddr(), 2*time.Second)
	if hErr != nil {
		t.Fatalf("unexpected error: %v", hErr)
	}
	if !ok {
		t.Fatal("expected health check to succeed")
	}
}

func TestCheckTunnelHealth_NoResponder(t *testing.T) {
	t.Parallel()
	// Probe a port with no responder — returns (false, nil) whether via
	// read timeout or ICMP connection refused (both are tunnel-level failures).
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ok, hErr := checkTunnelHealth(ctx, "127.0.0.1:19999", 500*time.Millisecond)
	if hErr != nil {
		t.Fatalf("no-responder should return (false, nil), got error: %v", hErr)
	}
	if ok {
		t.Fatal("expected health check to fail")
	}
}

func TestCheckTunnelHealth_ContextCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	ok, hErr := checkTunnelHealth(ctx, "127.0.0.1:19999", 10*time.Second)
	elapsed := time.Since(start)

	if ok {
		t.Fatal("expected health check to fail with cancelled context")
	}
	if hErr == nil {
		t.Fatal("expected an error for cancelled context, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancelled context should return quickly, took %s", elapsed)
	}
}

func TestCheckTunnelHealth_MismatchedResponse(t *testing.T) {
	t.Parallel()
	// Start a UDP listener that always replies with wrong data.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			conn.WriteTo([]byte("wrong-response"), addr)
		}
	}()

	ctx := context.Background()
	ok, hErr := checkTunnelHealth(ctx, conn.LocalAddr().String(), 2*time.Second)
	if hErr != nil {
		t.Fatalf("unexpected error: %v", hErr)
	}
	if ok {
		t.Fatal("expected health check to fail with mismatched echo")
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
		{
			name: "custom server probe port",
			cfg: config.NodeConfig{
				HealthCheckIntervalSec: 3,
				HealthCheckFailures:    3,
				ServerAllowedIPs:       []string{"10.7.0.0/24"},
				ServerProbePort:        9999,
			},
			expect: "10.7.0.1:9999",
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
