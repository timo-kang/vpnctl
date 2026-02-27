package agent

import (
	"context"
	"testing"
	"time"

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
