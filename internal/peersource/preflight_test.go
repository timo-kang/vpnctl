package peersource

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type checkRunner struct {
	ip, wg       string
	ipErr, wgErr error
}

func (r checkRunner) RunContext(context.Context, string, ...string) error { return nil }
func (r checkRunner) OutputContext(_ context.Context, name string, _ ...string) (string, error) {
	if name == "ip" {
		return r.ip, r.ipErr
	}
	return r.wg, r.wgErr
}
func TestMonitorPreflight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner checkRunner
		want   string
	}{
		{"missing_interface", checkRunner{ipErr: errors.New("device missing")}, "interface wg0 exists"},
		{"missing_ipv4", checkRunner{ip: "link/ether"}, "no IPv4"},
		{"unsupported_or_denied", checkRunner{ip: "inet 10.0.0.1/24", wgErr: errors.New("not a WireGuard interface")}, "Tailscale and Nebula"},
		{"permission", checkRunner{ip: "inet 10.0.0.1/24", wgErr: errors.New("Operation not permitted")}, "CAP_NET_ADMIN"},
		{"empty_valid", checkRunner{ip: "inet 10.0.0.1/24", wg: "private\tpublic\t51820\toff"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewWgSource("wg0", 51900)
			s.runner = tc.runner
			_, err := s.CheckContext(context.Background())
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
	s := NewWgSource("--help", 51900)
	if _, err := s.CheckContext(context.Background()); err == nil {
		t.Fatal("invalid interface accepted")
	}
}
