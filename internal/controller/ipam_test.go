// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/store"
)

func TestIPAMReservesControllerAndConfiguredRanges(t *testing.T) {
	t.Parallel()

	allocator, err := newIPAM(
		"10.7.0.0/24",
		"10.7.0.1/24",
		[]string{"10.7.0.2/31", "10.7.0.10"},
	)
	if err != nil {
		t.Fatalf("newIPAM: %v", err)
	}
	lease, err := allocator.lease("node-a", "", &store.Registry{})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if lease != "10.7.0.4/32" {
		t.Fatalf("lease=%q, want 10.7.0.4/32", lease)
	}
}

func TestIPAMSmallPoolExhaustionAndReuse(t *testing.T) {
	t.Parallel()

	allocator, err := newIPAM("10.7.0.0/30", "10.7.0.1/30", nil)
	if err != nil {
		t.Fatalf("newIPAM: %v", err)
	}
	lease, err := allocator.lease("node-a", "", &store.Registry{})
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	if lease != "10.7.0.2/32" {
		t.Fatalf("lease=%q", lease)
	}
	reg := &store.Registry{Nodes: []store.NodeInfo{{
		ID: "node-a", Name: "node-a", VPNIP: lease,
	}}}
	if _, err := allocator.lease("node-b", "", reg); err == nil || !strings.Contains(err.Error(), "no available") {
		t.Fatalf("exhaustion error=%v", err)
	}

	reg.Nodes = nil
	reused, err := allocator.lease("node-b", "", reg)
	if err != nil {
		t.Fatalf("reuse lease: %v", err)
	}
	if reused != lease {
		t.Fatalf("reused=%q, want %q", reused, lease)
	}
}

func TestIPAM24PoolExhaustion(t *testing.T) {
	t.Parallel()

	allocator, err := newIPAM("10.7.0.0/24", "10.7.0.1/24", nil)
	if err != nil {
		t.Fatalf("newIPAM: %v", err)
	}
	reg := &store.Registry{Nodes: make([]store.NodeInfo, 0, 253)}
	for host := 2; host <= 254; host++ {
		reg.Nodes = append(reg.Nodes, store.NodeInfo{
			ID:    fmt.Sprintf("node-%03d", host),
			Name:  fmt.Sprintf("node-%03d", host),
			VPNIP: fmt.Sprintf("10.7.0.%d/32", host),
		})
	}
	if _, err := allocator.lease("overflow", "", reg); err == nil || !strings.Contains(err.Error(), "no available") {
		t.Fatalf("exhaustion error=%v", err)
	}
}

func TestIPAMStableLeaseOwnership(t *testing.T) {
	t.Parallel()

	allocator, err := newIPAM("10.7.0.0/24", "10.7.0.1/24", nil)
	if err != nil {
		t.Fatalf("newIPAM: %v", err)
	}
	reg := &store.Registry{Nodes: []store.NodeInfo{{
		ID: "node-a", Name: "display-a", VPNIP: "10.7.0.22/32",
	}}}

	for _, requested := range []string{"", "10.7.0.22", "10.7.0.22/32"} {
		lease, err := allocator.lease("node-a", requested, reg)
		if err != nil {
			t.Fatalf("requested %q: %v", requested, err)
		}
		if lease != "10.7.0.22/32" {
			t.Fatalf("requested %q lease=%q", requested, lease)
		}
	}
	if _, err := allocator.lease("node-a", "10.7.0.23/32", reg); err == nil || !strings.Contains(err.Error(), "already owns") {
		t.Fatalf("lease change error=%v", err)
	}
}

func TestIPAMRequestedAddressValidation(t *testing.T) {
	t.Parallel()

	allocator, err := newIPAM(
		"10.7.0.0/24",
		"10.7.0.1/24",
		[]string{"10.7.0.10", "10.7.0.16/28"},
	)
	if err != nil {
		t.Fatalf("newIPAM: %v", err)
	}
	reg := &store.Registry{Nodes: []store.NodeInfo{{
		ID: "node-b", Name: "node-b", VPNIP: "10.7.0.2/32",
	}}}
	tests := []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "controller", value: "10.7.0.1/32", wantError: "controller wg_address"},
		{name: "single reservation", value: "10.7.0.10", wantError: "reserved_vpn_ips"},
		{name: "range reservation", value: "10.7.0.20/32", wantError: "reserved_vpn_ips"},
		{name: "duplicate", value: "10.7.0.2/32", wantError: "already leased"},
		{name: "network", value: "10.7.0.0/32", wantError: "network or broadcast"},
		{name: "broadcast", value: "10.7.0.255/32", wantError: "network or broadcast"},
		{name: "outside", value: "10.8.0.2/32", wantError: "outside"},
		{name: "non host prefix", value: "10.7.0.3/24", wantError: "/32"},
		{name: "malformed", value: "not-an-ip", wantError: "valid IPv4"},
		{name: "IPv6", value: "2001:db8::1", wantError: "IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := allocator.lease("node-a", tt.value, reg)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error=%v, want substring %q", err, tt.wantError)
			}
		})
	}

	lease, err := allocator.lease("node-a", "10.7.0.3", reg)
	if err != nil {
		t.Fatalf("valid requested lease: %v", err)
	}
	if lease != "10.7.0.3/32" {
		t.Fatalf("lease=%q", lease)
	}
}

func TestIPAMRegistryValidationAndMigration(t *testing.T) {
	t.Parallel()

	allocator, err := newIPAM("10.7.0.0/24", "10.7.0.1/24", []string{"10.7.0.10"})
	if err != nil {
		t.Fatalf("newIPAM: %v", err)
	}

	reg := &store.Registry{Nodes: []store.NodeInfo{{
		ID: "node-a", Name: "node-a", VPNIP: "10.7.0.2",
	}}}
	changed, err := allocator.validateAndNormalizeRegistry(reg)
	if err != nil {
		t.Fatalf("validateAndNormalizeRegistry: %v", err)
	}
	if !changed || reg.Nodes[0].VPNIP != "10.7.0.2/32" {
		t.Fatalf("changed=%v node=%+v", changed, reg.Nodes[0])
	}

	tests := []struct {
		name string
		reg  *store.Registry
		want string
	}{
		{
			name: "duplicate",
			reg: &store.Registry{Nodes: []store.NodeInfo{
				{ID: "node-a", VPNIP: "10.7.0.2/32"},
				{ID: "node-b", VPNIP: "10.7.0.2"},
			}},
			want: "assigned to both",
		},
		{
			name: "controller conflict",
			reg:  &store.Registry{Nodes: []store.NodeInfo{{ID: "node-a", VPNIP: "10.7.0.1/32"}}},
			want: "controller wg_address",
		},
		{
			name: "configured reservation conflict",
			reg:  &store.Registry{Nodes: []store.NodeInfo{{ID: "node-a", VPNIP: "10.7.0.10/32"}}},
			want: "reserved_vpn_ips",
		},
		{
			name: "outside",
			reg:  &store.Registry{Nodes: []store.NodeInfo{{ID: "node-a", VPNIP: "10.8.0.2/32"}}},
			want: "outside",
		},
		{
			name: "malformed",
			reg:  &store.Registry{Nodes: []store.NodeInfo{{ID: "node-a", VPNIP: "bad"}}},
			want: "invalid vpn_ip",
		},
		{
			name: "duplicate node ID",
			reg: &store.Registry{Nodes: []store.NodeInfo{
				{ID: "node-a", VPNIP: "10.7.0.2/32"},
				{ID: "node-a", VPNIP: "10.7.0.3/32"},
			}},
			want: "appears more than once",
		},
		{
			name: "lease without node ID",
			reg:  &store.Registry{Nodes: []store.NodeInfo{{VPNIP: "10.7.0.2/32"}}},
			want: "no node ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := allocator.validateAndNormalizeRegistry(tt.reg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestNewServerValidatesAndMigratesRegistryIPAM(t *testing.T) {
	t.Parallel()

	t.Run("migrates host address", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "registry.yaml")
		if err := store.SaveRegistry(path, &store.Registry{Nodes: []store.NodeInfo{{
			ID: "node-a", Name: "node-a", VPNIP: "10.7.0.2",
		}}}); err != nil {
			t.Fatalf("SaveRegistry: %v", err)
		}
		if _, err := NewServer(config.ControllerConfig{
			DataDir: tmp, VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24",
		}); err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		persisted, err := store.LoadRegistry(path)
		if err != nil {
			t.Fatalf("LoadRegistry: %v", err)
		}
		if persisted.Nodes[0].VPNIP != "10.7.0.2/32" {
			t.Fatalf("vpn_ip=%q", persisted.Nodes[0].VPNIP)
		}
	})

	t.Run("rejects duplicate", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "registry.yaml")
		if err := store.SaveRegistry(path, &store.Registry{Nodes: []store.NodeInfo{
			{ID: "node-a", Name: "node-a", VPNIP: "10.7.0.2/32"},
			{ID: "node-b", Name: "node-b", VPNIP: "10.7.0.2/32"},
		}}); err != nil {
			t.Fatalf("SaveRegistry: %v", err)
		}
		_, err := NewServer(config.ControllerConfig{
			DataDir: tmp, VPNCIDR: "10.7.0.0/24", WGAddress: "10.7.0.1/24",
		})
		if err == nil || !strings.Contains(err.Error(), "assigned to both") {
			t.Fatalf("NewServer error=%v", err)
		}
	})
}

func TestHandleRegisterRejectsInvalidRequestedVPNIP(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "controller", value: "10.7.0.1/32"},
		{name: "reserved", value: "10.7.0.10/32"},
		{name: "duplicate", value: "10.7.0.2/32"},
		{name: "outside", value: "10.8.0.2/32"},
		{name: "network", value: "10.7.0.0/32"},
		{name: "broadcast", value: "10.7.0.255/32"},
		{name: "malformed", value: "bad"},
		{name: "non host prefix", value: "10.7.0.3/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewServer(config.ControllerConfig{
				DataDir:        t.TempDir(),
				VPNCIDR:        "10.7.0.0/24",
				WGAddress:      "10.7.0.1/24",
				ReservedVPNIPs: []string{"10.7.0.10"},
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			s.reg.Nodes = []store.NodeInfo{{
				ID: "node-b", Name: "node-b", VPNIP: "10.7.0.2/32",
			}}
			body, err := json.Marshal(api.RegisterRequest{
				Name: "node-a", PubKey: "pub-a", VPNIP: tt.value,
			})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			rec := httptest.NewRecorder()
			s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if len(s.reg.Nodes) != 1 {
				t.Fatalf("invalid request mutated registry: %+v", s.reg.Nodes)
			}
		})
	}
}

func TestIPAMRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cidr          string
		controller    string
		reservations  []string
		wantSubstring string
	}{
		{
			name:          "address settings without CIDR",
			controller:    "10.7.0.1/24",
			wantSubstring: "vpn_cidr is required",
		},
		{
			name:          "non-network VPN CIDR",
			cidr:          "10.7.0.1/24",
			wantSubstring: "network prefix",
		},
		{
			name:          "controller outside",
			cidr:          "10.7.0.0/24",
			controller:    "10.8.0.1/24",
			wantSubstring: "outside",
		},
		{
			name:          "controller network address",
			cidr:          "10.7.0.0/24",
			controller:    "10.7.0.0/24",
			wantSubstring: "usable host",
		},
		{
			name:          "reservation outside",
			cidr:          "10.7.0.0/24",
			reservations:  []string{"10.8.0.0/24"},
			wantSubstring: "outside",
		},
		{
			name:          "reservation has host bits",
			cidr:          "10.7.0.0/24",
			reservations:  []string{"10.7.0.17/28"},
			wantSubstring: "network prefix",
		},
		{
			name:          "IPv6 reservation",
			cidr:          "10.7.0.0/24",
			reservations:  []string{"2001:db8::1"},
			wantSubstring: "IPv4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newIPAM(tt.cidr, tt.controller, tt.reservations)
			if err == nil || !strings.Contains(err.Error(), tt.wantSubstring) {
				t.Fatalf("error=%v, want substring %q", err, tt.wantSubstring)
			}
		})
	}
}

func TestRegisterLeaseStableAcrossRestart(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := config.ControllerConfig{
		DataDir:   tmp,
		VPNCIDR:   "10.7.0.0/24",
		WGAddress: "10.7.0.1/24",
	}
	first, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("first NewServer: %v", err)
	}
	firstResult, err := first.registerNode(nodeRegistration{
		Name: "node-a", PubKey: "pub-a",
	}, false)
	if err != nil {
		t.Fatalf("first registerNode: %v", err)
	}

	restarted, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("restarted NewServer: %v", err)
	}
	secondResult, err := restarted.registerNode(nodeRegistration{
		Name: "node-a", PubKey: "pub-a",
	}, false)
	if err != nil {
		t.Fatalf("second registerNode: %v", err)
	}
	if firstResult.VPNIP != "10.7.0.2/32" || secondResult.VPNIP != firstResult.VPNIP {
		t.Fatalf("first lease=%q second lease=%q", firstResult.VPNIP, secondResult.VPNIP)
	}
}

func TestConcurrentAutomaticRegistrationsReceiveUniqueLeases(t *testing.T) {
	t.Parallel()

	s, err := NewServer(config.ControllerConfig{
		DataDir:   t.TempDir(),
		VPNCIDR:   "10.7.0.0/24",
		WGAddress: "10.7.0.1/24",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	const nodeCount = 32
	results := make(chan nodeRegistrationResult, nodeCount)
	errorsCh := make(chan error, nodeCount)
	var group sync.WaitGroup
	for index := 0; index < nodeCount; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			result, err := s.registerNode(nodeRegistration{
				Name:   fmt.Sprintf("node-%02d", index),
				PubKey: fmt.Sprintf("pub-%02d", index),
			}, false)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- result
		}(index)
	}
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("registerNode: %v", err)
	}

	leases := make(map[string]struct{}, nodeCount)
	for result := range results {
		if _, duplicate := leases[result.VPNIP]; duplicate {
			t.Errorf("duplicate concurrent lease %q", result.VPNIP)
		}
		leases[result.VPNIP] = struct{}{}
	}
	if len(leases) != nodeCount {
		t.Fatalf("unique leases=%d, want %d", len(leases), nodeCount)
	}
}
