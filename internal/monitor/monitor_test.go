// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/peersource"
)

// fakePeerSource is a test double for peersource.PeerSource.
type fakePeerSource struct {
	peers []peersource.Peer
}

func (f *fakePeerSource) Discover() ([]peersource.Peer, error) { return f.peers, nil }
func (f *fakePeerSource) SelfIP() string                       { return "10.7.0.1" }
func (f *fakePeerSource) InterfaceName() string                { return "wg-test" }

func TestMonitor_RunCollectsProbes(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "monitor_test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	// Use 127.0.0.1 so UDP probes fail fast (ICMP port-unreachable) without
	// blocking for the full 2-second probe timeout. A non-local VPN address
	// like 10.7.0.2 would time out since there is no WireGuard interface.
	src := &fakePeerSource{
		peers: []peersource.Peer{
			{
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				VPNIP:     "127.0.0.1",
				ProbePort: 51900,
				Name:      "peer-1",
			},
		},
	}

	m := New(Config{
		Source:   src,
		Store:    store,
		Interval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	m.Run(ctx)

	results, err := store.QueryAll(5 * time.Minute)
	if err != nil {
		t.Fatalf("QueryAll: %v", err)
	}

	if len(results) < 2 {
		t.Fatalf("expected at least 2 probe results, got %d", len(results))
	}

	peerKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, r := range results {
		if r.PeerKey != peerKey {
			t.Errorf("PeerKey: want %q, got %q", peerKey, r.PeerKey)
		}
		if r.Success {
			t.Errorf("expected Success=false (no UDP responder), got true")
		}
	}
}

func TestMonitor_DefaultInterval(t *testing.T) {
	src := &fakePeerSource{}
	m := New(Config{
		Source:   src,
		Interval: 0,
	})
	if m.cfg.Interval != 5*time.Second {
		t.Errorf("expected default interval 5s, got %v", m.cfg.Interval)
	}
}

func TestMonitor_Subscribe(t *testing.T) {
	src := &fakePeerSource{
		peers: []peersource.Peer{
			{
				PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				VPNIP:     "127.0.0.1",
				ProbePort: 51901,
				Name:      "peer-2",
			},
		},
	}

	m := New(Config{
		Source:   src,
		Interval: 50 * time.Millisecond,
	})

	ch := m.Subscribe()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go m.Run(ctx)

	select {
	case snap := <-ch:
		if len(snap.Peers) != 1 {
			t.Errorf("expected 1 peer in snapshot, got %d", len(snap.Peers))
		}
		if snap.Time.IsZero() {
			t.Errorf("snapshot time should not be zero")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for snapshot on subscriber channel")
	}
}

func TestFilterPeers(t *testing.T) {
	peers := []peersource.Peer{
		{VPNIP: "10.0.0.1"},
		{VPNIP: "10.0.0.2"},
		{VPNIP: "10.0.0.3"},
	}

	// empty filter returns all
	got := filterPeers(peers, nil)
	if len(got) != 3 {
		t.Errorf("empty filter: expected 3, got %d", len(got))
	}

	// filter to specific IPs
	got = filterPeers(peers, []string{"10.0.0.1", "10.0.0.3"})
	if len(got) != 2 {
		t.Errorf("filtered: expected 2, got %d", len(got))
	}
	if got[0].VPNIP != "10.0.0.1" || got[1].VPNIP != "10.0.0.3" {
		t.Errorf("filtered peers don't match expected IPs")
	}
}
