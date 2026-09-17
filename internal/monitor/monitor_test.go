// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"net"
	"path/filepath"
	"sync"
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

	// A controlled negative responder avoids assumptions about an unused
	// fixed port or ICMP delivery on a busy runner.
	port := negativeProbeResponder(t)
	src := &fakePeerSource{
		peers: []peersource.Peer{
			{
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				VPNIP:     "127.0.0.1",
				ProbePort: port,
				Name:      "peer-1",
			},
		},
	}

	m := New(Config{
		Source:   src,
		Store:    store,
		Interval: 100 * time.Millisecond,
	})

	runUntilSnapshots(t, m, 2)

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
			t.Errorf("expected Success=false (invalid echo response), got true")
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
	port := negativeProbeResponder(t)
	src := &fakePeerSource{
		peers: []peersource.Peer{
			{
				PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				VPNIP:     "127.0.0.1",
				ProbePort: port,
				Name:      "peer-2",
			},
		},
	}

	m := New(Config{
		Source:   src,
		Interval: 50 * time.Millisecond,
	})

	snap := runUntilSnapshots(t, m, 1)
	if len(snap.Peers) != 1 {
		t.Errorf("expected 1 peer in snapshot, got %d", len(snap.Peers))
	}
	if snap.Time.IsZero() {
		t.Error("snapshot time should not be zero")
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

func TestSnapshotPublicationIsConcurrentAndIsolated(t *testing.T) {
	m := New(Config{})
	a, b := m.Subscribe(), m.Subscribe()
	snap := Snapshot{Time: time.Now(), Peers: []PeerState{{Peer: peersource.Peer{Name: "original"}}}}
	m.publish(snap)
	snap.Peers[0].Peer.Name = "producer-mutated"
	gotA, gotB := <-a, <-b
	gotA.Peers[0].Peer.Name = "consumer-mutated"
	if gotB.Peers[0].Peer.Name != "original" || m.Latest().Peers[0].Peer.Name != "original" {
		t.Fatal("snapshot aliases another owner")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				snapshot := m.Latest()
				if len(snapshot.Peers) > 0 {
					snapshot.Peers[0].Peer.Name = "reader"
				}
				if n%20 == 0 {
					m.Subscribe()
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		m.publish(Snapshot{Time: time.Now(), Peers: []PeerState{{Peer: peersource.Peer{Name: "published"}}}})
	}
	wg.Wait()
	if m.Latest().Peers[0].Peer.Name != "published" {
		t.Fatal("reader mutated published state")
	}
}

// Wait for the behavior being tested, not a count inferred from elapsed ticker
// intervals. The deadline is a hang guard; production probe budgets are intact.
func runUntilSnapshots(t *testing.T, m *Monitor, count int) Snapshot {
	t.Helper()
	ch := m.Subscribe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	defer func() { cancel(); <-done }()
	var last Snapshot
	for i := 0; i < count; i++ {
		select {
		case last = <-ch:
		case <-ctx.Done():
			t.Fatalf("monitor published only %d/%d snapshots: %v", i, count, ctx.Err())
		}
	}
	return last
}

func negativeProbeResponder(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP([]byte("invalid-echo"), addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().(*net.UDPAddr).Port
}
