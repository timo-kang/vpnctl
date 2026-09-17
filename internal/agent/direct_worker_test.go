// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/wireguard"
)

func TestCancelledDirectResultCannotOverwriteNewDesiredState(t *testing.T) {
	remote, err := direct.StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	addr, err := net.ResolveUDPAddr("udp", remote.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	shared, err := direct.ListenShared("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(204)
	}))
	defer ctrl.Close()
	defer close(release)
	client := api.NewClient(ctrl.URL)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan directSnapshot, 1)
	applied := make(chan []wireguard.Peer, 10)
	var running, maxRunning atomic.Int32
	apply := func(peers []wireguard.Peer) error {
		n := running.Add(1)
		if n > maxRunning.Load() {
			maxRunning.Store(n)
		}
		defer running.Add(-1)
		applied <- peers
		return nil
	}
	done := make(chan struct{})
	cfg := config.NodeConfig{DirectIntervalSec: 1, ServerPublicKey: "hub", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}}
	go func() { defer close(done); runDirect(ctx, client, cfg, "node", shared, updates, apply) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("worker failed to drain")
		}
	}()
	peer := api.PeerCandidate{ID: "peer", PubKey: "peer-key", VPNIP: "10.7.0.3/32", Endpoint: "127.0.0.1:51821", PublicAddr: remote.LocalAddr(), ProbePort: addr.Port, P2PReady: true}
	updates <- directSnapshot{peers: []api.PeerCandidate{peer}}
	select {
	case peers := <-applied:
		if len(peers) != 1 {
			t.Fatal(peers)
		}
	case <-time.After(time.Second):
		t.Fatal("initial apply missing")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("report never started")
	}
	peer.P2PReady = false
	updates <- directSnapshot{peers: []api.PeerCandidate{peer}}
	select {
	case peers := <-applied:
		if len(peers) != 0 {
			t.Fatal("old result restored direct", peers)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled report blocked new desired state")
	}
	cancel()
	<-done
	if maxRunning.Load() != 1 {
		t.Fatal("concurrent kernel apply")
	}
	select {
	case peers := <-applied:
		t.Fatal("late apply", peers)
	default:
	}
}
