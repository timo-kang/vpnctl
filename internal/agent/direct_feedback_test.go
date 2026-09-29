// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/wireguard"
)

// Success feedback from one submitted result must not cancel the same round's
// remaining results when no peer identity or probe destination changed.
func TestDirectReadinessPromotionDoesNotCancelProbeFeedback(t *testing.T) {
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
	entered := make(chan struct{})
	accepted := make(chan struct{})
	result := make(chan error, 1)
	release := make(chan struct{})
	var once sync.Once
	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report api.DirectResultRequest
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		io.Copy(io.Discard, r.Body)
		if report.PeerID == "peer-a" {
			w.WriteHeader(http.StatusNoContent)
			close(accepted)
			return
		}
		close(entered)
		select {
		case <-r.Context().Done():
			result <- r.Context().Err()
		case <-release:
			w.WriteHeader(http.StatusNoContent)
			result <- nil
		}
	}))
	defer ctrl.Close()
	defer once.Do(func() { close(release) })
	client := api.NewClient(ctrl.URL)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan directSnapshot, 1)
	applied := make(chan int, 2)
	done := make(chan struct{})
	cfg := config.NodeConfig{DirectIntervalSec: 1, ServerPublicKey: "hub", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}}
	go func() {
		defer close(done)
		runDirect(ctx, client, cfg, "node", shared, updates, func(p []wireguard.Peer) error { applied <- len(p); return nil })
	}()
	defer func() { cancel(); <-done }()
	peer := api.PeerCandidate{ID: "peer-a", PubKey: "peer-a-key", VPNIP: "10.7.0.3/32", Endpoint: "127.0.0.1:51821", PublicAddr: remote.LocalAddr(), ProbePort: addr.Port}
	other := peer
	other.ID, other.PubKey, other.VPNIP = "peer-b", "peer-b-key", "10.7.0.4/32"
	updates <- directSnapshot{peers: []api.PeerCandidate{peer, other}}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("probe feedback never started")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("first peer was not accepted")
	}
	peer.P2PReady = true
	updates <- directSnapshot{peers: []api.PeerCandidate{peer, other}}
	select {
	case n := <-applied:
		if n != 1 {
			t.Fatal("promotion did not apply peer", n)
		}
	case <-time.After(time.Second):
		t.Fatal("feedback blocked peer application")
	}
	select {
	case err := <-result:
		t.Fatal("readiness feedback cancelled the active report", err)
	case <-time.After(250 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe feedback did not finish")
	}
}
