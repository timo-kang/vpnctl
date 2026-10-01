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

// A readiness withdrawal must cancel stale results, but does not change the
// probe destination. Waiting a complete cadence before a fresh round adds an
// avoidable 60 seconds in the production profile, plus collector latency.
func TestDirectWithdrawalPromptlyStartsFreshRound(t *testing.T) {
	remote, e := direct.StartResponder("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer remote.Close()
	addr, e := net.ResolveUDPAddr("udp", remote.LocalAddr())
	if e != nil {
		t.Fatal(e)
	}
	shared, e := direct.ListenShared("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer shared.Close()
	entered, cancelled, fresh := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	var requests atomic.Int32
	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if requests.Add(1) == 1 {
			close(entered)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		select {
		case fresh <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ctrl.Close()
	client := api.NewClient(ctrl.URL)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan directSnapshot, 1)
	done := make(chan struct{})
	cfg := config.NodeConfig{DirectIntervalSec: 3, ServerPublicKey: "hub", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"10.7.0.0/24"}}
	go func() {
		defer close(done)
		runDirect(ctx, client, cfg, "node", shared, updates, func([]wireguard.Peer) error { return nil })
	}()
	defer func() { cancel(); <-done }()
	peer := api.PeerCandidate{ID: "peer", PubKey: "peer-key", VPNIP: "10.7.0.3/32", Endpoint: "127.0.0.1:51821", PublicAddr: remote.LocalAddr(), ProbePort: addr.Port, P2PReady: true}
	updates <- directSnapshot{peers: []api.PeerCandidate{peer}}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial measurement did not start")
	}
	peer.P2PReady = false
	updates <- directSnapshot{peers: []api.PeerCandidate{peer}}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("withdrawal did not cancel stale result")
	}
	select {
	case <-fresh:
	case <-time.After(time.Second):
		t.Fatal("readiness withdrawal delayed fresh measurement by a full cadence")
	}
}
