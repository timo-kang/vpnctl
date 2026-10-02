// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/atomicfile"
	"vpnctl/internal/config"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

func directRequestForTest(t *testing.T, s *Server, from, to string, success bool) api.DirectResultRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, peer := range s.directCandidatesLocked(from) {
		if peer.ID == to {
			return api.DirectResultRequest{NodeID: from, PeerID: to, Success: success, ProbeToken: peer.ProbeToken}
		}
	}
	t.Fatal("direct candidate not found")
	return api.DirectResultRequest{}
}
func directSubmitForTest(t *testing.T, s *Server, req api.DirectResultRequest, want int) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleDirectResult(w, httptest.NewRequest(http.MethodPost, "/direct-result", bytes.NewReader(body)))
	if w.Code != want {
		t.Fatalf("direct result: got %d want %d: %s", w.Code, want, w.Body.String())
	}
}
func directGenerationFixture(t *testing.T) (*Server, nodeRegistration, nodeRegistration) {
	t.Helper()
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", P2PReadyMode: "mutual"})
	if err != nil {
		t.Fatal(err)
	}
	a := nodeRegistration{Name: "a", PubKey: "pub-a", Endpoint: "192.0.2.1:51820", ProbePort: 5000, PublicAddr: "192.0.2.1:5000", NATType: "open"}
	b := nodeRegistration{Name: "b", PubKey: "pub-b", Endpoint: "192.0.2.2:51820", ProbePort: 5000, PublicAddr: "192.0.2.2:5000", NATType: "open"}
	for _, n := range []nodeRegistration{a, b} {
		if _, err := s.registerNode(n, false); err != nil {
			t.Fatal(err)
		}
	}
	return s, a, b
}
func directReadyForTest(t *testing.T, s *Server) {
	t.Helper()
	directSubmitForTest(t, s, directRequestForTest(t, s, "a", "b", true), 204)
	directSubmitForTest(t, s, directRequestForTest(t, s, "b", "a", true), 204)
	if !s.p2pReadyLocked("a", "b") {
		t.Fatal("positive setup failed")
	}
}
func TestDirectGenerationChangesInvalidateBothDirections(t *testing.T) {
	for _, mode := range []string{"endpoint", "public_addr", "nat", "probe_port", "key", "late_success", "aba", "nat-api", "observed-endpoint", "observed-disappears"} {
		t.Run(mode, func(t *testing.T) {
			s, _, b := directGenerationFixture(t)
			if mode == "observed-endpoint" || mode == "observed-disappears" {
				s.reg.Nodes[1].Endpoint = ""
				s.directObserved = map[string]string{b.PubKey: "192.0.2.2:51820"}
			}
			directReadyForTest(t, s)
			oldAB := directRequestForTest(t, s, "a", "b", true)
			oldBA := directRequestForTest(t, s, "b", "a", true)
			switch mode {
			case "endpoint", "aba":
				b.Endpoint = "192.0.2.3:51820"
			case "public_addr":
				b.PublicAddr = "192.0.2.3:5000"
			case "nat":
				b.NATType = "symmetric"
			case "probe_port":
				b.ProbePort = 5001
			case "key":
				b.PubKey = "new-pub-b"
			case "late_success":
				directSubmitForTest(t, s, directRequestForTest(t, s, "a", "b", false), 204)
			case "nat-api":
				body, _ := json.Marshal(api.NATProbeRequest{NodeID: "b", PublicAddr: "192.0.2.3:5000", NATType: "open"})
				w := httptest.NewRecorder()
				s.handleNATProbe(w, httptest.NewRequest(http.MethodPost, "/nat-probe", bytes.NewReader(body)))
				if w.Code != 204 {
					t.Fatal(w.Code)
				}
			case "observed-endpoint", "observed-disappears":
				s.cfg.WGInterface = "wg-test"
				dump := "private public 51820 off\n"
				if mode == "observed-endpoint" {
					dump += b.PubKey + " (none) 192.0.2.8:51820 10.7.0.3/32 0 0 0 off\n"
				}
				s.wg = wireguard.NewManager(&fakeRunner{out: map[string]string{"wg show wg-test dump": dump}})
				s.refreshDirectEndpoints() // A changed or disappeared observed mapping invalidates the prior generation.
			}
			if mode != "late_success" && mode != "nat-api" && mode != "observed-endpoint" && mode != "observed-disappears" {
				if _, err := s.registerNode(b, false); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "aba" {
				b.Endpoint = "192.0.2.2:51820"
				if _, err := s.registerNode(b, false); err != nil {
					t.Fatal(err)
				}
			}
			if s.p2pReadyLocked("a", "b") {
				t.Fatal("stale readiness after input change")
			}
			directSubmitForTest(t, s, oldAB, 409)
			directSubmitForTest(t, s, oldBA, 409)
			directReadyForTest(t, s)
		})
	}
}
func TestDirectTicketsRejectReplayExpiryAndWrongBinding(t *testing.T) {
	for _, mode := range []string{"missing", "tampered", "wrong-node", "wrong-peer", "expired", "clock-backward", "restart", "replay", "older-result"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := directGenerationFixture(t)
			now := time.Now()
			s.directNow = func() time.Time { return now }
			req := directRequestForTest(t, s, "a", "b", true)
			switch mode {
			case "missing":
				req.ProbeToken = ""
			case "tampered":
				req.ProbeToken += "a"
			case "wrong-node":
				req.NodeID, req.PeerID = req.PeerID, req.NodeID
			case "wrong-peer":
				req.PeerID = "a"
			case "expired":
				now = now.Add(directReadinessTTL)
			case "clock-backward":
				now = now.Add(-time.Second)
			case "restart":
				var err error
				s, err = NewServer(s.cfg)
				if err != nil {
					t.Fatal(err)
				}
			case "replay":
				directSubmitForTest(t, s, req, 204)
			case "older-result":
				directSubmitForTest(t, s, directRequestForTest(t, s, "a", "b", true), 204)
			}
			want := 409
			if mode == "wrong-peer" {
				want = 400
			}
			directSubmitForTest(t, s, req, want)
		})
	}
}
func TestDirectReceiptCannotRefreshOldMeasurement(t *testing.T) {
	s, _, _ := directGenerationFixture(t)
	now := time.Now()
	s.directNow = func() time.Time { return now }
	ab := directRequestForTest(t, s, "a", "b", true)
	ba := directRequestForTest(t, s, "b", "a", true)
	now = now.Add(directReadinessTTL - time.Second)
	directSubmitForTest(t, s, ab, 204)
	directSubmitForTest(t, s, ba, 204)
	if !s.p2pReadyLocked("a", "b") {
		t.Fatal("still-current measurement lost")
	}
	now = now.Add(time.Second)
	if s.p2pReadyLocked("a", "b") {
		t.Fatal("receipt extended measurement lifetime")
	}
}
func TestDirectGenerationChangesOnlyAfterRegistryPublication(t *testing.T) {
	s, _, b := directGenerationFixture(t)
	directReadyForTest(t, s)
	req := directRequestForTest(t, s, "a", "b", true)
	s.saveRegistry = func(string, *store.Registry) error { return errors.New("before publication") }
	b.Endpoint = "192.0.2.9:51820"
	if _, err := s.registerNode(b, false); err == nil {
		t.Fatal("expected save failure")
	}
	if !s.p2pReadyLocked("a", "b") {
		t.Fatal("failed mutation invalidated committed state")
	}
	directSubmitForTest(t, s, req, 204)
}

type directEndpointRaceRunner struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (r *directEndpointRaceRunner) Run(string, ...string) error {
	return errors.New("unexpected mutation")
}
func (r *directEndpointRaceRunner) Output(string, ...string) (string, error) {
	endpoint := "192.0.2.9:51820"
	if r.calls.Add(1) == 1 {
		close(r.entered)
		<-r.release
		endpoint = "192.0.2.8:51820"
	}
	return "private public 51820 off\npub-b (none) " + endpoint + " 10.7.0.3/32 0 0 0 off\n", nil
}
func TestDirectObservedEndpointLateInventoryCannotRestoreOldGeneration(t *testing.T) {
	s, _, _ := directGenerationFixture(t)
	s.reg.Nodes[1].Endpoint = ""
	s.cfg.WGInterface = "wg-test"
	runner := &directEndpointRaceRunner{entered: make(chan struct{}), release: make(chan struct{})}
	s.wg = wireguard.NewManager(runner)
	done := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(runner.release) })
	go func() { defer close(done); s.refreshDirectEndpoints() }()
	select {
	case <-runner.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first inventory did not start")
	}
	s.refreshDirectEndpoints()
	fresh := directRequestForTest(t, s, "a", "b", true)
	release.Do(func() { close(runner.release) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("old inventory did not drain")
	}
	if s.directObserved["pub-b"] != "192.0.2.9:51820" {
		t.Fatal("older inventory won")
	}
	directSubmitForTest(t, s, fresh, 204)
}
func TestDirectGenerationOverAuthenticatedAPI(t *testing.T) {
	s, _ := testAdminServer(t, t.TempDir())
	h, bootstrap, tlsCfg := testTLSAPI(t, s)
	tokens, err := s.tokenStore.List()
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := enrollTestClient(t, h, bootstrap, tlsCfg, tokens[0], "a")
	b, _, _ := enrollTestClient(t, h, bootstrap, tlsCfg, tokens[0], "b")
	ctx := context.Background()
	request := func(client *api.Client, from string, success bool) api.DirectResultRequest {
		t.Helper()
		out, err := client.Candidates(ctx, from)
		if err != nil || len(out.Peers) != 1 {
			t.Fatal(out, err)
		}
		peer := out.Peers[0]
		if peer.DirectGeneration == "" || peer.ProbeToken == "" {
			t.Fatal("API lost ticket")
		}
		return api.DirectResultRequest{NodeID: from, PeerID: peer.ID, Success: success, ProbeToken: peer.ProbeToken}
	}
	for n := 0; n < 30; n++ {
		ar, br := request(a, "a", true), request(b, "b", true)
		if err := a.SubmitDirectResult(ctx, ar); err != nil {
			t.Fatal(err)
		}
		if err := b.SubmitDirectResult(ctx, br); err != nil {
			t.Fatal(err)
		}
		ready, err := a.Candidates(ctx, "a")
		if err != nil || len(ready.Peers) != 1 || !ready.Peers[0].P2PReady {
			t.Fatal("fresh mutual API success lost", ready, err)
		}
		if err := b.SubmitDirectResult(ctx, ar); err == nil {
			t.Fatal("wrong certificate accepted ticket")
		}
		old := request(b, "b", true)
		if err := a.SubmitDirectResult(ctx, request(a, "a", false)); err != nil {
			t.Fatal(err)
		}
		if err := b.SubmitDirectResult(ctx, old); err == nil {
			t.Fatal("late authenticated success revived failed pair")
		}
		out, err := a.Candidates(ctx, "a")
		if err != nil || out.Peers[0].P2PReady {
			t.Fatal(out, err)
		}
	}
}

func TestDirectNoopRegistrationPreservesGeneration(t *testing.T) {
	s, _, b := directGenerationFixture(t)
	directReadyForTest(t, s)
	request := directRequestForTest(t, s, "a", "b", true)
	if _, err := s.registerNode(b, false); err != nil {
		t.Fatal(err)
	}
	if !s.p2pReadyLocked("a", "b") {
		t.Fatal("heartbeat invalidated unchanged path")
	}
	directSubmitForTest(t, s, request, 204)
}

func TestDirectUncertainPublishedChangeInvalidatesGeneration(t *testing.T) {
	s, _, b := directGenerationFixture(t)
	directReadyForTest(t, s)
	old := directRequestForTest(t, s, "a", "b", true)
	s.saveRegistry = func(path string, reg *store.Registry) error {
		if err := store.SaveRegistry(path, reg); err != nil {
			return err
		}
		return &atomicfile.CommitError{Err: errors.New("directory sync failed after replacement")}
	}
	b.Endpoint = "192.0.2.9:51820"
	if _, err := s.registerNode(b, false); !atomicfile.Replaced(err) {
		t.Fatal(err)
	}
	if s.p2pReadyLocked("a", "b") {
		t.Fatal("published path retained readiness")
	}
	directSubmitForTest(t, s, old, 409)
}
