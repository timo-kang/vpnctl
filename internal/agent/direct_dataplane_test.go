// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/directpath"
)

type dataplaneCall struct {
	ctx        context.Context
	candidates []directpath.Candidate
}
type blockedDataplane struct {
	calls    chan dataplaneCall
	inFlight atomic.Int32
	overlap  atomic.Bool
	closed   atomic.Bool
}

func (e *blockedDataplane) Step(ctx context.Context, c []directpath.Candidate) ([]directpath.Status, error) {
	if e.inFlight.Add(1) != 1 {
		e.overlap.Store(true)
	}
	defer e.inFlight.Add(-1)
	e.calls <- dataplaneCall{ctx, c}
	<-ctx.Done()
	// Simulate a late success which must be drained on replacement/shutdown.
	return []directpath.Status{{ID: "peer", State: "active", Generation: "obsolete"}}, nil
}
func (e *blockedDataplane) Reset(context.Context) error {
	if e.inFlight.Load() != 0 {
		e.overlap.Store(true)
	}
	return nil
}
func (e *blockedDataplane) Close() {
	if e.inFlight.Load() != 0 {
		e.overlap.Store(true)
	}
	e.closed.Store(true)
}
func directFixture() (config.NodeConfig, api.PeerCandidate) {
	key := func(n byte) string { b := make([]byte, 32); b[0] = n; return base64.StdEncoding.EncodeToString(b) }
	cfg := config.NodeConfig{WGInterface: "fixture", WGConfigPath: "fixture.conf", WGPublicKey: key(1), ServerPublicKey: key(2), VPNIP: "10.7.0.2/32", ServerAllowedIPs: []string{"10.7.0.0/24"}}
	p := api.PeerCandidate{ID: "peer", PubKey: key(3), VPNIP: "10.7.0.3/32", Endpoint: "192.0.2.3:51820", ProbePort: 51900, P2PReady: true, DirectGeneration: "g1", ProbeToken: "ticket"}
	return cfg, p
}
func TestDataplaneReplacementAndShutdownJoinOldWork(t *testing.T) {
	cfg, p := directFixture()
	updates := make(chan directSnapshot, 2)
	updates <- directSnapshot{peers: []api.PeerCandidate{p}, receivedAt: time.Now(), receivedBoot: directBootNow()}
	e := &blockedDataplane{calls: make(chan dataplaneCall, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDataplaneWorker(ctx, cfg, updates, func(context.Context) (dataplaneEngine, error) { return e, nil })
	}()
	take := func(generation string) dataplaneCall {
		t.Helper()
		timeout := time.NewTimer(6 * time.Second)
		defer timeout.Stop()
		for {
			select {
			case c := <-e.calls:
				if len(c.candidates) == 1 && c.candidates[0].Generation == generation {
					return c
				}
			case <-timeout.C:
				t.Fatal("expected generation not checked", generation)
				return dataplaneCall{}
			}
		}
	}
	old := take("g1")
	p.DirectGeneration = "g2"
	updates <- directSnapshot{peers: []api.PeerCandidate{p}, receivedAt: time.Now(), receivedBoot: directBootNow()}
	next := take("g2")
	if old.ctx.Err() == nil {
		t.Fatal("old generation was not cancelled")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain")
	}
	if next.ctx.Err() == nil || !e.closed.Load() || e.overlap.Load() {
		t.Fatal("dataplane ownership overlapped")
	}
}
func TestCandidateFreshnessAndSTUNCannotRefreshAuthority(t *testing.T) {
	now := time.Now()
	for _, age := range []time.Duration{-time.Nanosecond, directpath.CandidateMaxAge, directpath.CandidateMaxAge + time.Second} {
		if freshDirect(now.Add(-age), now) {
			t.Fatal("invalid age accepted", age)
		}
	}
	if freshDirect(time.Time{}, now) || !freshDirect(now.Add(-time.Second), now) {
		t.Fatal("freshness boundary")
	}
	snapshots := directSnapshots{current: directSnapshot{receivedAt: now.Add(-directpath.CandidateMaxAge)}}
	out := make(chan directSnapshot, 1)
	snapshots.update(out, func(s *directSnapshot) { s.publicAddr = "192.0.2.1:1234" })
	if freshDirect((<-out).receivedAt, now) {
		t.Fatal("STUN refreshed authority")
	}
	cfg, p := directFixture()
	p.ProbeToken = ""
	c, err := directCandidates(cfg, directSnapshot{peers: []api.PeerCandidate{p}})
	if err != nil || len(c) != 0 {
		t.Fatal("unticketed candidate admitted", c, err)
	}
	p.ProbeToken = "new"
	p.VPNIP = "10.7.0.0/24"
	if _, err = directCandidates(cfg, directSnapshot{peers: []api.PeerCandidate{p}}); err == nil {
		t.Fatal("subnet admitted as host")
	}
}

func TestCandidateBootAgeIncludesSuspendEvenWithWallRollback(t *testing.T) {
	received := uint64(time.Hour)
	for _, now := range []uint64{0, received - 1, received + uint64(directpath.CandidateMaxAge)} {
		if freshDirectBoot(received, now) {
			t.Fatal("expired/backwards clock admitted", now)
		}
	}
	if !freshDirectBoot(received, received+uint64(time.Second)) {
		t.Fatal("fresh boot age rejected")
	}
}

type pacedDataplane struct {
	calls    chan time.Time
	attempts int
}

func (e *pacedDataplane) Step(_ context.Context, c []directpath.Candidate) ([]directpath.Status, error) {
	if len(c) == 0 {
		return nil, nil
	}
	e.calls <- time.Now()
	e.attempts++
	state := "probing"
	if e.attempts >= 2 {
		state = "active"
	}
	return []directpath.Status{{ID: c[0].ID, State: state, Generation: c[0].Generation}}, nil
}
func (*pacedDataplane) Reset(context.Context) error { return nil }
func (*pacedDataplane) Close()                      {}

func TestDataplaneInitialProofCadenceSurvivesUnchangedUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, p := directFixture()
		updates := make(chan directSnapshot, 2)
		fresh := func() directSnapshot {
			return directSnapshot{peers: []api.PeerCandidate{p}, receivedAt: time.Now(), receivedBoot: directBootNow()}
		}
		updates <- fresh()
		e := &pacedDataplane{calls: make(chan time.Time, 8)}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runDataplaneWorker(ctx, cfg, updates, func(context.Context) (dataplaneEngine, error) { return e, nil })
		}()
		defer func() { cancel(); <-done }()
		first := <-e.calls
		updates <- fresh()
		second := <-e.calls
		if gap := second.Sub(first); gap != directpath.VerificationInterval {
			t.Fatal("initial verification delayed by identical update", gap)
		}
		third := <-e.calls
		if gap := third.Sub(second); gap != time.Second {
			t.Fatal("active peer retained fast trial polling", gap)
		}
	})
}
