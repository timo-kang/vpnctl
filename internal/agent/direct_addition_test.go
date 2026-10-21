// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/base64"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/directpath"
)

type heldDataplaneCall struct {
	dataplaneCall
	release chan struct{}
}

type heldDataplane struct {
	calls    chan heldDataplaneCall
	inFlight atomic.Int32
	overlap  atomic.Bool
}

func (e *heldDataplane) Step(ctx context.Context, c []directpath.Candidate) ([]directpath.Status, error) {
	if e.inFlight.Add(1) != 1 {
		e.overlap.Store(true)
	}
	defer e.inFlight.Add(-1)
	if len(c) == 0 {
		return nil, nil
	}
	call := heldDataplaneCall{dataplaneCall{ctx, c}, make(chan struct{})}
	e.calls <- call
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.release:
		var statuses []directpath.Status
		for _, peer := range c {
			statuses = append(statuses, directpath.Status{ID: peer.ID, State: "active", Generation: peer.Generation})
		}
		return statuses, nil
	}
}
func (e *heldDataplane) Reset(context.Context) error {
	if e.inFlight.Load() != 0 {
		e.overlap.Store(true)
	}
	return nil
}
func (e *heldDataplane) Close() {
	if e.inFlight.Load() != 0 {
		e.overlap.Store(true)
	}
}

func additionalDirectPeer(p api.PeerCandidate) api.PeerCandidate {
	p.ID, p.VPNIP, p.Endpoint = "additional", "10.7.0.4/32", "192.0.2.4:51820"
	key := make([]byte, 32)
	key[0] = 4
	p.PubKey = base64.StdEncoding.EncodeToString(key)
	return p
}

func TestDataplaneAdditionPreservesInFlightVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, peer := directFixture()
		updates := make(chan directSnapshot, 4)
		publish := func(peers ...api.PeerCandidate) {
			updates <- directSnapshot{peers: peers, receivedAt: time.Now(), receivedBoot: directBootNow()}
		}
		publish(peer)
		e := &heldDataplane{calls: make(chan heldDataplaneCall, 4)}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runDataplaneWorker(ctx, cfg, updates, func(context.Context) (dataplaneEngine, error) { return e, nil })
		}()
		defer func() {
			cancel()
			<-done
			if e.overlap.Load() {
				t.Error("verification, reset or close overlapped")
			}
		}()
		first := <-e.calls
		publish(peer, additionalDirectPeer(peer))
		synctest.Wait()
		if first.ctx.Err() != nil {
			t.Fatal("adding an unrelated candidate interrupted an authorized mutation/verification")
		}
		if len(first.candidates) != 1 || len(e.calls) != 0 {
			t.Fatal("addition mutated or overlapped the running candidate snapshot")
		}
		close(first.release)
		next := <-e.calls
		if len(next.candidates) != 2 {
			t.Fatal("new candidate was not verified after existing work completed", next.candidates)
		}
	})
}

func TestDataplaneAdditionDoesNotMaskWithdrawalOrReplacement(t *testing.T) {
	for name, change := range map[string]func(*api.PeerCandidate){
		"withdrawal":     func(p *api.PeerCandidate) { p.P2PReady = false },
		"ticket removed": func(p *api.PeerCandidate) { p.ProbeToken = "" },
		"identity":       func(p *api.PeerCandidate) { p.ID = "replacement" },
		"key": func(p *api.PeerCandidate) {
			key := make([]byte, 32)
			key[0] = 5
			p.PubKey = base64.StdEncoding.EncodeToString(key)
		},
		"address":    func(p *api.PeerCandidate) { p.VPNIP = "10.7.0.5/32" },
		"endpoint":   func(p *api.PeerCandidate) { p.Endpoint = "192.0.2.5:51820" },
		"probe port": func(p *api.PeerCandidate) { p.ProbePort++ },
		"keepalive":  func(p *api.PeerCandidate) { p.NATType = "unknown" },
		"generation": func(p *api.PeerCandidate) { p.DirectGeneration = "replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, peer := directFixture()
				cfg.DirectKeepaliveSymmetricSec, cfg.DirectKeepaliveUnknownSec = 5, 7
				updates := make(chan directSnapshot, 4)
				publish := func(peers ...api.PeerCandidate) {
					updates <- directSnapshot{peers: peers, receivedAt: time.Now(), receivedBoot: directBootNow()}
				}
				publish(peer)
				e := &heldDataplane{calls: make(chan heldDataplaneCall, 4)}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					runDataplaneWorker(ctx, cfg, updates, func(context.Context) (dataplaneEngine, error) { return e, nil })
				}()
				defer func() {
					cancel()
					<-done
					if e.overlap.Load() {
						t.Error("replacement or cleanup overlapped old verification")
					}
				}()
				first := <-e.calls
				additional := additionalDirectPeer(peer)
				publish(peer, additional)
				synctest.Wait()
				if first.ctx.Err() != nil {
					t.Fatal("addition interrupted original candidate")
				}
				change(&peer)
				publish(peer, additional)
				synctest.Wait()
				if first.ctx.Err() == nil {
					t.Fatal("withdrawn/replaced authority survived an additive update")
				}
				next := <-e.calls
				want, err := directCandidates(cfg, directSnapshot{peers: []api.PeerCandidate{peer, additional}})
				if err != nil || !reflect.DeepEqual(next.candidates, want) {
					t.Fatal("replacement did not use latest authorized candidates", next.candidates, err)
				}
			})
		})
	}
}
