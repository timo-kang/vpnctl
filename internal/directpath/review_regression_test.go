// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"testing"
	"time"
)

func TestStaleRelayProofCannotPromoteStagedPeer(t *testing.T) {
	e, k, c := fixture(t)
	now := time.Now()
	e.now = func() time.Time { return now }
	k.mode = "stage-silent"
	if s, err := e.Step(context.Background(), []Candidate{c}); err != nil || s[0].State != "handshaking" {
		t.Fatal(s, err)
	}
	now = now.Add(31 * time.Second)
	k.mode = "healthy"
	k.relaySilent = true
	p := k.s.Peers[c.Key]
	p.Handshake, p.RX, p.TX = 1, 32, 32
	k.s.Peers[c.Key] = p
	s, err := e.Step(context.Background(), []Candidate{c})
	if err != nil {
		t.Fatal(err)
	}
	if k.adds != 0 {
		t.Fatalf("stale relay proof admitted route: adds=%d statuses=%v relay proof age=%s", k.adds, s, now.Sub(e.relayVerified))
	}
}
func TestExpiredTrialCannotWithdrawHealthyActivePeer(t *testing.T) {
	e, k, c := fixture(t)
	now := time.Now()
	e.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
			t.Fatal(err)
		}
	}
	other := c
	other.ID = "new-peer"
	other.Key = key(4)
	other.Address = "10.7.0.4"
	if _, err := e.Step(context.Background(), []Candidate{c, other}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(InitialTrialWindow)
	s, err := e.Step(context.Background(), []Candidate{c, other})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := k.s.Peers[c.Key]; !present {
		t.Fatalf("expired trial withdrew healthy active peer: statuses=%v", s)
	}
}
