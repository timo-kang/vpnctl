// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"vpnctl/internal/atomicfile"
)

func TestStagingDoesNotStealRelayPrefixWhileRemoteTransportIsAbsent(t *testing.T) {
	e, k, c := fixture(t)
	k.mode = "stage-silent"
	now := time.Now()
	e.now = func() time.Time { return now }
	for i := 0; i < 30; i++ {
		out, err := e.Step(context.Background(), []Candidate{c})
		if err != nil || len(out) != 1 || out[0].State != "handshaking" || len(k.s.Peers[c.Key].Prefixes) != 0 || k.adds != 0 {
			t.Fatal("unverified transport captured relay traffic", out, err)
		}
		now = now.Add(time.Second)
	}
	p := k.s.Peers[c.Key]
	p.Handshake, p.RX, p.TX = 1, 32, 32
	k.s.Peers[c.Key] = p
	k.mode = "healthy"
	for _, want := range []string{"probing", "active"} {
		out, err := e.Step(context.Background(), []Candidate{c})
		if err != nil || out[0].State != want {
			t.Fatal("handshake bypassed consecutive nonce verification", out, err)
		}
	}
}

func TestStagedAndInterruptedPromotionRecoverOnlyOwnedShapes(t *testing.T) {
	for _, phase := range []string{"staging", "handshake", "activating"} {
		for _, mode := range []string{"staged", "keepalive-zero", "prefix-only", "keepalive-only", "full", "foreign-prefix", "foreign-keepalive", "foreign-psk"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				e, k, c := fixture(t)
				k.mode = "stage-silent"
				if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
					t.Fatal(err)
				}
				e.j.Phases[c.Key] = phase
				p := k.s.Peers[c.Key]
				switch mode {
				case "keepalive-zero":
					p.Keepalive = 0
				case "prefix-only":
					p.Prefixes = []string{c.Address + "/32"}
				case "keepalive-only":
					p.Keepalive = c.Keepalive
				case "full":
					p.Prefixes = []string{c.Address + "/32"}
					p.Keepalive = c.Keepalive
				case "foreign-prefix":
					p.Prefixes = []string{"203.0.113.5/32"}
				case "foreign-keepalive":
					p.Keepalive = 99
				case "foreign-psk":
					p.PSK = true
				}
				k.s.Peers[c.Key] = p
				reopened := newEngine(e.cfg, e.j, k, e.save)
				err := reopened.Reset(context.Background())
				safe := mode == "staged" || phase == "staging" && mode == "keepalive-zero" || phase == "activating" && (mode == "prefix-only" || mode == "keepalive-only" || mode == "full")
				if (err == nil) != safe {
					t.Fatal("wrong partial promotion ownership", err)
				}
				_, remains := k.s.Peers[c.Key]
				if remains == safe {
					t.Fatal("foreign peer removed or owned peer retained")
				}
				if safe && len(reopened.j.Phases) != 0 {
					t.Fatal("stale phase survived recovery")
				}
			})
		}
	}
}

func TestJournalPhaseValidationRejectsLegacyOrOrphanAuthority(t *testing.T) {
	e, _, c := fixture(t)
	for _, mode := range []string{"legacy", "orphan", "unknown"} {
		j := e.j
		j.Version = 2
		j.Peers = map[string]Candidate{c.Key: c}
		j.Phases = map[string]string{c.Key: "handshake"}
		switch mode {
		case "legacy":
			j.Version = 1
		case "orphan":
			j.Peers = map[string]Candidate{}
		case "unknown":
			j.Phases[c.Key] = "active"
		}
		if validatePhases(j) == nil {
			t.Fatal("invalid phase accepted", mode)
		}
	}
}

func TestOnePositiveNonceDoesNotExtendTrialDeadline(t *testing.T) {
	e, k, c := fixture(t)
	now := time.Now()
	e.now = func() time.Time { return now }
	if out, err := e.Step(context.Background(), []Candidate{c}); err != nil || out[0].State != "probing" {
		t.Fatal(out, err)
	}
	now = now.Add(InitialTrialWindow)
	out, err := e.Step(context.Background(), []Candidate{c})
	if err != nil || out[0].State == "active" || k.removes != 1 {
		t.Fatal("late second success extended route occupancy", out, err)
	}
}

// Exercise every durable boundary: before/after prefix-free staging and
// before/after application-prefix promotion, with both invisible and visible
// (rename succeeded but durability uncertain) write failures.
func TestStagingJournalFailureAtEveryBoundaryRecovers(t *testing.T) {
	for boundary := 1; boundary <= 4; boundary++ {
		for _, visible := range []bool{false, true} {
			t.Run(fmt.Sprintf("save-%d-visible-%v", boundary, visible), func(t *testing.T) {
				e, k, c := fixture(t)
				original := e.j
				save := e.save
				calls := 0
				e.save = func(j journal) error {
					calls++
					if calls == boundary {
						if visible {
							if err := save(j); err != nil {
								return err
							}
							return &atomicfile.CommitError{Err: errors.New("injected fsync failure")}
						}
						return errors.New("injected write failure")
					}
					return save(j)
				}
				if _, err := e.Step(context.Background(), []Candidate{c}); err == nil {
					t.Fatal("write failure ignored")
				}
				if boundary <= 3 && k.adds != 0 {
					t.Fatal("prefix assigned without durable promotion intent")
				}
				prior := original
				if k.saved != nil {
					prior = *k.saved
				}
				reopened := newEngine(e.cfg, prior, k, save)
				if err := reopened.Reset(context.Background()); err != nil {
					t.Fatal(err)
				}
				if len(k.s.Peers) != 1 {
					t.Fatal("owned peer remained after restart")
				}
				if _, ok := k.s.Peers[e.cfg.ServerPublicKey]; !ok {
					t.Fatal("relay lost during recovery")
				}
			})
		}
	}
}
