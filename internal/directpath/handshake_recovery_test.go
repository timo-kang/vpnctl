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

// A staged peer can exhaust its native handshake retries without acquiring an
// application prefix. It needs a fresh attempt after connectivity returns;
// growing handshake byte counters alone must never authorize promotion.
type stalledHandshakeKernel struct {
	*fakeKernel
	stages    int
	reachable bool
}

func (k *stalledHandshakeKernel) Stage(ctx context.Context, candidates []Candidate) error {
	k.stages++
	if err := k.fakeKernel.Stage(ctx, candidates); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range candidates {
		p := k.s.Peers[c.Key]
		if !k.reachable {
			p.Handshake, p.RX, p.TX = 0, 296, 776
		}
		k.s.Peers[c.Key] = p
	}
	return nil
}
func TestStalledHandshakeRecoversWithoutCapturingRelayTraffic(t *testing.T) {
	for _, faultDuration := range []time.Duration{12 * time.Second, 95 * time.Second} {
		t.Run(faultDuration.String(), func(t *testing.T) {
			e, base, c := fixture(t)
			k := &stalledHandshakeKernel{fakeKernel: base}
			e.backend = k
			now := time.Now()
			e.now = func() time.Time { return now }
			start := now
			for now.Sub(start) < faultDuration {
				out, err := e.Step(context.Background(), []Candidate{c})
				if err != nil || len(out) != 1 || out[0].State != "handshaking" || k.adds != 0 || len(k.s.Peers[c.Key].Prefixes) != 0 {
					t.Fatal("unconfirmed handshake displaced relay", out, err)
				}
				now = now.Add(time.Second)
			}
			if k.stages < 2 {
				t.Fatal("blackhole left a native retry stall indefinitely")
			}
			k.reachable = true
			restored := now
			for now.Sub(restored) < 15*time.Second {
				out, err := e.Step(context.Background(), []Candidate{c})
				if err != nil {
					t.Fatal(err)
				}
				if len(out) == 1 && out[0].State == "active" {
					if k.stages < 2 || e.successes[c.Key] < 2 {
						t.Fatal("recovery skipped fresh transport or nonce proof")
					}
					return
				}
				now = now.Add(time.Second)
			}
			t.Fatal("native handshake stall prevented recovery; no bounded restart", k.stages)
		})
	}
}

func TestStalledRestartRechecksIdentityAndCompletedTransport(t *testing.T) {
	for _, mode := range []string{"ready", "prefix", "psk", "keepalive", "endpoint", "identity", "relay", "phase"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c := fixture(t)
			k.mode = "stage-silent"
			if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
				t.Fatal(err)
			}
			p := k.s.Peers[c.Key]
			switch mode {
			case "ready":
				p.Handshake, p.RX, p.TX = 1, 32, 32
			case "prefix":
				p.Prefixes = []string{c.Address + "/32"}
			case "psk":
				p.PSK = true
			case "keepalive":
				p.Keepalive = 2
			case "endpoint":
				p.Endpoint = "192.0.2.99:51820"
			case "identity":
				k.s.Identity.Index++
			case "relay":
				delete(k.s.Peers, e.cfg.ServerPublicKey)
			case "phase":
				e.j.Phases[c.Key] = "activating"
			}
			k.s.Peers[c.Key] = p
			restarted, err := e.restartStalled(context.Background(), []Candidate{c})
			if (err == nil) != (mode == "ready") || len(restarted) != 0 || k.removes != 0 || k.adds != 0 {
				t.Fatal("restart adopted drift or destroyed completed transport", mode, restarted, err, k.removes, k.adds)
			}
		})
	}
}

func TestStalledRestartDurableBoundariesRecover(t *testing.T) {
	for boundary := 1; boundary <= 3; boundary++ {
		for _, visible := range []bool{false, true} {
			t.Run(fmt.Sprintf("save-%d-visible-%v", boundary, visible), func(t *testing.T) {
				e, k, c := fixture(t)
				k.mode = "stage-silent"
				if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
					t.Fatal(err)
				}
				save := e.save
				calls := 0
				e.save = func(j journal) error {
					calls++
					if calls == boundary {
						if visible {
							if err := save(j); err != nil {
								return err
							}
							return &atomicfile.CommitError{Err: errors.New("injected directory fsync failure")}
						}
						return errors.New("injected write failure")
					}
					return save(j)
				}
				if _, err := e.restartStalled(context.Background(), []Candidate{c}); err == nil {
					t.Fatal("save failure ignored")
				}
				if k.adds != 0 {
					t.Fatal("transport restart assigned an application prefix")
				}
				reopened := newEngine(e.cfg, *k.saved, k, save)
				if err := reopened.Reset(context.Background()); err != nil {
					t.Fatal(err)
				}
				if len(k.s.Peers) != 1 {
					t.Fatal("partial transport retry was not recovered")
				}
				if _, ok := k.s.Peers[e.cfg.ServerPublicKey]; !ok {
					t.Fatal("relay lost during recovery")
				}
			})
		}
	}
}

func TestWithdrawnStalledCandidateIsNotRestarted(t *testing.T) {
	e, base, c := fixture(t)
	k := &stalledHandshakeKernel{fakeKernel: base}
	e.backend = k
	now := time.Now()
	e.now = func() time.Time { return now }
	if _, err := e.Step(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Second)
	if out, err := e.Step(context.Background(), nil); err != nil || len(out) != 0 || k.stages != 1 || len(e.handshakeStarted) != 0 {
		t.Fatal("withdrawal revived stale transport", out, err, k.stages, e.handshakeStarted)
	}
}
