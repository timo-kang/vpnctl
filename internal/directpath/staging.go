// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"time"
)

// Version 2 distinguishes peers that have no application prefix from peers in
// a possibly interrupted promotion. Version 1 must never authorize either form.
func validatePhases(j journal) error {
	if j.Version == 1 && len(j.Phases) != 0 {
		return errors.New("legacy journal contains staged peers")
	}
	for key, phase := range j.Phases {
		if _, ok := j.Peers[key]; !ok || phase != "staging" && phase != "handshake" && phase != "activating" {
			return errors.New("invalid direct journal phase")
		}
	}
	return nil
}

func staged(p kernelPeer, c Candidate) bool {
	return p.Key == c.Key && !p.PSK && len(p.Prefixes) == 0 && p.Keepalive == 1
}
func (e *Engine) owned(p kernelPeer, c Candidate) bool {
	switch e.j.Phases[c.Key] {
	case "staging":
		return p.Key == c.Key && !p.PSK && len(p.Prefixes) == 0 && (p.Keepalive == 0 || p.Keepalive == 1)
	case "handshake":
		return staged(p, c)
	case "activating":
		// wg set updates keepalive and prefixes separately. Either order can be
		// visible after an interrupted command; no other prefixes/PSK are owned.
		return p.Key == c.Key && !p.PSK && (p.Keepalive == 1 || p.Keepalive == c.Keepalive) && (len(p.Prefixes) == 0 || len(p.Prefixes) == 1 && p.Prefixes[0] == c.Address+"/32")
	default:
		return owned(p, c)
	}
}

func (e *Engine) promote(ctx context.Context, candidates []Candidate) error {
	if len(candidates) == 0 {
		return nil
	}
	s, err := e.inspect(ctx)
	if err != nil {
		return err
	}
	if !e.relayOK(s) {
		return errors.New("relay baseline changed")
	}
	for _, c := range candidates {
		p := s.Peers[c.Key]
		if e.j.Phases[c.Key] != "handshake" || !staged(p, c) || p.Endpoint != c.Endpoint || p.Handshake <= 0 || p.RX == 0 || p.TX == 0 {
			return errors.New("direct transport not ready for promotion")
		}
		addr := netip.MustParseAddr(c.Address)
		for key, other := range s.Peers {
			if key == c.Key || key == e.cfg.ServerPublicKey {
				continue
			}
			for _, raw := range other.Prefixes {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || prefix.Contains(addr) {
					return errors.New("foreign peer owns direct destination")
				}
			}
		}
	}
	next := e.j
	next.Phases = maps.Clone(e.j.Phases)
	for _, c := range candidates {
		next.Phases[c.Key] = "activating"
	}
	if err := e.persist(next); err != nil {
		return err
	}
	started := e.now()
	if err := e.backend.Add(ctx, candidates); err != nil {
		return err
	}
	s, err = e.inspect(ctx)
	if err != nil {
		return err
	}
	for _, c := range candidates {
		if !matches(s.Peers[c.Key], c) {
			return errors.New("direct promotion readback failed")
		}
	}
	next = e.j
	next.Phases = maps.Clone(e.j.Phases)
	for _, c := range candidates {
		delete(next.Phases, c.Key)
	}
	if err := e.persist(next); err != nil {
		return err
	}
	for _, c := range candidates {
		e.trialStarted[c.Key] = started
	}
	return nil
}

// Recreate only prefix-free, unconfirmed transports. Native WG retry timers can
// finish without a usable session (including after the staged queue is purged).
// Different endpoint cadences avoid repeatedly restarting both sides together.
func handshakeRestartDelay(local, peer string) time.Duration {
	if local < peer {
		return 6 * time.Second
	}
	return 8 * time.Second
}

func (e *Engine) restartStalled(ctx context.Context, candidates []Candidate) (map[string]bool, error) {
	restarted := map[string]bool{}
	if len(candidates) == 0 {
		return restarted, nil
	}
	s, err := e.inspect(ctx)
	if err != nil {
		return restarted, err
	}
	if !e.relayOK(s) {
		return restarted, errors.New("relay baseline changed before transport retry")
	}
	var keys []string
	var retry []Candidate
	for _, c := range candidates {
		p := s.Peers[c.Key]
		if e.j.Peers[c.Key] != c || e.j.Phases[c.Key] != "handshake" || !staged(p, c) || p.Endpoint != c.Endpoint {
			return restarted, errors.New("stalled transport ownership changed")
		}
		// A handshake can complete between the first inspection and this retry.
		// Never deliberately reset transport that this fresh read has proven ready.
		if p.Handshake > 0 && p.RX > 0 && p.TX > 0 {
			continue
		}
		keys = append(keys, c.Key)
		retry = append(retry, c)
	}
	// Reuse the ordinary ownership/readback and durable removal/creation protocol.
	// A partial failure remains recoverable; no application prefix is installed.
	removed, err := e.removeWhere(ctx, keys, func(p kernelPeer, c Candidate) bool {
		return p.Endpoint == c.Endpoint && (p.Handshake <= 0 || p.RX == 0 || p.TX == 0)
	})
	if err != nil {
		return restarted, err
	}
	selected := make(map[string]bool, len(removed))
	for _, key := range removed {
		selected[key] = true
	}
	kept := retry[:0]
	for _, c := range retry {
		if selected[c.Key] {
			kept = append(kept, c)
		}
	}
	retry = kept
	if err := e.add(ctx, retry); err != nil {
		return restarted, err
	}
	for _, c := range retry {
		restarted[c.ID] = true
	}
	return restarted, nil
}
