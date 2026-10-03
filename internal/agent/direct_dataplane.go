// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/config"
	"vpnctl/internal/directpath"
)

// Recovery precedes registration, so a controller outage cannot strand peers
// left by an earlier process. Unjournaled/foreign peers are never adopted.
func recoverDirect(ctx context.Context, cfg config.NodeConfig) {
	if cfg.WGInterface == "" || cfg.WGConfigPath == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e, err := directpath.Open(ctx, cfg)
	if err == nil {
		defer e.Close()
		err = e.Reset(ctx)
	}
	if err != nil && ctx.Err() == nil {
		slog.Warn("direct recovery blocked", "err", err)
	}
}
func directCandidates(cfg config.NodeConfig, s directSnapshot) ([]directpath.Candidate, error) {
	out := []directpath.Candidate{}
	for _, p := range s.peers {
		if !p.P2PReady {
			continue
		}
		if p.DirectGeneration == "" || p.ProbeToken == "" {
			continue
		} // old controllers cannot admit new trials
		addr, err := netip.ParsePrefix(normalizeHostIP(p.VPNIP))
		if err != nil || addr.Bits() != 32 {
			return nil, errors.New("invalid direct VPN host")
		}
		out = append(out, directpath.Candidate{ID: p.ID, Key: p.PubKey, Endpoint: p.Endpoint, Address: addr.Addr().String(), ProbePort: p.ProbePort, Keepalive: directKeepalive(cfg, p.NATType), Generation: p.DirectGeneration})
	}
	slices.SortFunc(out, func(a, b directpath.Candidate) int { return strings.Compare(a.Key, b.Key) })
	return out, directpath.ValidateCandidates(cfg, out)
}

// This worker alone mutates direct peers. Controller calls and their timeouts
// remain in the UDP worker; the local one-second cycle is independent of them.
type dataplaneEngine interface {
	Step(context.Context, []directpath.Candidate) ([]directpath.Status, error)
	Reset(context.Context) error
	Close()
}

func freshDirect(received, now time.Time) bool {
	age := now.Sub(received)
	wallAge := now.Round(0).Sub(received.Round(0))
	return !received.IsZero() && age >= 0 && age < directpath.CandidateMaxAge && wallAge >= 0 && wallAge < directpath.CandidateMaxAge
}

// Suspend time counts against cached authority; a realtime rollback cannot
// extend it. This is userspace expiry on reconciliation, not a kernel lease.
func directBootNow() uint64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil || ts.Nano() <= 0 {
		return 0
	}
	return uint64(ts.Nano())
}
func freshDirectBoot(received, now uint64) bool {
	return received != 0 && now >= received && now-received < uint64(directpath.CandidateMaxAge)
}

func runDirectDataplane(ctx context.Context, cfg config.NodeConfig, updates <-chan directSnapshot) {
	runDataplaneWorker(ctx, cfg, updates, func(ctx context.Context) (dataplaneEngine, error) {
		e, err := directpath.Open(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return e, nil
	})
}

func runDataplaneWorker(ctx context.Context, cfg config.NodeConfig, updates <-chan directSnapshot, open func(context.Context) (dataplaneEngine, error)) {
	if cfg.WGInterface == "" || cfg.WGConfigPath == "" {
		return
	}
	var engine dataplaneEngine
	defer func() {
		if engine != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := engine.Reset(cleanup); err != nil {
				slog.Warn("direct shutdown recovery blocked", "err", err)
			}
			engine.Close()
		}
	}()
	var candidates []directpath.Candidate
	var received time.Time
	var receivedBoot uint64
	var stop context.CancelFunc
	type result struct {
		statuses []directpath.Status
		err      error
	}
	var done chan result
	var lastStart time.Time
	var previous []directpath.Status
	timer := time.NewTimer(0)
	defer timer.Stop()
	drain := func() {
		if stop != nil {
			stop()
			<-done
			stop = nil
			done = nil
		}
	}
	defer drain()
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			next, err := directCandidates(cfg, s)
			if err != nil {
				slog.Warn("direct candidates rejected", "err", err)
				continue
			}
			if !reflect.DeepEqual(next, candidates) {
				drain()
				for _, status := range previous {
					slog.Info("direct dataplane", "peer", status.ID, "state", "pending", "reason", "candidate_changed")
				}
				previous = nil
				timer.Reset(max(0, time.Until(lastStart.Add(time.Second))))
			}
			candidates, received, receivedBoot = next, s.receivedAt, s.receivedBoot
		case r := <-done:
			stop()
			stop = nil
			done = nil
			if r.err == nil && len(r.statuses) != 0 && (!freshDirect(received, time.Now()) || !freshDirectBoot(receivedBoot, directBootNow())) {
				r.err = errors.New("candidate authority expired during verification")
			}
			if r.err != nil {
				slog.Warn("direct dataplane blocked", "err", r.err)
				for _, status := range previous {
					slog.Warn("direct dataplane", "peer", status.ID, "state", "blocked", "reason", "kernel_or_journal_error")
				}
				previous = nil
				// A failed readback is not an active path. Reset only proven owned peers;
				// a conflict/durability failure remains blocked for operator diagnosis.
				cleanup, cancel := context.WithTimeout(ctx, 3*time.Second)
				if err := engine.Reset(cleanup); err != nil {
					slog.Warn("direct fallback blocked", "err", err)
				}
				cancel()
			} else if !reflect.DeepEqual(previous, r.statuses) {
				present := map[string]bool{}
				for _, status := range r.statuses {
					present[status.ID] = true
				}
				for _, status := range previous {
					if !present[status.ID] {
						slog.Info("direct dataplane", "peer", status.ID, "state", "relay_unverified", "reason", "candidate_withdrawn")
					}
				}
				for _, status := range r.statuses {
					slog.Info("direct dataplane", "peer", status.ID, "state", status.State, "reason", status.Reason, "generation", status.Generation)
				}
				if len(r.statuses) == 0 {
					slog.Info("direct dataplane baseline", "managed_peers", 0)
				}
				previous = r.statuses
			}
			timer.Reset(max(0, time.Until(lastStart.Add(time.Second))))
		case <-timer.C:
			if done != nil {
				continue
			}
			lastStart = time.Now()
			if engine == nil {
				openCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				var err error
				engine, err = open(openCtx)
				if err == nil {
					err = engine.Reset(openCtx)
				}
				cancel()
				if err != nil {
					if engine != nil {
						engine.Close()
						engine = nil
					}
					slog.Warn("direct dataplane unavailable", "err", err)
					timer.Reset(5 * time.Second)
					continue
				}
			}
			desired := candidates
			// Receiving another STUN update cannot refresh controller authorization.
			if !freshDirect(received, time.Now()) || !freshDirectBoot(receivedBoot, directBootNow()) {
				desired = nil
			}
			work, cancel := context.WithTimeout(ctx, 4*time.Second)
			stop = cancel
			done = make(chan result, 1)
			out := done
			go func() { s, err := engine.Step(work, desired); out <- result{s, err} }()
		}
	}
}
