// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package underlayevent tracks changes to explicitly configured uplinks. It
// observes kernel notifications and never changes network configuration.
package underlayevent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayplan"
)

var ErrUnavailable = errors.New("underlay events unavailable; fresh inventory and evidence required")

const retryDelay = time.Second
const drainBudget = 25 * time.Millisecond
const maxDatagrams = 128

type link struct {
	index int
	name  string
}
type event struct {
	kind          uint16
	index         int
	name          string
	indexes       []int
	global        bool
	terminal      bool
	table, metric uint32
}
type source interface {
	read() ([]event, error) // errEmpty means the nonblocking socket is drained
	wait(time.Duration) error
	close() error
}

var errEmpty = errors.New("no queued events")

type state struct {
	name    string
	index   int
	version uint64
}
type Monitor struct {
	mu        sync.Mutex
	states    map[string]*state
	epoch     [32]byte
	revision  uint64
	source    source
	open      func(context.Context) (source, []link, error)
	nextRetry time.Time
	closed    bool
	failed    bool
	terminals []relayobserve.TerminalScope
}

func New(underlays []relayplan.Underlay) (*Monitor, error) {
	if err := relayplan.ValidateUnderlays(underlays); err != nil {
		return nil, err
	}
	m := &Monitor{states: map[string]*state{}, open: openSource}
	if _, err := rand.Read(m.epoch[:]); err != nil {
		return nil, err
	}
	for _, u := range underlays {
		m.states[u.ID] = &state{name: u.Interface, version: 1}
	}
	return m, nil
}
func (m *Monitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.source != nil {
		err := m.source.close()
		m.source = nil
		return err
	}
	return nil
}
func (m *Monitor) changed(s *state) {
	if s.version == math.MaxUint64 || m.revision == math.MaxUint64 {
		m.failed = true
		return
	}
	s.version++
	m.revision++
}
func (m *Monitor) lose() error {
	if m.source != nil {
		_ = m.source.close()
		m.source = nil
	}
	for _, s := range m.states {
		m.changed(s)
		s.index = 0
	}
	m.nextRetry = time.Now().Add(retryDelay)
	return ErrUnavailable
}
func (m *Monitor) connect(ctx context.Context) error {
	if m.closed || m.failed || time.Now().Before(m.nextRetry) {
		return ErrUnavailable
	}
	if m.source != nil {
		return nil
	}
	src, links, err := m.open(ctx)
	if err != nil {
		return m.lose()
	}
	m.source = src
	for _, s := range m.states {
		s.index = 0
		for _, l := range links {
			if s.name == l.name {
				s.index = l.index
			}
		}
	}
	return nil
}
func (m *Monitor) drain(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.connect(ctx); err != nil {
		return err
	}
	started := time.Now()
	for n := 0; n < maxDatagrams && time.Since(started) < drainBudget; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		events, err := m.source.read()
		if errors.Is(err, errEmpty) {
			return nil
		}
		if err != nil {
			return m.lose()
		}
		for _, ev := range events {
			for id, s := range m.states {
				affected := ev.global
				if ev.terminal {
					for _, scope := range m.terminals {
						if ev.table == scope.Table && ev.metric == scope.Metric {
							affected = id == scope.UnderlayID
							break
						}
					}
				}
				switch ev.kind {
				case newLink, delLink:
					if ev.name == s.name || s.index != 0 && ev.index == s.index {
						affected = true
						if ev.kind == newLink && ev.name == s.name {
							s.index = ev.index
						} else {
							s.index = 0
						}
					}
				case newAddress, delAddress:
					affected = affected || s.index != 0 && ev.index == s.index
				case newRoute, delRoute:
					for _, i := range ev.indexes {
						affected = affected || s.index != 0 && i == s.index
					}
				}
				if affected {
					m.changed(s)
				}
			}
		}
		if m.failed {
			return m.lose()
		}
	}
	// A continuously readable socket cannot monopolize a lease/apply budget.
	// Treat an unfinished drain exactly like loss; no partial generation escapes.
	return m.lose()
}

func (m *Monitor) SetTerminalScopes(ctx context.Context, scopes []relayobserve.TerminalScope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Drain queued events under the previous journal mapping before retiring it.
	// No event from the interval between admissions gets reclassified as new ownership.
	if err := m.drain(ctx); err != nil {
		return err
	}
	// At most eight installed entries plus eight waiting explicit intents.
	// These are event scopes only; the installed candidate limit remains eight.
	if len(scopes) > 16 {
		return ErrUnavailable
	}
	seen := map[uint32]bool{}
	for _, s := range scopes {
		if _, ok := m.states[s.UnderlayID]; !ok || s.Table < 100000 || s.Table > 624287 || s.Metric < 100000 || seen[s.Table] {
			return ErrUnavailable
		}
		seen[s.Table] = true
	}
	m.terminals = append(m.terminals[:0], scopes...)
	return nil
}
func (m *Monitor) Generation(ctx context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[id]
	if !ok {
		return "", ErrUnavailable
	}
	if err := m.drain(ctx); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%x/%s/%d", m.epoch, id, s.version)))
	return hex.EncodeToString(sum[:]), nil
}

// Wait wakes on relevant changes, bounded by the normal polling interval.
// Notifications from unrelated devices/owned app routes do not trigger work.
// No background receiver, hidden queue or goroutine outlives this monitor.
func (m *Monitor) Wait(ctx context.Context, interval time.Duration) error {
	deadline := time.Now().Add(interval)
	m.mu.Lock()
	revision := m.revision
	m.mu.Unlock()
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.mu.Lock()
		err := m.drain(ctx)
		changed := revision != m.revision
		if err == nil && !changed {
			err = m.source.wait(min(100*time.Millisecond, time.Until(deadline)))
			if err != nil {
				err = m.lose()
			}
		}
		m.mu.Unlock()
		if err != nil {
			// An unavailable collector must not cause a tight retry/reconcile loop.
			timer := time.NewTimer(max(0, min(retryDelay, time.Until(deadline))))
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return err
			}
		}
		if changed {
			return nil
		}
	}
	return ctx.Err()
}
