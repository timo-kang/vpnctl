// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package underlayevent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type delayedDrainSource struct {
	source
	delay time.Duration
	reads int
	after func()
}

func (s *delayedDrainSource) read() ([]event, error) {
	s.reads++
	events, err := s.source.read()
	if s.reads == 1 {
		time.Sleep(s.delay)
		if s.after != nil {
			s.after()
		}
	}
	return events, err
}

func TestDrainedEventQueueAfterSchedulingDelayPreservesIndependentGeneration(t *testing.T) {
	m, src := fixture(t)
	wifi, lan := generation(t, m, "wifi"), generation(t, m, "lan")
	src.events = [][]event{{{kind: newAddress, index: 7}}}
	delayed := &delayedDrainSource{source: src, delay: drainBudget + 5*time.Millisecond}
	m.source = delayed
	got, err := m.Generation(context.Background(), "wifi")
	if err != nil || got == wifi {
		t.Fatal("complete event queue treated as loss", err)
	}
	if generation(t, m, "lan") != lan || src.closed != 0 {
		t.Fatal("unrelated underlay lost proof")
	}
	if delayed.reads > 3 {
		t.Fatal("unbounded drain", delayed.reads)
	}
}

func TestDrainBudgetStillRejectsPendingEventsErrorsAndCancellation(t *testing.T) {
	for _, mode := range []string{"pending", "read-error", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			m, src := fixture(t)
			generation(t, m, "wifi")
			src.events = [][]event{{{kind: newAddress, index: 7}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			delayed := &delayedDrainSource{source: src, delay: drainBudget + 5*time.Millisecond}
			switch mode {
			case "pending":
				src.events = append(src.events, []event{{kind: newAddress, index: 8}})
			case "read-error":
				delayed.after = func() { src.err = errors.New("lost socket") }
			case "cancelled":
				delayed.after = cancel
			}
			m.source = delayed
			if got, err := m.Generation(ctx, "wifi"); err == nil || got != "" {
				t.Fatal("partial or cancelled proof accepted", got, err)
			}
			if delayed.reads > 2 {
				t.Fatal("budget continued draining", delayed.reads)
			}
			if mode != "cancelled" && src.closed != 1 {
				t.Fatal("uncertain stream not retired")
			}
		})
	}
}

func TestDrainDatagramBoundaryNeverProcessesExtraEvent(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			m, src := fixture(t)
			before := generation(t, m, "wifi")
			other := generation(t, m, "lan")
			version := m.states["wifi"].version
			for n := 0; n < maxDatagrams; n++ {
				src.events = append(src.events, []event{{kind: newAddress, index: 7}})
			}
			if pending {
				src.events = append(src.events, []event{{kind: newAddress, index: 7}})
			}
			counted := &delayedDrainSource{source: src}
			m.source = counted
			got, err := m.Generation(context.Background(), "wifi")
			if counted.reads != maxDatagrams+1 {
				t.Fatal("datagram bound not exercised", counted.reads)
			}
			if pending {
				if err == nil || got != "" || src.closed != 1 {
					t.Fatal("pending event accepted", err)
				}
				// maxDatagrams processed changes, followed by one stream-loss invalidation.
				if m.states["wifi"].version != version+maxDatagrams+1 {
					t.Fatal("extra event processed")
				}
			} else {
				if err != nil || got == before || src.closed != 0 || generation(t, m, "lan") != other {
					t.Fatal("complete bounded queue lost", err)
				}
			}
		})
	}
}
