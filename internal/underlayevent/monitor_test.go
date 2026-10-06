// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package underlayevent

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"math"
	"sync"
	"testing"
	"time"
	"vpnctl/internal/relayplan"
)

type fakeSource struct {
	events  [][]event
	err     error
	flood   bool
	closed  int
	waits   int
	waitErr error
}

func (s *fakeSource) read() ([]event, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.flood {
		return []event{{kind: newAddress, index: 7}}, nil
	}
	if len(s.events) == 0 {
		return nil, errEmpty
	}
	v := s.events[0]
	s.events = s.events[1:]
	return v, nil
}
func (s *fakeSource) wait(d time.Duration) error {
	s.waits++
	if s.waitErr != nil {
		return s.waitErr
	}
	time.Sleep(d)
	return nil
}
func (s *fakeSource) close() error { s.closed++; return nil }
func fixture(t *testing.T) (*Monitor, *fakeSource) {
	t.Helper()
	m, err := New([]relayplan.Underlay{{ID: "wifi", Interface: "wan0", Kind: "wifi"}, {ID: "lan", Interface: "wan1", Kind: "ethernet"}, {ID: "lte", Interface: "wwan0", Kind: "lte"}})
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSource{}
	m.open = func(context.Context) (source, []link, error) { return s, []link{{7, "wan0"}, {8, "wan1"}}, nil }
	t.Cleanup(func() { m.Close() })
	return m, s
}
func generation(t *testing.T, m *Monitor, id string) string {
	t.Helper()
	s, err := m.Generation(context.Background(), id)
	if err != nil || len(s) != 64 {
		t.Fatal(s, err)
	}
	return s
}
func TestChangesInvalidateOnlyAffectedUnderlayEvenAfterABA(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []event
	}{
		{"link-flap", []event{{kind: newLink, index: 7, name: "wan0"}, {kind: newLink, index: 7, name: "wan0"}}},
		{"address-delete-restore", []event{{kind: delAddress, index: 7}, {kind: newAddress, index: 7}}},
		{"route-delete-restore", []event{{kind: delRoute, indexes: []int{7}}, {kind: newRoute, indexes: []int{7}}}},
		{"rename-return", []event{{kind: newLink, index: 7, name: "renamed"}, {kind: newLink, index: 7, name: "wan0"}}},
		{"same-index-reuse", []event{{kind: delLink, index: 7, name: "wan0"}, {kind: newLink, index: 7, name: "wan0"}}},
		{"different-index-reuse", []event{{kind: delLink, index: 7, name: "wan0"}, {kind: newLink, index: 70, name: "wan0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, s := fixture(t)
			before, other := generation(t, m, "wifi"), generation(t, m, "lan")
			s.events = [][]event{tc.events}
			if generation(t, m, "wifi") == before || generation(t, m, "lan") != other {
				t.Fatal("lost change or invalidated unrelated underlay")
			}
			stable := generation(t, m, "wifi")
			if generation(t, m, "wifi") != stable {
				t.Fatal("quiet source changed generation")
			}
		})
	}
}
func TestUnknownDevicesStayExcludedAndRenamedIndexIsRetired(t *testing.T) {
	m, s := fixture(t)
	before := generation(t, m, "wifi")
	s.events = [][]event{{{kind: newLink, index: 50, name: "ethercat"}, {kind: newAddress, index: 50}, {kind: newRoute, indexes: []int{50}}}}
	if generation(t, m, "wifi") != before {
		t.Fatal("foreign device adopted")
	}
	s.events = [][]event{{{kind: newLink, index: 7, name: "elsewhere"}}}
	renamed := generation(t, m, "wifi")
	s.events = [][]event{{{kind: newAddress, index: 7}}}
	if generation(t, m, "wifi") != renamed {
		t.Fatal("retired index still assigned")
	}
	lte := generation(t, m, "lte")
	s.events = [][]event{{{kind: newLink, index: 11, name: "wwan0"}, {kind: newAddress, index: 11}}}
	if generation(t, m, "lte") == lte {
		t.Fatal("hotplug missed")
	}
	if _, err := m.Generation(context.Background(), "ethercat"); err == nil {
		t.Fatal("unconfigured ID accepted")
	}
}
func TestLossFloodRestartAndCounterExhaustionCannotReplay(t *testing.T) {
	for _, mode := range []string{"overflow", "malformed", "flood", "counter"} {
		t.Run(mode, func(t *testing.T) {
			m, s := fixture(t)
			before, other := generation(t, m, "wifi"), generation(t, m, "lan")
			switch mode {
			case "overflow":
				s.err = unix.ENOBUFS
			case "malformed":
				s.err = ErrUnavailable
			case "flood":
				s.flood = true
			case "counter":
				m.states["wifi"].version = math.MaxUint64
				s.events = [][]event{{{kind: newAddress, index: 7}}}
			}
			start := time.Now()
			if v, err := m.Generation(context.Background(), "wifi"); err == nil || v != "" {
				t.Fatal("lost stream accepted")
			}
			if time.Since(start) > 200*time.Millisecond || s.closed != 1 {
				t.Fatal("unbounded loss handling", s.closed)
			}
			if _, err := m.Generation(context.Background(), "wifi"); err == nil {
				t.Fatal("retry backoff missing")
			}
			s.err = nil
			s.flood = false
			m.nextRetry = time.Time{}
			if mode == "counter" {
				if _, err := m.Generation(context.Background(), "wifi"); err == nil {
					t.Fatal("wrapped counter")
				}
				return
			}
			if generation(t, m, "wifi") == before || generation(t, m, "lan") == other {
				t.Fatal("loss retained generation")
			}
		})
	}
	m, _ := fixture(t)
	another, _ := fixture(t)
	if generation(t, m, "wifi") == generation(t, another, "wifi") {
		t.Fatal("restart reused epoch")
	}
}
func TestWaitCancellationRelevantWakeAndUnavailableBackoff(t *testing.T) {
	m, s := fixture(t)
	generation(t, m, "wifi")
	s.events = [][]event{{{kind: newAddress, index: 7}}}
	start := time.Now()
	if err := m.Wait(context.Background(), time.Second); err != nil || time.Since(start) > 200*time.Millisecond {
		t.Fatal("event did not wake wait", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start = time.Now()
	if !errors.Is(m.Wait(ctx, time.Second), context.DeadlineExceeded) || time.Since(start) > 250*time.Millisecond {
		t.Fatal("wait ignored cancellation")
	}
	s.waitErr = unix.ENOBUFS
	start = time.Now()
	if m.Wait(context.Background(), 50*time.Millisecond) == nil || time.Since(start) < 40*time.Millisecond || s.closed != 1 {
		t.Fatal("collector error caused spin or lost stream stayed open")
	}
}
func TestGenerationCloseAndConcurrentReaders(t *testing.T) {
	m, _ := fixture(t)
	want := generation(t, m, "wifi")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				if got, err := m.Generation(context.Background(), "wifi"); err != nil || got != want {
					t.Error(got, err)
				}
			}
		}()
	}
	wg.Wait()
	m.Close()
	m.Close()
	if _, err := m.Generation(context.Background(), "wifi"); err == nil {
		t.Fatal("closed monitor accepted")
	}
}
