// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/uplinkapi"
)

// View is an observation, not an instruction to close a payload connection or
// route/lease authority. Current must be called at each point of use.
type View struct {
	APIAvailable bool   `json:"api_available"`
	Availability string `json:"availability"`
	Freshness    string `json:"freshness"`
	Reason       string `json:"reason"`
	ProducerID   string `json:"producer_id,omitempty"`
	Revision     uint64 `json:"revision,string"`
	PathRevision uint64 `json:"path_revision,string"`
	PathID       string `json:"path_id,omitempty"`
	Reset        bool   `json:"reset"`
}

type State struct {
	mu                                 sync.Mutex
	target                             string
	clock                              func() (string, uint64, error)
	epoch, lastClock                   uint64
	first, api, invalid, reset, active bool
	last                               *uplinkapi.Frame
}

func NewState(target string) (*State, error) { return newState(target, relayapply.LocalUplinkClock) }
func newState(target string, clock func() (string, uint64, error)) (*State, error) {
	if !idPattern.MatchString(target) || clock == nil {
		return nil, errors.New("valid target and clock required")
	}
	return &State{target: target, clock: clock}, nil
}

// Begin retires callbacks from all earlier connections. An authenticated stream
// must receive a full frame; its last cursor may be supplied for resynchronizing.
func (s *State) Begin() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.api = false
	s.first = true
	if s.epoch == ^uint64(0) {
		s.invalid = true
		return 0
	}
	s.epoch++
	s.active = true
	return s.epoch
}
func (s *State) Cursor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return ""
	}
	return s.last.Cursor
}
func (s *State) Disconnect(epoch uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch == s.epoch {
		s.api = false
		s.active = false
	}
}

func (s *State) Accept(epoch uint64, raw []byte) error {
	f, err := decodeFrame(raw, s.target)
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch == 0 || epoch != s.epoch || !s.active {
		return errors.New("retired uplink stream")
	}
	reject := func() error { s.api = false; s.invalid = true; return errFrame }
	if err != nil {
		return reject()
	}
	newPublication := s.last == nil
	reset := f.Type == "reset"
	if old := s.last; old != nil {
		transportChanged := f.Cursor[:32] != old.Cursor[:32]
		seq, _ := strconv.ParseUint(strings.Split(f.Cursor, ":")[1], 10, 64)
		prev, _ := strconv.ParseUint(strings.Split(old.Cursor, ":")[1], 10, 64)
		if transportChanged && !s.first || !transportChanged && (seq < prev || seq == prev && stableFrame(f) != stableFrame(*old)) {
			return reject()
		}
		a, b := f.Snapshot, old.Snapshot
		newPublication = a.ProducerID != b.ProducerID || a.Revision > b.Revision
		if a.ProducerID == b.ProducerID {
			if a.Revision < b.Revision || a.PathRevision < b.PathRevision {
				return reject()
			}
			if a.Revision > b.Revision && a.Freshness == "fresh" && a.ObservedBootNS <= b.ObservedBootNS {
				return reject()
			}
			if a.Revision == b.Revision {
				if a.ObservedBootNS != b.ObservedBootNS || a.ValidUntilBootNS != b.ValidUntilBootNS || a.PathRevision != b.PathRevision {
					return reject()
				}
				if a.Freshness == "fresh" && (b.Freshness != "fresh" || a.Availability != b.Availability || a.PathID != b.PathID || a.Evidence != b.Evidence || a.Reason != b.Reason) {
					return reject()
				}
			}
		}
		reset = (reset && f.Cursor != old.Cursor) || transportChanged || a.ProducerID != b.ProducerID || (!transportChanged && seq > prev && seq-prev > 1) || (a.ProducerID == b.ProducerID && a.Revision > b.Revision && a.Revision-b.Revision > 1)
	}
	if newPublication {
		s.invalid = false
	}
	s.last = &f
	s.api = true
	s.first = false
	s.reset = reset
	s.current() // Latch clock/expiry failures at receipt, before returning.
	return nil
}

func (s *State) Current() View { s.mu.Lock(); defer s.mu.Unlock(); return s.current() }
func (s *State) current() View {
	v := View{APIAvailable: s.api, Availability: "unknown", Freshness: "unknown", Reason: "observation_unavailable", Reset: s.reset}
	if s.last == nil {
		return v
	}
	a := s.last.Snapshot
	v.ProducerID = a.ProducerID
	v.Revision = a.Revision
	v.PathRevision = a.PathRevision
	v.Availability = a.Availability
	v.Freshness = a.Freshness
	v.Reason = a.Reason
	v.PathID = a.PathID
	domain, now, err := s.clock()
	reason := ""
	if err != nil || domain != a.ClockDomain || now == 0 || now < s.lastClock || a.Freshness == "fresh" && now < a.ObservedBootNS {
		reason = "clock_unavailable"
	} else {
		s.lastClock = now
	}
	if reason == "" && a.Freshness == "fresh" && now >= a.ValidUntilBootNS {
		reason = "observation_expired"
	}
	if reason != "" {
		s.invalid = true
	}
	if s.invalid {
		v.Availability = "unknown"
		v.Freshness = "stale"
		v.PathID = ""
		v.Reason = reason
		if reason == "" {
			v.Reason = "observation_invalidated"
		}
	}
	return v
}
