// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"time"

	"vpnctl/internal/relaycatalog"
)

type PathStatus struct {
	PathID       string `json:"path_id"`
	State        string `json:"state"`
	PublicKey    string `json:"public_key,omitempty"`
	InnerAddress string `json:"inner_address,omitempty"`
}

// Report is safe to print. Prepared bindings prove only durable local key and
// approved IP ownership, never installed routes, private-key proof or uplink health.
type Report struct {
	ControllerID       string             `json:"controller_id,omitempty"`
	ObservedGeneration uint64             `json:"observed_generation"`
	SchemaVersion      int                `json:"schema_version"`
	NodeID             string             `json:"node_id"`
	Validity           string             `json:"validity"`
	Preparation        string             `json:"preparation"`
	UsableCache        bool               `json:"usable_cache"`
	BlockedReason      string             `json:"blocked_reason,omitempty"`
	Refresh            refreshState       `json:"refresh"`
	RetainedKeys       int                `json:"retained_keys"`
	RetiredKeys        int                `json:"retired_keys"`
	Paths              []PathStatus       `json:"paths"`
	Catalog            *relaycatalog.View `json:"catalog,omitempty"`
}

func MissingReport(node string) Report {
	return Report{SchemaVersion: 1, NodeID: node, Validity: "missing", Preparation: "empty", Refresh: refreshState{Result: "never"}, Paths: []PathStatus{}}
}

// Small clock corrections are tolerated, but cannot resurrect an expiry that
// this cache has already observed and durably recorded.
func (s *Store) currentTime() time.Time {
	now := s.now()
	if now.Before(s.state.ObservedAt) {
		return s.state.ObservedAt
	}
	return now
}
func (s *Store) clockRegressed() bool {
	return s.now().Add(30 * time.Second).Before(s.state.ObservedAt)
}
func (s *Store) Status() (Report, error) {
	if !s.mu.TryLock() {
		return busyReport(s.nodeID), ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return Report{}, osClosed()
	}
	if s.uncertain {
		return s.report(), ErrUncertain
	}
	// Persist a clock high-water mark: observing expiry must not be undone by a
	// later clock rollback, including after a process restart.
	if e := s.save(cloneState(s.state)); e != nil {
		return s.report(), e
	}
	return s.report(), nil
}
func (s *Store) report() Report {
	r := MissingReport(s.nodeID)
	r.ControllerID = s.state.ControllerID
	r.ObservedGeneration = s.state.Generation
	r.Refresh = s.state.Refresh
	r.BlockedReason = s.state.BlockedReason
	r.RetainedKeys = len(s.state.Keys)
	for _, k := range s.state.Keys {
		if k.Retired {
			r.RetiredKeys++
		}
	}
	if s.state.Catalog != nil {
		v := cloneView(*s.state.Catalog)
		r.Catalog = &v
		r.Validity = "valid"
		if s.clockRegressed() || v.IssuedAt.After(s.now().Add(30*time.Second)) {
			r.Validity = "clock_skew"
		} else if !s.currentTime().Before(v.ExpiresAt) {
			r.Validity = "expired"
		}
		wanted, prepared := 0, 0
		for _, p := range v.Spec.Paths {
			status := PathStatus{PathID: p.ID, State: "unbound"}
			if k, ok := s.key(p.ID); ok {
				status.State = "pending"
				status.PublicKey = k.PublicKey
				if k.Binding != nil {
					status.State = "bound"
					status.InnerAddress = k.Binding.InnerAddress
					if !p.Disabled && !p.Drain {
						prepared++
					}
				}
			}
			if p.Disabled {
				status.State = "disabled"
			} else if p.Drain {
				status.State = "draining"
			} else {
				wanted++
			}
			r.Paths = append(r.Paths, status)
		}
		r.Preparation = "partial"
		if wanted == 0 {
			r.Preparation = "empty"
		} else if prepared == wanted {
			r.Preparation = "complete"
		}
		r.UsableCache = r.Validity == "valid" && prepared > 0
	}
	if r.BlockedReason != "" || r.Validity != "valid" {
		r.UsableCache = false
		if r.Validity != "missing" {
			r.Preparation = "blocked"
		}
	}
	if s.state.Refresh.Result == "in_progress" {
		r.Preparation = "partial"
		r.UsableCache = false
	}
	if s.uncertain {
		r.Validity = "uncertain"
		r.Preparation = "blocked"
		r.UsableCache = false
	}
	return r
}

func busyReport(node string) Report {
	r := MissingReport(node)
	r.Validity = "busy"
	r.Preparation = "blocked"
	return r
}
