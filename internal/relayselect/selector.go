// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package relayselect computes a desired target path from local, verified TCP
// observations. It never applies routes and never calls the controller.
package relayselect

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

type Policy struct {
	Version        int           `json:"version"`
	Mode           string        `json:"mode"`
	ManualPin      string        `json:"manual_pin,omitempty"`
	MaxCost        int           `json:"max_cost"` // -1 means unrestricted
	Successes      int           `json:"successes"`
	HoldDown       time.Duration `json:"hold_down_ns"`
	MinimumDwell   time.Duration `json:"minimum_dwell_ns"`
	MaxAge         time.Duration `json:"max_age_ns"`
	MaxConnectTime time.Duration `json:"max_connect_time_ns"`
}

func DefaultPolicy() Policy {
	return Policy{Version: 1, Mode: "auto", MaxCost: -1, Successes: 2, HoldDown: 15 * time.Second, MinimumDwell: 30 * time.Second, MaxAge: 10 * time.Second, MaxConnectTime: time.Second}
}
func (p Policy) Validate() error {
	if p.Version != 1 || p.Mode != "auto" && p.Mode != "manual" || (p.Mode == "manual") != (p.ManualPin != "") || len(p.ManualPin) > 64 || p.MaxCost < -1 || p.MaxCost > 65535 || p.Successes < 2 || p.Successes > 10 || p.HoldDown < time.Second || p.HoldDown > time.Hour || p.MinimumDwell < time.Second || p.MinimumDwell > time.Hour || p.MaxAge < time.Second || p.MaxAge > 30*time.Second || p.MaxConnectTime <= 0 || p.MaxConnectTime > 2*time.Second {
		return errors.New("invalid target selection policy")
	}
	return nil
}

type Candidate struct {
	relayobserve.TargetObservation
	ConsecutiveSuccesses int `json:"consecutive_successes"`
	// Diagnostic only: a fresh success arrived too late to continue the prior
	// confirmation sequence. It does not identify CPU load as the cause.
	ConfirmationGap time.Duration `json:"confirmation_gap_ns,omitempty"`
	Eligible        bool          `json:"eligible"`
	Exclusion       string        `json:"exclusion,omitempty"`
	Samples         int           `json:"connect_samples"`
	Failures        int           `json:"connect_failures"`
	// FailureFraction is a bounded 16-attempt TCP connect window, never packet loss.
	FailureFraction float64 `json:"connect_failure_fraction"`
}
type Decision struct {
	SchemaVersion          int                       `json:"schema_version"`
	ControllerID           string                    `json:"controller_id"`
	NodeID                 string                    `json:"node_id"`
	Generation             uint64                    `json:"generation"`
	TargetID               string                    `json:"target_id"`
	ObservedAt             time.Time                 `json:"observed_at"`
	ValidUntil             time.Time                 `json:"valid_until"`
	Policy                 Policy                    `json:"policy"`
	Applied                bool                      `json:"applied"`
	State                  string                    `json:"state"`
	Reason                 string                    `json:"reason"`
	DesiredPathID          string                    `json:"desired_path_id"`
	PreviousPathID         string                    `json:"previous_path_id,omitempty"`
	Changed                bool                      `json:"changed"`
	ChangedAt              time.Time                 `json:"changed_at,omitempty"`
	Candidates             []Candidate               `json:"candidates"`
	ObservationDiagnostics *relayobserve.Diagnostics `json:"observation_diagnostics,omitempty"`
}
type history struct {
	fingerprint        string
	underlayGeneration string
	observed           time.Time
	healthySince       time.Time
	successes          int
	attempts           []bool // true is failure
}
type Selector struct {
	policy                   Policy
	controller, node, target string
	generation               uint64
	approvalUntil            time.Time
	authorityStarted         time.Time
	authorityBoot            time.Duration
	authorityBudget          time.Duration
	lastBatch                time.Time
	histories                map[string]*history
	selected                 string
	changedAt                time.Time
	now                      func() time.Time
	boot                     func() (time.Duration, error)
}

func New(policy Policy) (*Selector, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Selector{policy: policy, histories: map[string]*history{}, now: time.Now, boot: bootTime}, nil
}

// MaxConnectTime is the immutable ceiling used by Decide. Actuators may stop
// waiting for a TCP connect that could no longer qualify, while retaining their
// full budgets for the surrounding ownership and transfer evidence.
func (s *Selector) MaxConnectTime() time.Duration { return s.policy.MaxConnectTime }

// ObservationExclusion identifies candidates that this immutable policy cannot
// select, even with perfect health. Skipping their socket proofs grants no
// eligibility; Decide still validates every observation and applies the policy.
func (s *Selector) ObservationExclusion(path string, cost int) string {
	if s.policy.Mode == "manual" && path != s.policy.ManualPin {
		return "manual_pin"
	}
	if s.policy.MaxCost >= 0 && cost > s.policy.MaxCost {
		return "cost_limit"
	}
	return ""
}

// RecordApplied anchors dwell to the actual verified change, including rollback.
// It grants no eligibility: the next Decide still needs fresh candidate evidence.
func (s *Selector) RecordApplied(path string, changedAt time.Time) {
	s.selected, s.changedAt = path, changedAt
}

func (s *Selector) Decide(report relayobserve.TargetReport) Decision {
	now := s.now()
	d := Decision{SchemaVersion: 1, ControllerID: report.ControllerID, NodeID: report.NodeID, Generation: report.Generation, TargetID: report.TargetID, ObservedAt: now, ValidUntil: now, Policy: s.policy, State: "blocked", Reason: "observation_unavailable", Candidates: []Candidate{}}
	d.ObservationDiagnostics = report.Diagnostics
	previous := s.selected
	finish := func(path, state, reason string) Decision {
		if path != s.selected {
			s.selected = path
			s.changedAt = now
		}
		d.DesiredPathID, d.State, d.Reason = path, state, reason
		d.Changed, d.ChangedAt = previous != path, s.changedAt
		if d.Changed {
			d.PreviousPathID = previous
		}
		return d
	}
	reject := func(reason string) Decision {
		s.histories = map[string]*history{}
		return finish("", "blocked", reason)
	}
	boot, err := s.boot()
	if err != nil || !report.Valid {
		return reject(reportReason(report.Reason, "observation_unavailable"))
	}
	if report.SchemaVersion != 1 || report.ControllerID == "" || report.NodeID == "" || report.TargetID == "" || report.Generation == 0 || len(report.Paths) == 0 || len(report.Paths) > relaycatalog.MaxPathsPerNode || report.StartedAt.After(report.ObservedAt) || report.ObservedAt.After(now) || now.Sub(report.ObservedAt) > s.policy.MaxAge || boot < report.BootTime || boot-report.BootTime > s.policy.MaxAge {
		return reject("invalid_or_stale_observation")
	}
	if s.controller != "" && (s.controller != report.ControllerID || s.node != report.NodeID || s.target != report.TargetID) {
		return reject("identity_changed_restart_required")
	}
	if s.generation > report.Generation {
		return reject("generation_regressed")
	}
	if !s.lastBatch.IsZero() && !report.StartedAt.After(s.lastBatch) {
		return reject("observation_replayed")
	}
	s.lastBatch = report.ObservedAt
	if s.generation != report.Generation {
		s.controller, s.node, s.target = report.ControllerID, report.NodeID, report.TargetID
		s.generation, s.approvalUntil = report.Generation, report.ApprovalUntil
		s.authorityStarted, s.authorityBoot, s.authorityBudget = now, boot, report.ApprovalUntil.Sub(now)
		s.histories = map[string]*history{}
		// Fresh authority needs consecutive proof again. Let finish withdraw
		// the prior selection so ChangedAt records this withdrawal, too.
	} else if !report.ApprovalUntil.Equal(s.approvalUntil) {
		return reject("approval_changed_without_generation")
	}
	// Neither restarting observation cycles nor a backwards wall clock extends
	// this grant. BOOTTIME also includes suspend. New authority needs a new generation.
	if !now.Before(s.approvalUntil) || now.Sub(s.authorityStarted) < 0 || now.Sub(s.authorityStarted) >= s.authorityBudget || boot < s.authorityBoot || boot-s.authorityBoot >= s.authorityBudget {
		return reject("approval_expired")
	}
	d.ValidUntil = now.Add(s.policy.MaxAge)
	if s.approvalUntil.Before(d.ValidUntil) {
		d.ValidUntil = s.approvalUntil
	}
	// Reflect the remaining monotonic/BOOTTIME budget in the exported validity too.
	remaining := min(s.authorityBudget-now.Sub(s.authorityStarted), s.authorityBudget-(boot-s.authorityBoot))
	if until := now.Add(remaining); until.Before(d.ValidUntil) {
		d.ValidUntil = until
	}
	seen := map[string]bool{}
	eligible := []Candidate{}
	unknown, failed := false, false
	for _, observation := range report.Paths {
		if observation.PathID == "" || seen[observation.PathID] || observation.Priority < 0 || observation.Priority > 65535 || observation.Cost < 0 || observation.Cost > 65535 {
			return reject("invalid_candidate_observation")
		}
		seen[observation.PathID] = true
		c := Candidate{TargetObservation: observation}
		h := s.histories[c.PathID]
		if h == nil || h.fingerprint != c.Fingerprint || h.underlayGeneration != c.UnderlayGeneration {
			h = &history{fingerprint: c.Fingerprint, underlayGeneration: c.UnderlayGeneration}
			s.histories[c.PathID] = h
		}
		switch {
		case c.State == "excluded":
			c.Exclusion = c.Reason
		case s.policy.Mode == "manual" && c.PathID != s.policy.ManualPin:
			c.Exclusion = "manual_pin"
		case s.policy.MaxCost >= 0 && c.Cost > s.policy.MaxCost:
			c.Exclusion = "cost_limit"
		case c.ObservedAt.Before(report.StartedAt) || c.ObservedAt.After(report.ObservedAt) || now.Sub(c.ObservedAt) > s.policy.MaxAge || !h.observed.IsZero() && !c.ObservedAt.After(h.observed):
			c.Exclusion = "stale_observation"
			unknown = true
		case c.State == "unknown":
			c.Exclusion = reportReason(c.Reason, "candidate_unknown")
			unknown = true
		case c.State == "unreachable":
			c.Exclusion = reportReason(c.Reason, "target_connect_failed")
			failed = true
			h.attempts = appendAttempt(h.attempts, true)
		case c.State != "reachable" || len(c.Fingerprint) != 64 || c.UnderlayGeneration != "" && len(c.UnderlayGeneration) != 64 || c.Handshake <= 0 || c.RXDelta == 0 || c.TXDelta == 0 || c.ConnectTime < 0:
			return reject("invalid_candidate_evidence")
		case c.ConnectTime > s.policy.MaxConnectTime:
			c.Exclusion = "connect_time_limit"
			failed = true
			h.attempts = appendAttempt(h.attempts, false)
		default:
			h.attempts = appendAttempt(h.attempts, false)
			// A gap or failed/unknown observation breaks continuous health.
			if !h.observed.IsZero() && c.ObservedAt.Sub(h.observed) > s.policy.MaxAge {
				if h.successes > 0 {
					c.ConfirmationGap = c.ObservedAt.Sub(h.observed)
				}
				h.successes = 0
				h.healthySince = time.Time{}
			}
			if h.successes == 0 {
				h.healthySince = now
			}
			h.successes = min(h.successes+1, s.policy.Successes)
			c.Eligible = h.successes >= s.policy.Successes
			if !c.Eligible {
				c.Exclusion = "confirming"
				unknown = true
			}
		}
		if c.Exclusion != "" && c.Exclusion != "confirming" {
			h.successes = 0
			h.healthySince = time.Time{}
		}
		h.observed = c.ObservedAt
		c.ConsecutiveSuccesses = h.successes
		c.Samples = len(h.attempts)
		for _, failure := range h.attempts {
			if failure {
				c.Failures++
			}
		}
		if c.Samples > 0 {
			c.FailureFraction = float64(c.Failures) / float64(c.Samples)
		}
		if c.Eligible {
			eligible = append(eligible, c)
			if until := c.ObservedAt.Add(s.policy.MaxAge); until.Before(d.ValidUntil) {
				d.ValidUntil = until
			}
		}
		d.Candidates = append(d.Candidates, c)
	}
	for id := range s.histories {
		if !seen[id] {
			delete(s.histories, id)
		}
	}
	slices.SortFunc(d.Candidates, func(a, b Candidate) int {
		if a.PathID < b.PathID {
			return -1
		}
		if a.PathID > b.PathID {
			return 1
		}
		return 0
	})
	if len(eligible) == 0 {
		if s.policy.Mode == "manual" {
			return finish("", "unavailable", "manual_pin_unavailable")
		}
		if unknown {
			if report.Reason == "observation_budget_exhausted" {
				return finish("", "unknown", report.Reason)
			}
			return finish("", "unknown", "candidate_evidence_incomplete")
		}
		if failed {
			return finish("", "no_verified_path", "target_connect_failed")
		}
		return finish("", "unavailable", "no_permitted_candidate")
	}
	slices.SortFunc(eligible, func(a, b Candidate) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		if a.Cost != b.Cost {
			return a.Cost - b.Cost
		}
		// Measured latency is a quality ceiling, not a noisy tie-breaker.
		if a.PathID < b.PathID {
			return -1
		}
		if a.PathID > b.PathID {
			return 1
		}
		return 0
	})
	best := eligible[0]
	if s.selected == "" {
		return finish(best.PathID, "selection_ready", "initial_selection")
	}
	current := slices.IndexFunc(eligible, func(c Candidate) bool { return c.PathID == s.selected })
	if current < 0 {
		return finish(best.PathID, "selection_ready", "selected_path_unavailable")
	}
	if best.PathID == s.selected {
		return finish(s.selected, "selection_ready", "selected_path_verified")
	}
	if now.Sub(s.changedAt) < s.policy.MinimumDwell {
		return finish(s.selected, "selection_ready", "minimum_dwell")
	}
	if now.Sub(s.histories[best.PathID].healthySince) < s.policy.HoldDown {
		return finish(s.selected, "selection_ready", "recovery_hold_down")
	}
	return finish(best.PathID, "selection_ready", "preferred_path_recovered")
}
func appendAttempt(v []bool, failure bool) []bool {
	if len(v) == 16 {
		copy(v, v[1:])
		v = v[:15]
	}
	return append(v, failure)
}
func reportReason(reason, fallback string) string {
	if reason != "" {
		return reason
	}
	return fallback
}
func (d Decision) Error() error {
	if d.DesiredPathID == "" {
		return fmt.Errorf("target selection: %s", d.Reason)
	}
	return nil
}
