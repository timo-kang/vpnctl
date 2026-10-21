// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package predictorinput builds bounded, event-time predictor inputs from
// measured data. It neither collects data nor establishes route authority.
package predictorinput

import (
	"errors"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/predictor"
)

const MaxSamples = history.MaxWindowSamples
const MaxWindow = 2 * time.Minute

var ErrInvalid = errors.New("invalid predictor input")

// Config is explicit: the source cadence and the model must determine the
// freshness budget. Reading or replaying data never refreshes its timestamps.
type Config struct {
	RTTWindow  time.Duration
	LossWindow time.Duration
	Bucket     time.Duration
	MaxAge     time.Duration
}

// Feature distinguishes a measured zero from missing, unknown or stale input.
// InputCount includes UnknownCount; neither counts delivery duplicates.
// ObservedAt/AgeNS describe the latest source sample, even when unusable.
type Feature struct {
	Source       string     `json:"source"`
	State        string     `json:"state"`
	Reason       string     `json:"reason,omitempty"`
	ObservedAt   *time.Time `json:"observed_at,omitempty"`
	AgeNS        *int64     `json:"age_ns,omitempty"`
	InputCount   int        `json:"input_count"`
	UnknownCount int        `json:"unknown_count"`
}

type Result struct {
	Stream      history.Stream
	Observation predictor.Observation
	Features    [predictor.SignalCount]Feature
	Ready       bool // at least one measured network dimension; not model warmup/accuracy
	Reason      string
}
