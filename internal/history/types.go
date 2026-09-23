// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package history owns the controller's measured fleet history. It deliberately
// has no dependency on the registry, HTTP, WireGuard or deployment layout.
package history

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vpnctl/internal/quality"
)

const (
	Retention        = 7 * 24 * time.Hour
	MaxBatch         = 256
	MaxRows          = 4_000_000
	MaxStreams       = 256
	MaxNodeStreams   = 16
	MaxWindowSamples = 1200 // replay of two minutes, at most 10 Hz per stream
	QueryTimeout     = 8 * time.Second
)

var (
	ErrInvalid  = errors.New("invalid history observation")
	ErrConflict = errors.New("sample ID reused with different content")
	ErrCapacity = errors.New("history capacity reached")
)

// QuotaError identifies a rejected probe batch whose logical storage budget is
// exhausted. It deliberately excludes temporary WAL/lock/IO backpressure.
// ErrCapacity remains the compatibility umbrella for existing storage callers.
type QuotaError struct {
	Resource string
	Limit    int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("%s: %s limit %d", ErrCapacity, e.Resource, e.Limit)
}
func (e *QuotaError) Unwrap() error { return ErrCapacity }

// Observation is one probe outcome, including an explicit unavailable observation.
// Path/relay/uplink are reporter claims, not independently verified route state.
type Observation struct {
	ID        string    `json:"id"`
	Source    string    `json:"source,omitempty"`
	Validity  string    `json:"validity,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	PeerID    string    `json:"peer_id"`
	Path      string    `json:"path"`
	RelayID   string    `json:"relay_id,omitempty"`
	Uplink    string    `json:"uplink,omitempty"`
	Success   *bool     `json:"success"`
	RTTMs     *float64  `json:"rtt_ms"`
}

type Stream struct {
	Source  string `json:"source"`
	NodeID  string `json:"node_id"`
	PeerID  string `json:"peer_id"`
	Path    string `json:"path"`
	RelayID string `json:"relay_id"`
	Uplink  string `json:"uplink"`
}

type Measurement struct {
	Stream
	quality.PeerQuality
	Validity string `json:"validity"`
	Reason   string `json:"reason"`
}

type Bucket struct {
	Stream
	Time            time.Time `json:"time"` // lower, exclusive edge; upper edge is time + width
	Count           int       `json:"sample_count"`
	UnknownCount    int       `json:"unknown_count"`
	Successes       int       `json:"success_count"`
	AvailabilityPct *float64  `json:"availability_pct"` // successes / attempts, not wall-time uptime
	AvgRTTMs        *float64  `json:"avg_rtt_ms"`
	P95RTTMs        *float64  `json:"p95_rtt_ms"` // exact nearest-rank percentile of successful probes
	LossPct         *float64  `json:"loss_pct"`
}

func validLabel(s string, required bool) bool {
	if !utf8.ValidString(s) || len(s) > 128 || (required && s == "") || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u007f' {
			return false
		}
	}
	return true
}
func Validate(node string, o Observation, now time.Time) error {
	if !validLabel(node, true) || !validLabel(o.ID, true) || !validLabel(o.PeerID, true) || !validLabel(o.RelayID, false) || !validLabel(o.Uplink, false) {
		return fmt.Errorf("%w: invalid identity/label", ErrInvalid)
	}
	if o.Path != "direct" && o.Path != "relay" && o.Path != "unknown" {
		return fmt.Errorf("%w: path must be direct, relay or unknown", ErrInvalid)
	}
	if o.Path == "direct" && o.RelayID != "" {
		return fmt.Errorf("%w: direct path cannot claim a relay", ErrInvalid)
	}
	if o.Timestamp.IsZero() || o.Timestamp.After(now) || !o.Timestamp.After(now.Add(-Retention)) {
		return fmt.Errorf("%w: timestamp must be in (now-7d, now]", ErrInvalid)
	}
	switch o.Source {
	case "", "legacy-probe", "cli-ping", "agent-direct", "monitor-overlay":
	default:
		return fmt.Errorf("%w: unsupported probe source", ErrInvalid)
	}
	if o.Source == "agent-direct" && o.Path != "direct" {
		return fmt.Errorf("%w: candidate probe requires direct path", ErrInvalid)
	}
	if o.Success != nil && *o.Success && o.Reason != "" {
		return fmt.Errorf("%w: successful probe cannot carry an error reason", ErrInvalid)
	}
	if !validLabel(o.Reason, false) || len(o.Reason) > 64 {
		return fmt.Errorf("%w: invalid probe reason", ErrInvalid)
	}
	if o.Success == nil {
		if o.Validity != "unknown" || o.Reason == "" || o.RTTMs != nil {
			return fmt.Errorf("%w: unknown requires reason and null success/RTT", ErrInvalid)
		}
	} else if o.Validity != "" && o.Validity != "observed" {
		return fmt.Errorf("%w: completed probe requires observed validity", ErrInvalid)
	}
	if o.Success != nil && ((*o.Success && o.RTTMs == nil) || (!*o.Success && o.RTTMs != nil)) {
		return fmt.Errorf("%w: success requires RTT; failure requires null RTT", ErrInvalid)
	}
	if o.RTTMs != nil && (math.IsNaN(*o.RTTMs) || math.IsInf(*o.RTTMs, 0) || *o.RTTMs < 0 || *o.RTTMs > 60_000) {
		return fmt.Errorf("%w: RTT must be finite and in [0,60000] ms", ErrInvalid)
	}
	return nil
}
func FormatNumber(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%.2f", *v)
}
func pointer[T any](v T) *T { return &v }

// Storage is the controller-facing persistence/query boundary. The implementation
// owns retention and publishes detached status only after a successful commit.
type Storage interface {
	Ingest(context.Context, string, []Observation, time.Time) error
	Latest(time.Time) map[string][]Measurement
	Query(context.Context, string, time.Time, time.Duration, time.Duration) ([]Bucket, error)
	Maintain(context.Context, time.Time) error
}

var _ Storage = (*Store)(nil)

// Canonicalize preserves compatibility with the original completed-probe API.
func (o Observation) Canonicalize() Observation {
	if o.Source == "" {
		o.Source = "legacy-probe"
	}
	if o.Validity == "" && o.Success != nil {
		o.Validity = "observed"
	}
	o.Timestamp = o.Timestamp.UTC().Truncate(time.Microsecond)
	return o
}
