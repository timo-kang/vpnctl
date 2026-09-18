// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
)

const measurementRetention = 7 * 24 * time.Hour

// Envelope is the common identity and provenance contract for a measurement.
// Values are kept separate so a consumer can distinguish an observed sample
// from an inferred aggregate and preserve the unit explicitly.
type Envelope struct {
	NodeID      string    `json:"node_id"`
	Target      string    `json:"target,omitempty"`
	Relay       string    `json:"relay,omitempty"`
	Underlay    string    `json:"underlay,omitempty"`
	OverlayPath string    `json:"overlay_path,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Unit        string    `json:"unit"`
	Validity    string    `json:"validity"`
}

// Measurement carries the fields shared by RTT, loss, availability and
// transport diagnostics. Nil values mean unknown and must not be counted as 0.
type Measurement struct {
	Envelope
	Value           *float64 `json:"value,omitempty"`
	RTTMs           *float64 `json:"rtt_ms,omitempty"`
	JitterMs        *float64 `json:"jitter_ms,omitempty"`
	LossPct         *float64 `json:"loss_pct,omitempty"`
	AvailabilityPct *float64 `json:"availability_pct,omitempty"`
	HandshakeAgeSec *float64 `json:"handshake_age_sec,omitempty"`
	TransferRxBytes *uint64  `json:"transfer_rx_bytes,omitempty"`
	TransferTxBytes *uint64  `json:"transfer_tx_bytes,omitempty"`
}

func validEnvelopeLabel(value string, required bool) bool {
	if required && value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u007f' {
			return false
		}
	}
	return true
}

func finiteRange(value *float64, min, max float64) bool {
	return value == nil || !math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= min && *value <= max
}

func (m Measurement) Validate(now time.Time) error {
	if !validEnvelopeLabel(m.NodeID, true) || !validEnvelopeLabel(m.Target, false) || !validEnvelopeLabel(m.Relay, false) || !validEnvelopeLabel(m.Underlay, false) || !validEnvelopeLabel(m.OverlayPath, false) || !validEnvelopeLabel(m.Source, true) || !validEnvelopeLabel(m.Unit, true) || !validEnvelopeLabel(m.Validity, true) {
		return fmt.Errorf("invalid measurement envelope")
	}
	if m.Validity != "observed" && m.Validity != "inferred" && m.Validity != "unknown" {
		return fmt.Errorf("invalid measurement validity")
	}
	if m.Timestamp.IsZero() || m.Timestamp.After(now) || !m.Timestamp.After(now.Add(-measurementRetention)) {
		return fmt.Errorf("measurement timestamp outside retention")
	}
	if !finiteRange(m.Value, -math.MaxFloat64, math.MaxFloat64) || !finiteRange(m.RTTMs, 0, 60000) || !finiteRange(m.JitterMs, 0, 60000) || !finiteRange(m.LossPct, 0, 100) || !finiteRange(m.AvailabilityPct, 0, 100) || !finiteRange(m.HandshakeAgeSec, 0, 7*24*60*60) {
		return fmt.Errorf("measurement value outside range")
	}
	return nil
}
