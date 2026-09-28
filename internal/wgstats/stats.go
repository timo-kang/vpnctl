// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package wgstats describes WireGuard device observations. These counters do not
// prove an application uplink, an underlay, or the route taken by any packet.
package wgstats

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const MaxPeers = 1024
const MaxGap = 90 * time.Second

// Counter is encoded as a decimal string: JSON numbers lose uint64 precision.
type Counter uint64

func (c Counter) MarshalJSON() ([]byte, error) { return []byte(fmt.Sprintf("\"%d\"", c)), nil }
func (c *Counter) UnmarshalJSON(b []byte) error {
	if len(b) < 3 || b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("counter must be a decimal string")
	}
	var n uint64
	for i, d := range b[1 : len(b)-1] {
		if d < '0' || d > '9' || (i == 0 && d == '0' && len(b) > 3) {
			return fmt.Errorf("invalid counter")
		}
		v := uint64(d - '0')
		if n > (^uint64(0)-v)/10 {
			return fmt.Errorf("counter overflow")
		}
		n = n*10 + v
	}
	*c = Counter(n)
	return nil
}
func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Sample is absolute kernel state. Generation identifies the collector session,
// interface incarnation and observed membership epoch, independently of TLS.
type Sample struct {
	ObservedAt time.Time  `json:"observed_at"`
	Generation string     `json:"generation"`
	Validity   string     `json:"validity"`
	Reason     string     `json:"reason"`
	Endpoint   bool       `json:"endpoint_available"`
	Handshake  *time.Time `json:"handshake"`
	RX         *Counter   `json:"rx_bytes"`
	TX         *Counter   `json:"tx_bytes"`
}

func (s Sample) Clone() Sample {
	if s.Handshake != nil {
		v := *s.Handshake
		s.Handshake = &v
	}
	if s.RX != nil {
		v := *s.RX
		s.RX = &v
	}
	if s.TX != nil {
		v := *s.TX
		s.TX = &v
	}
	return s
}
func (s Sample) Validate() error {
	if s.ObservedAt.IsZero() || s.ObservedAt.Year() < 2000 || s.ObservedAt.Year() > 9999 {
		return fmt.Errorf("invalid collection timestamp")
	}
	if s.Validity == "unknown" {
		switch s.Reason {
		case "file_source", "discovery_failed", "discovery_conflict", "interface_unavailable", "permission_denied", "invalid_dump", "command_failed":
		default:
			return fmt.Errorf("invalid collection failure")
		}
		if s.RX != nil || s.TX != nil || s.Handshake != nil || s.Generation != "" || s.Endpoint {
			return fmt.Errorf("unknown collection carries kernel data")
		}
		return nil
	}
	if s.Validity != "observed" || s.Reason != "" || len(s.Generation) != 32 || s.RX == nil || s.TX == nil {
		return fmt.Errorf("invalid kernel observation")
	}
	if _, err := hex.DecodeString(s.Generation); err != nil {
		return fmt.Errorf("invalid generation")
	}
	if s.Handshake != nil && (s.Handshake.IsZero() || s.Handshake.Year() < 1970 || s.Handshake.Year() > 9999) {
		return fmt.Errorf("invalid handshake")
	}
	return nil
}
func Unknown(at time.Time, reason string) Sample {
	return Sample{ObservedAt: at, Validity: "unknown", Reason: reason}
}

type View struct {
	Sample
	HandshakeState      string   `json:"handshake_state"`
	HandshakeAgeSeconds *float64 `json:"handshake_age_seconds"`
	RateValidity        string   `json:"rate_validity"`
	RateReason          string   `json:"rate_reason"`
	IntervalSeconds     *float64 `json:"interval_seconds"`
	RXDelta             *Counter `json:"rx_delta_bytes"`
	TXDelta             *Counter `json:"tx_delta_bytes"`
	RXPerSecond         *float64 `json:"rx_bytes_per_second"`
	TXPerSecond         *float64 `json:"tx_bytes_per_second"`
	Stale               bool     `json:"stale"`
}

func ptr[T any](v T) *T { return &v }
func Compare(current Sample, previous *Sample) View {
	v := View{Sample: current.Clone(), HandshakeState: "unknown", RateValidity: "unknown", RateReason: "first_sample"}
	if current.Validity != "observed" {
		v.RateReason = current.Reason
		return v
	}
	switch {
	case current.Handshake == nil:
		v.HandshakeState = "never"
	case current.Handshake.After(current.ObservedAt):
		v.HandshakeState = "clock_skew"
	default:
		v.HandshakeState = "observed"
		v.HandshakeAgeSeconds = ptr(current.ObservedAt.Sub(*current.Handshake).Seconds())
	}
	if previous == nil {
		return v
	}
	dt := current.ObservedAt.Sub(previous.ObservedAt)
	switch {
	case previous.Validity != "observed":
		v.RateReason = "collection_gap"
	case dt <= 0:
		v.RateReason = "clock_regressed"
	case current.Generation != previous.Generation:
		v.RateReason = "generation_changed"
	case dt > MaxGap:
		v.RateReason = "collection_gap"
	case current.RX == nil || current.TX == nil || previous.RX == nil || previous.TX == nil:
		v.RateReason = "missing_counter"
	case *current.RX < *previous.RX || *current.TX < *previous.TX:
		v.RateReason = "counter_reset"
	case previous.Handshake != nil && (current.Handshake == nil || current.Handshake.Before(*previous.Handshake)):
		v.RateReason = "handshake_regressed"
	case v.HandshakeState == "clock_skew" || (previous.Handshake != nil && previous.Handshake.After(previous.ObservedAt)):
		v.RateReason = "clock_skew"
	default:
		// Subtract integers BEFORE floating conversion, including above 2^53.
		rx, tx := *current.RX-*previous.RX, *current.TX-*previous.TX
		v.RateValidity = "inferred"
		v.RateReason = "polling_continuity_assumed"
		v.IntervalSeconds = ptr(dt.Seconds())
		v.RXDelta = &rx
		v.TXDelta = &tx
		v.RXPerSecond = ptr(float64(rx) / dt.Seconds())
		v.TXPerSecond = ptr(float64(tx) / dt.Seconds())
	}
	return v
}
func (v View) Fresh(now time.Time, ttl time.Duration) View {
	v.Sample = v.Sample.Clone()
	if now.Before(v.ObservedAt) || !now.Before(v.ObservedAt.Add(ttl)) {
		v.Stale = true
		v.HandshakeAgeSeconds = nil
		v.RateValidity = "unknown"
		v.RateReason = "stale"
		if now.Before(v.ObservedAt) {
			v.RateReason = "clock_regressed"
		}
		v.IntervalSeconds = nil
		v.RXDelta = nil
		v.TXDelta = nil
		v.RXPerSecond = nil
		v.TXPerSecond = nil
	} else if v.HandshakeState == "observed" && v.Handshake != nil {
		v.HandshakeAgeSeconds = ptr(now.Sub(*v.Handshake).Seconds())
	}
	return v
}
func (v View) Text() string {
	val := func(c *Counter) string {
		if c == nil {
			return "-"
		}
		return fmt.Sprint(*c)
	}
	rate := func(f *float64) string {
		if f == nil {
			return "-"
		}
		return fmt.Sprintf("%.1f", *f)
	}
	return fmt.Sprintf("WG %s hs=%s RX/TX(bytes)=%s/%s inferred(B/s)=%s/%s reason=%s stale=%t", v.Validity, v.HandshakeState, val(v.RX), val(v.TX), rate(v.RXPerSecond), rate(v.TXPerSecond), v.RateReason, v.Stale)
}

func (v View) Clone() View {
	v.Sample = v.Sample.Clone()
	if v.HandshakeAgeSeconds != nil {
		v.HandshakeAgeSeconds = ptr(*v.HandshakeAgeSeconds)
	}
	if v.IntervalSeconds != nil {
		v.IntervalSeconds = ptr(*v.IntervalSeconds)
	}
	if v.RXDelta != nil {
		v.RXDelta = ptr(*v.RXDelta)
	}
	if v.TXDelta != nil {
		v.TXDelta = ptr(*v.TXDelta)
	}
	if v.RXPerSecond != nil {
		v.RXPerSecond = ptr(*v.RXPerSecond)
	}
	if v.TXPerSecond != nil {
		v.TXPerSecond = ptr(*v.TXPerSecond)
	}
	return v
}
