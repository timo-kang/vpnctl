// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

// Package modemsignal reads ModemManager RF caches without changing modem
// settings. A read timestamp never establishes the age of the RF measurement.
package modemsignal

import (
	"fmt"
	"math"
	"time"
)

const Source = "modemmanager-signal"
const MaxOutputBytes = 64 << 10

type Value struct {
	State  string   `json:"state"` // cached, missing, unknown, unsupported
	Reason string   `json:"reason"`
	Value  *float64 `json:"value,omitempty"`
}
type Radio struct {
	RSSI Value `json:"rssi_dbm"`
	RSRP Value `json:"rsrp_dbm"`
	RSRQ Value `json:"rsrq_db"`
	SNR  Value `json:"snr_db"` // not SINR
}
type Snapshot struct {
	Source    string    `json:"source"`
	ReadAt    time.Time `json:"read_at"`
	ReadStale bool      `json:"read_stale"`
	// MeasurementTime is always "unavailable": mmcli has no per-RF event time.
	MeasurementTime    string  `json:"measurement_time"`
	State              string  `json:"state"`
	Reason             string  `json:"reason"`
	RefreshRateSec     *uint32 `json:"refresh_rate_sec,omitempty"`
	RSSIThreshold      *uint32 `json:"rssi_threshold_dbm,omitempty"`
	ErrorRateThreshold *bool   `json:"error_rate_threshold,omitempty"`
	LTE                Radio   `json:"lte"`
	NR5G               Radio   `json:"nr5g"`
}

func values(s *Snapshot) []*Value {
	return []*Value{&s.LTE.RSSI, &s.LTE.RSRP, &s.LTE.RSRQ, &s.LTE.SNR, &s.NR5G.RSSI, &s.NR5G.RSRP, &s.NR5G.RSRQ, &s.NR5G.SNR}
}
func unavailable(at time.Time, state, reason string) Snapshot {
	s := Snapshot{Source: Source, ReadAt: at.Round(0).UTC(), MeasurementTime: "unavailable", State: state, Reason: reason}
	for _, v := range values(&s) {
		*v = Value{State: state, Reason: reason}
	}
	return s
}
func MissingModem(at time.Time) Snapshot { return unavailable(at, "missing", "no_modem") }
func Unavailable(at time.Time) Snapshot  { return unavailable(at, "unknown", "collector_unavailable") }

func numeric(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= -1000 && v <= 1000 }
func validStateReason(state, reason string) bool {
	switch state {
	case "cached":
		return reason == "measurement_time_unknown"
	case "missing":
		return reason == "no_modem" || reason == "not_reported" || reason == "signals_not_reported"
	case "unsupported":
		return reason == "signal_interface_unsupported"
	case "unknown":
		switch reason {
		case "collector_unavailable", "invalid_output", "invalid_value", "signals_invalid", "canceled", "timeout", "output_limit", "invalid_modem_index":
			return true
		}
	}
	return false
}
func (s Snapshot) Validate(now time.Time) error {
	if s.Source != Source || s.MeasurementTime != "unavailable" || s.ReadAt.IsZero() || s.ReadAt.After(now) || !s.ReadAt.After(now.Add(-7*24*time.Hour)) || s.ReadStale || !validStateReason(s.State, s.Reason) {
		return fmt.Errorf("invalid modem signal snapshot")
	}
	cached := 0
	for _, v := range values(&s) {
		if !validStateReason(v.State, v.Reason) || (v.State == "cached") != (v.Value != nil) || v.Value != nil && !numeric(*v.Value) {
			return fmt.Errorf("invalid modem signal value")
		}
		if v.State == "cached" {
			cached++
		}
		if s.State == "missing" && v.State != "missing" || (s.State == "unsupported") != (v.State == "unsupported") {
			return fmt.Errorf("inconsistent modem signal state")
		}
	}
	if (s.State == "cached") != (cached > 0) {
		return fmt.Errorf("inconsistent modem signal availability")
	}
	return nil
}

// Fresh marks the age of the read, not the RF measurement. Even a non-stale read
// has cached RF values with unknown measurement age. Returned pointers detach.
func (s Snapshot) Fresh(now time.Time, maxAge time.Duration) Snapshot {
	s.ReadStale = s.ReadStale || maxAge <= 0 || now.Before(s.ReadAt) || now.Sub(s.ReadAt) >= maxAge
	for _, v := range values(&s) {
		if v.Value != nil {
			n := *v.Value
			v.Value = &n
		}
	}
	if s.RefreshRateSec != nil {
		n := *s.RefreshRateSec
		s.RefreshRateSec = &n
	}
	if s.RSSIThreshold != nil {
		n := *s.RSSIThreshold
		s.RSSIThreshold = &n
	}
	if s.ErrorRateThreshold != nil {
		n := *s.ErrorRateThreshold
		s.ErrorRateThreshold = &n
	}
	return s
}
