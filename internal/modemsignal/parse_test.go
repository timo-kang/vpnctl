// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package modemsignal

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1700000000, 0).UTC()

const fixture = "modem.signal.refresh-rate : 0\nmodem.signal.rssi-threshold : 3\nmodem.signal.error-rate-threshold : no\nmodem.signal.lte.rssi : -65.25\nmodem.signal.lte.rsrp : -90.00\nmodem.signal.lte.rsrq : --\nmodem.signal.lte.snr : 0.00\nmodem.signal.5g.rsrp : -95.10\nmodem.signal.5g.snr : 4.50\nmodem.generic.signal-quality.recent : yes\nmodem.3gpp.imei : PRIVATE_IMEI\nmodem.generic.own-numbers : PRIVATE_PHONE\n"

func TestCachedRFNeverInventsMeasurementTime(t *testing.T) {
	s := Parse(fixture, now)
	if err := s.Validate(now); err != nil {
		t.Fatal(err)
	}
	if s.State != "cached" || s.MeasurementTime != "unavailable" || s.RefreshRateSec == nil || *s.RefreshRateSec != 0 || s.RSSIThreshold == nil || *s.RSSIThreshold != 3 || s.ErrorRateThreshold == nil || *s.ErrorRateThreshold {
		t.Fatal("lost settings/time basis", s)
	}
	if s.LTE.SNR.Value == nil || *s.LTE.SNR.Value != 0 || s.LTE.SNR.State != "cached" || s.LTE.RSRQ.Value != nil || s.LTE.RSRQ.State != "missing" || *s.NR5G.RSRP.Value != -95.1 {
		t.Fatal("zero/missing/technology conflated", s)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "imei") || strings.Contains(string(raw), "recent") {
		t.Fatal("private/unrelated metadata leaked", string(raw))
	}
	lines := strings.Split(strings.TrimSpace(fixture), "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	if !reflect.DeepEqual(s, Parse(strings.Join(lines, "\n"), now)) {
		t.Fatal("order changed results")
	}
	fresh := s.Fresh(now.Add(time.Second), 2*time.Second)
	if fresh.ReadStale || fresh.LTE.SNR.State != "cached" || fresh.MeasurementTime != "unavailable" {
		t.Fatal("read became a live RF sample")
	}
	stale := s.Fresh(now.Add(2*time.Second), 2*time.Second)
	if !stale.ReadStale || !s.Fresh(now.Add(-time.Nanosecond), time.Second).ReadStale {
		t.Fatal("expiry/clockback ignored")
	}
	if !stale.Fresh(now, time.Hour).ReadStale {
		t.Fatal("stale source revived")
	}
	*fresh.LTE.SNR.Value = 9
	*fresh.RefreshRateSec = 30
	if *s.LTE.SNR.Value != 0 || *s.RefreshRateSec != 0 {
		t.Fatal("Fresh aliases source")
	}
}

func TestRFParserInvalidAndMissing(t *testing.T) {
	for _, v := range []string{"NaN", "Inf", "-Inf", "-1001", "1001", "text", "", "4,50"} {
		s := Parse("modem.signal.lte.snr : "+v, now)
		if s.State != "unknown" || s.LTE.SNR.State != "unknown" || s.LTE.SNR.Value != nil {
			t.Fatalf("bad value %q accepted: %+v", v, s)
		}
		if err := s.Validate(now); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"", "broken line", "modem.generic.signal-quality.recent : yes", "modem.signal.refresh-rate : -1", "modem.signal.refresh-rate : 4294967296", "modem.signal.error-rate-threshold : true", "modem.signal.lte.snr : 1\nmodem.signal.lte.snr : 2", "modem.signal.lte.snr : 1\nmodem.signal.lte.snr : 1"} {
		s := Parse(raw, now)
		if s.State != "unknown" || s.Reason != "invalid_output" {
			t.Fatal("malformed/ambiguous output accepted", s)
		}
	}
	s := Parse("modem.signal.refresh-rate : 0\nmodem.signal.lte.rsrq : --", now)
	if s.State != "missing" || s.LTE.RSRQ.Reason != "not_reported" {
		t.Fatal("missing declared zero/unsupported", s)
	}
	s = Parse(strings.Repeat("x", MaxOutputBytes+1), now)
	if s.Reason != "output_limit" {
		t.Fatal("oversized input accepted")
	}
	s = Parse("modem.signal.lte.rsrp : NaN\nmodem.signal.5g.snr : 1", now)
	if s.State != "cached" || s.LTE.RSRP.State != "unknown" || s.NR5G.SNR.Value == nil {
		t.Fatal("partial data lost", s)
	}
}

func TestRFAdmission(t *testing.T) {
	for _, mutate := range []func(*Snapshot){func(s *Snapshot) { s.Source = "invented" }, func(s *Snapshot) { s.MeasurementTime = "fresh" }, func(s *Snapshot) { s.ReadAt = now.Add(time.Nanosecond) }, func(s *Snapshot) { s.ReadAt = now.Add(-7 * 24 * time.Hour) }, func(s *Snapshot) { s.LTE.SNR.Value = nil }, func(s *Snapshot) { *s.LTE.SNR.Value = math.NaN() }, func(s *Snapshot) { s.State = "observed" }, func(s *Snapshot) { s.LTE.RSRQ.Value = new(float64) }, func(s *Snapshot) { s.ReadStale = true }} {
		s := Parse(fixture, now)
		mutate(&s)
		if s.Validate(now) == nil {
			t.Fatal("invalid snapshot admitted", s)
		}
	}
}

func TestRFRejectsContradictoryUnsupportedInterface(t *testing.T) {
	s := Parse(fixture, now)
	s.LTE.RSRQ = Value{State: "unsupported", Reason: "signal_interface_unsupported"}
	if s.Validate(now) == nil {
		t.Fatal("interface declared unsupported while cached RF values are present")
	}
}

func FuzzRFParser(f *testing.F) {
	f.Add(fixture)
	f.Add("modem.signal.lte.snr : --")
	f.Add("modem.signal.lte.snr : NaN")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > MaxOutputBytes+1 {
			return
		}
		s := Parse(raw, now)
		if err := s.Validate(now); err != nil {
			t.Fatal("parser emitted invalid evidence", err)
		}
		if !reflect.DeepEqual(s, Parse(raw, now)) {
			t.Fatal("nondeterminism")
		}
		if s.MeasurementTime != "unavailable" {
			t.Fatal("invented measurement time")
		}
		for _, v := range values(&s) {
			if v.Value != nil && v.State != "cached" {
				t.Fatal("invented freshness")
			}
		}
	})
}
