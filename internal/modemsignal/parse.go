// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package modemsignal

import (
	"strconv"
	"strings"
	"time"
)

// Parse accepts mmcli --signal-get --output-keyvalue with LC_ALL=C. Only fixed
// RF/settings keys survive; unknown metadata is discarded. Missing keys/"--"
// do not prove unsupported hardware or a numeric zero.
func Parse(raw string, readAt time.Time) Snapshot {
	bad := func() Snapshot { return unavailable(readAt, "unknown", "invalid_output") }
	if len(raw) > MaxOutputBytes {
		return unavailable(readAt, "unknown", "output_limit")
	}
	s := unavailable(readAt, "missing", "not_reported")
	s.Reason = "signals_not_reported"
	keys := []string{"modem.signal.lte.rssi", "modem.signal.lte.rsrp", "modem.signal.lte.rsrq", "modem.signal.lte.snr", "modem.signal.5g.rssi", "modem.signal.5g.rsrp", "modem.signal.5g.rsrq", "modem.signal.5g.snr"}
	fields := values(&s)
	index := map[string]int{}
	for i, k := range keys {
		index[k] = i
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return bad()
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		i, rf := index[key]
		setting := key == "modem.signal.refresh-rate" || key == "modem.signal.rssi-threshold" || key == "modem.signal.error-rate-threshold"
		if !rf && !setting {
			continue
		}
		if seen[key] {
			return bad()
		}
		seen[key] = true
		if value == "--" {
			continue
		}
		if rf {
			n, err := strconv.ParseFloat(value, 64)
			if err != nil || !numeric(n) {
				*fields[i] = Value{State: "unknown", Reason: "invalid_value"}
				continue
			}
			*fields[i] = Value{State: "cached", Reason: "measurement_time_unknown", Value: &n}
			continue
		}
		if key == "modem.signal.error-rate-threshold" {
			if value != "yes" && value != "no" {
				return bad()
			}
			enabled := value == "yes"
			s.ErrorRateThreshold = &enabled
		} else {
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return bad()
			}
			v := uint32(n)
			if key == "modem.signal.refresh-rate" {
				s.RefreshRateSec = &v
			} else {
				s.RSSIThreshold = &v
			}
		}
	}
	if len(seen) == 0 {
		return bad()
	}
	for _, v := range fields {
		if v.State == "unknown" {
			s.State, s.Reason = "unknown", "signals_invalid"
		}
	}
	for _, v := range fields {
		if v.State == "cached" {
			s.State, s.Reason = "cached", "measurement_time_unknown"
		}
	}
	return s
}
