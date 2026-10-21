// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"vpnctl/internal/uplinkapi"
)

var (
	errFrame  = errors.New("invalid uplink frame")
	idPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	hexID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	domainID  = regexp.MustCompile(`^v1:[0-9a-f]{64}$`)
	fieldName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Check duplicate keys and depth before Go's permissive struct decoder. The
// byte bound also bounds unknown additive fields; names remain case-sensitive.
func checkJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errFrame
	}
	token, err := d.Token()
	if err != nil {
		return errFrame
	}
	if number, ok := token.(json.Number); ok && number == "-0" {
		return errFrame
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errFrame
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || !fieldName.MatchString(name) || seen[name] {
				return errFrame
			}
			seen[name] = true
		}
		if err := checkJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func canonicalUint(raw json.RawMessage, quoted, required bool) error {
	if len(raw) == 0 {
		if required {
			return errFrame
		}
		return nil
	}
	v := string(raw)
	if quoted {
		if len(v) < 3 || v[0] != '"' || json.Unmarshal(raw, &v) != nil {
			return errFrame
		}
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != v {
		return errFrame
	}
	return nil
}

func decodeFrame(raw []byte, target string) (uplinkapi.Frame, error) {
	var f uplinkapi.Frame
	if len(raw) > uplinkapi.MaxRecordBytes || !utf8.Valid(raw) {
		return f, errFrame
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if checkJSON(d, 0) != nil {
		return f, errFrame
	}
	if _, err := d.Token(); err != io.EOF {
		return f, errFrame
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || json.Unmarshal(raw, &f) != nil {
		return f, errFrame
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(root["snapshot"], &fields) != nil {
		return f, errFrame
	}
	s := f.Snapshot
	parts := strings.Split(f.Cursor, ":")
	if f.SchemaVersion != 1 || s.SchemaVersion != 1 || (f.Type != "snapshot" && f.Type != "reset") || len(parts) != 2 || !hexID.MatchString(parts[0]) || canonicalUint(json.RawMessage(parts[1]), false, true) != nil || parts[1] == "0" {
		return f, errFrame
	}
	for _, key := range []string{"target_id", "producer_id", "availability", "freshness", "reason", "clock_domain", "session_continuity"} {
		v := fields[key]
		if len(v) == 0 || v[0] != '"' {
			return f, errFrame
		}
	}
	for _, key := range []string{"path_id", "evidence"} {
		if v := fields[key]; len(v) > 0 && v[0] != '"' {
			return f, errFrame
		}
	}
	for _, key := range []string{"revision", "path_revision", "observed_boot_ns", "valid_until_boot_ns"} {
		if canonicalUint(fields[key], true, key == "revision" || key == "path_revision") != nil {
			return f, errFrame
		}
	}
	if canonicalUint(fields["remaining_validity_ms"], false, true) != nil || canonicalUint(fields["observed_age_ms"], false, false) != nil {
		return f, errFrame
	}
	if s.TargetID != target || !hexID.MatchString(s.ProducerID) || s.Revision == 0 || !domainID.MatchString(s.ClockDomain) || s.SessionContinuity != "not_established" {
		return f, errFrame
	}
	if s.Freshness == "fresh" {
		if s.ObservedBootNS == 0 || s.ValidUntilBootNS <= s.ObservedBootNS || s.ValidUntilBootNS-s.ObservedBootNS > 30_000_000_000 {
			return f, errFrame
		}
		switch s.Availability {
		case "reachable":
			if !idPattern.MatchString(s.PathID) || s.PathRevision == 0 || s.Evidence != "unbound_tcp_connect" || s.Reason != "unbound_tcp_connect_verified" {
				return f, errFrame
			}
		case "unreachable":
			if s.PathID != "" || s.Evidence != "bound_tcp_connect" || s.Reason != "approved_candidates_unreachable" {
				return f, errFrame
			}
		case "blocked":
			if s.PathID != "" || s.Evidence != "" || s.Reason != "approval_denied_or_expired" {
				return f, errFrame
			}
		default:
			return f, errFrame
		}
	} else {
		if (s.Freshness != "unknown" && s.Freshness != "stale") || s.Availability != "unknown" || s.PathID != "" || s.Evidence != "" {
			return f, errFrame
		}
		switch s.Reason {
		case "observation_unavailable", "clock_unavailable", "revision_exhausted", "observation_expired", "observation_invalidated":
		default:
			return f, errFrame
		}
	}
	return f, nil
}

func stableFrame(f uplinkapi.Frame) string {
	f.Snapshot.ObservedAgeMS = nil
	f.Snapshot.RemainingValidityMS = 0
	f.Type = ""
	b, _ := json.Marshal(f)
	return string(b)
}
