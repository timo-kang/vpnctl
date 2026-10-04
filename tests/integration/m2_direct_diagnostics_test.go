//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const soakDirectRecordLimit = 512

// This is an output allowlist, not an error/log passthrough. Values from input
// are never copied, except timestamps accepted by the RFC3339 parser.
var soakDirectVocabulary = map[string]string{
	"active": "state=active ", "probing": "state=probing ",
	"cooldown": "state=cooldown ", "relay_unverified": "state=relay_unverified ",
	"reason_overlay_probe_failed":               "reason=overlay_probe_failed ",
	"reason_overlay_probe_timeout":              "reason=overlay_probe_timeout ",
	"reason_overlay_probe_failed_no_handshake":  "reason=overlay_probe_failed_no_handshake ",
	"reason_overlay_probe_timeout_no_handshake": "reason=overlay_probe_timeout_no_handshake ",
	"reason_direct_traffic_not_observed":        "reason=direct_traffic_not_observed ",
	"reason_direct_handshake_missing":           "reason=direct_handshake_missing ",
	"reason_candidate_changed":                  "reason=candidate_changed ",
	"reason_candidate_withdrawn":                "reason=candidate_withdrawn ",
	"reason_relay_baseline_unverified":          "reason=relay_baseline_unverified ",
	"engine_unavailable":                        "direct dataplane unavailable",
	"recovery_blocked":                          "direct recovery blocked",
	"verification_blocked":                      "direct dataplane blocked",
	"tunnel_restore_failed":                     "restore cached tunnel failed",
	"baseline_config_changed":                   "direct baseline configuration changed",
	"interface_key_conflict":                    "interface public key conflict",
	"journal_identity_conflict":                 "direct journal interface identity conflict",
	"peer_ownership_conflict":                   "direct peer ownership conflict",
	"invalid_journal":                           "invalid direct journal",
	"foreign_peer_conflict":                     "unowned direct peer already exists",
	"relay_baseline_changed":                    "relay baseline changed",
}

type soakDirectRecord struct {
	At    time.Time `json:"at"`
	Codes []string  `json:"codes"`
}

type soakDirectDiagnostics struct {
	Counts         map[string]int     `json:"counts"`
	Records        []soakDirectRecord `json:"records"`
	DroppedRecords int                `json:"dropped_records"`
	UnparsedTimes  int                `json:"unparsed_times"`
	ReadIncomplete bool               `json:"read_incomplete"`
}

func collectSoakDirectDiagnostics(r io.Reader) soakDirectDiagnostics {
	d := soakDirectDiagnostics{Counts: map[string]int{}, Records: []soakDirectRecord{}}
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		// A trailing space also matches a final reason=... field. Previously
		// such end-of-line fields were silently omitted from reason counts.
		line := scan.Text() + " "
		var codes []string
		for code, literal := range soakDirectVocabulary {
			if strings.Contains(line, literal) {
				d.Counts[code]++
				codes = append(codes, code)
			}
		}
		if len(codes) == 0 {
			continue
		}
		prefix, _, _ := strings.Cut(line, " ")
		stamp, err := time.Parse(time.RFC3339Nano, strings.TrimPrefix(prefix, "time="))
		if !strings.HasPrefix(prefix, "time=") || err != nil {
			d.UnparsedTimes++
			continue
		}
		sort.Strings(codes)
		record := soakDirectRecord{At: stamp.UTC(), Codes: codes}
		if len(d.Records) == soakDirectRecordLimit {
			copy(d.Records, d.Records[1:])
			d.Records[len(d.Records)-1] = record
			d.DroppedRecords++
		} else {
			d.Records = append(d.Records, record)
		}
	}
	d.ReadIncomplete = scan.Err() != nil
	return d
}

func writeSoakDirectDiagnostics(t *testing.T, dir, results string, size int) {
	t.Helper()
	counts := map[string]map[string]int{}
	timelines := map[string]soakDirectDiagnostics{}
	for n := 0; n < size; n++ {
		f, err := os.Open(filepath.Join(dir, fmt.Sprintf("node-%d.log", n)))
		if err != nil {
			continue
		}
		d := collectSoakDirectDiagnostics(f)
		f.Close()
		alias := strconv.Itoa(n)
		counts[alias], timelines[alias] = d.Counts, d
	}
	for name, value := range map[string]any{
		"direct-diagnostic-counts.json":   counts,
		"direct-diagnostic-timeline.json": timelines,
	} {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Error(err)
			continue
		}
		path := filepath.Join(results, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Error(err)
		} else {
			exposeSoakArtifact(t, path)
		}
	}
}

func TestSoakDirectDiagnosticsAllowlistAndBounds(t *testing.T) {
	var raw bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&raw, nil))
	for n := 0; n < soakDirectRecordLimit+5; n++ {
		logger.Info("direct dataplane", "peer", "secret-identity", "state", "relay_unverified", "reason", "overlay_probe_timeout_no_handshake", "generation", "secret-generation")
	}
	logger.Info("direct dataplane", "peer", "secret-last-peer", "state", "pending", "reason", "candidate_changed")
	logger.Warn("direct dataplane blocked", "err", "private-key secret-error 192.0.2.10:51820")
	d := collectSoakDirectDiagnostics(&raw)
	if len(d.Records) != soakDirectRecordLimit || d.DroppedRecords != 7 || d.ReadIncomplete || d.UnparsedTimes != 0 {
		t.Fatal("bounded complete records were not retained")
	}
	if d.Counts["reason_overlay_probe_timeout_no_handshake"] != soakDirectRecordLimit+5 || d.Counts["reason_overlay_probe_timeout"] != 0 || d.Counts["reason_candidate_changed"] != 1 || d.Counts["verification_blocked"] != 1 {
		t.Fatal("specific/end-of-line reason counts lost or conflated")
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "private-key", "192.0.2", "generation", "peer="} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("raw field escaped diagnostic allowlist")
		}
	}
	for _, record := range d.Records {
		if record.At.IsZero() {
			t.Fatal("missing parsed timestamp")
		}
		for _, code := range record.Codes {
			if _, ok := soakDirectVocabulary[code]; !ok {
				t.Fatal("unlisted output code")
			}
		}
	}
	bad := collectSoakDirectDiagnostics(strings.NewReader("time=private-key state=active\n" + strings.Repeat("x", 70<<10)))
	if !bad.ReadIncomplete || bad.UnparsedTimes != 1 || len(bad.Records) != 0 || bad.Counts["active"] != 1 {
		t.Fatal("invalid/oversized input was reported as complete")
	}
}
