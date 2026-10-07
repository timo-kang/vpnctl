//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"os"
	"strings"
	"testing"
)

func TestDirectFaultModeIsExplicitAndDefaultsToOriginalOuterDrop(t *testing.T) {
	for _, raw := range []string{"", "outer-wg", "inner-nonce"} {
		mode, err := directFaultMode(raw)
		if err != nil || raw == "" && mode != "outer-wg" || raw != "" && mode != raw {
			t.Fatal("fault mode changed", mode, err)
		}
	}
	for _, raw := range []string{"all", "inner", "outer-wg,inner-nonce"} {
		if _, err := directFaultMode(raw); err == nil {
			t.Fatal("ambiguous fault selection accepted")
		}
	}
}

func TestDirectInnerFaultPreservesHandshakeAndEmptyTransport(t *testing.T) {
	got, err := directFaultRules("inner-nonce", "192.0.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, " drop") != 1 || !strings.Contains(got, "@th,64,32 0x04000000 udp length > 40 counter name payload_drop drop") {
		t.Fatal("inner fault must drop only nonempty type-4 transport")
	}
	for _, name := range []string{"payload_drop", "keepalive_tx", "keepalive_rx", "handshake_rx"} {
		if !strings.Contains(got, "counter "+name+" {") || !strings.Contains(got, "counter name "+name) {
			t.Fatal("missing live fault counter", name)
		}
	}
	if !strings.Contains(got, "udp length 40 counter name keepalive_rx") || !strings.Contains(got, "@th,64,8 { 1, 2 } counter name handshake_rx") || strings.Contains(got, "51900") {
		t.Fatal("fault interferes with handshake, keepalive, or underlay readiness")
	}
	outer, err := directFaultRules("outer-wg", "192.0.2.3")
	if err != nil || !strings.Contains(outer, "ip daddr 192.0.2.3 udp dport 51820 drop") || strings.Contains(outer, "@th") {
		t.Fatal("original outer WG fault changed", err)
	}
	if _, err := directFaultRules("inner-nonce", "192.0.2.3; flush ruleset"); err == nil {
		t.Fatal("non-address accepted")
	}
}

func TestDirectTransportSummaryExcludesIdentityAndRequiresCurrentPeer(t *testing.T) {
	got, err := directTransportSummary("peer", "foreign\t123\npeer\t456\n", "foreign\t999\t999\npeer\t32\t64\n")
	if err != nil || got.Handshake != 456 || got.RX != 32 || got.TX != 64 {
		t.Fatal(got, err)
	}
	if _, err := directTransportSummary("missing", "peer\t456\n", "peer\t32\t64\n"); err == nil {
		t.Fatal("missing peer counted as authenticated")
	}
	if _, err := directTransportSummary("peer", "peer\t456\npeer\t456\n", "peer\t32\t64\n"); err == nil {
		t.Fatal("duplicate peer observation accepted")
	}
}

func TestDirectInnerFaultCounterEvidenceRequiresEveryNamedCounter(t *testing.T) {
	text := `{"nftables":[{"counter":{"family":"inet","table":"direct_fault","name":"payload_drop","packets":1}},{"counter":{"family":"inet","table":"direct_fault","name":"keepalive_tx","packets":2}},{"counter":{"family":"inet","table":"direct_fault","name":"keepalive_rx","packets":3}},{"counter":{"family":"inet","table":"direct_fault","name":"handshake_rx","packets":4}}]}`
	got, err := directFaultCounters([]byte(text))
	if err != nil || got["payload_drop"] != 1 || got["keepalive_rx"] != 3 || len(got) != 4 {
		t.Fatal(got, err)
	}
	for _, raw := range []string{`{}`, `{"nftables":[]}`, strings.Replace(text, `"packets":3`, `"packets":0`, 1), strings.Replace(text, `"name":"handshake_rx"`, `"name":"keepalive_rx"`, 1)} {
		if _, err := directFaultCounters([]byte(raw)); err == nil {
			t.Fatal("missing, zero, or duplicate counter accepted")
		}
	}
}

func TestDirectOptionalGlobalSocketDiagnosticRecordsAvailability(t *testing.T) {
	missing := directSocketDiagnostic(func(path string) ([]byte, error) {
		if path != "/proc/sys/net/core/wmem_max" {
			t.Fatal("unexpected diagnostic path", path)
		}
		return nil, os.ErrNotExist
	})
	if missing["available"] != false || missing["error"] == "" || missing["scope"] != "kernel_global" {
		t.Fatal("missing optional global sysctl was hidden", missing)
	}
	present := directSocketDiagnostic(func(string) ([]byte, error) { return []byte("212992\n"), nil })
	if present["available"] != true || present["value"] != "212992" {
		t.Fatal("available global sysctl was omitted", present)
	}
}
