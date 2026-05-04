// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package peersource

import (
	"testing"
	"time"
)

// TestParseWgDump_BasicPeers verifies that two peers with valid data are parsed correctly.
func TestParseWgDump_BasicPeers(t *testing.T) {
	t.Parallel()

	dump := "" +
		"wg0\t(priv)\t(pub)\t51820\toff\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(psk)\t203.0.113.10:12345\t10.7.0.2/32\t1700000000\t1024\t2048\t25\n" +
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(psk)\t198.51.100.20:54321\t10.7.0.3/32\t1700001000\t512\t1024\toff\n"

	peers := parseWgDump(dump, 51900)

	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}

	// First peer
	p := peers[0]
	if p.PublicKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Errorf("peer[0] PublicKey=%q", p.PublicKey)
	}
	if p.Endpoint != "203.0.113.10:12345" {
		t.Errorf("peer[0] Endpoint=%q", p.Endpoint)
	}
	if p.VPNIP != "10.7.0.2" {
		t.Errorf("peer[0] VPNIP=%q", p.VPNIP)
	}
	if p.Name != "AAAAAAAA" {
		t.Errorf("peer[0] Name=%q", p.Name)
	}
	if p.ProbePort != 51900 {
		t.Errorf("peer[0] ProbePort=%d", p.ProbePort)
	}
	wantHandshake := time.Unix(1700000000, 0)
	if !p.LastHandshake.Equal(wantHandshake) {
		t.Errorf("peer[0] LastHandshake=%v want %v", p.LastHandshake, wantHandshake)
	}

	// Second peer
	p2 := peers[1]
	if p2.PublicKey != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" {
		t.Errorf("peer[1] PublicKey=%q", p2.PublicKey)
	}
	if p2.VPNIP != "10.7.0.3" {
		t.Errorf("peer[1] VPNIP=%q", p2.VPNIP)
	}
}

// TestParseWgDump_SkipsInvalidPeers verifies that peers with endpoint "(none)" are skipped.
func TestParseWgDump_SkipsInvalidPeers(t *testing.T) {
	t.Parallel()

	dump := "" +
		"wg0\t(priv)\t(pub)\t51820\toff\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(psk)\t(none)\t10.7.0.2/32\t0\t0\t0\toff\n" +
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(psk)\t0.0.0.0:0\t10.7.0.3/32\t0\t0\t0\toff\n" +
		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\t(psk)\t[::]:0\t10.7.0.4/32\t0\t0\t0\toff\n" +
		"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\t(psk)\t203.0.113.10:12345\t10.7.0.5/32\t1700000000\t0\t0\toff\n"

	peers := parseWgDump(dump, 51900)

	if len(peers) != 1 {
		t.Fatalf("expected 1 peer (valid), got %d", len(peers))
	}
	if peers[0].PublicKey != "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=" {
		t.Errorf("unexpected peer: %q", peers[0].PublicKey)
	}
}

// TestParseWgDump_ExtractsVPNIPFromSlash32 verifies that when multiple AllowedIPs are present,
// the /32 entry is preferred for VPNIP extraction.
func TestParseWgDump_ExtractsVPNIPFromSlash32(t *testing.T) {
	t.Parallel()

	// Peer has multiple AllowedIPs; the /32 should be preferred.
	dump := "" +
		"wg0\t(priv)\t(pub)\t51820\toff\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(psk)\t203.0.113.10:12345\t10.0.0.0/8,10.7.0.2/32,192.168.0.0/16\t1700000000\t0\t0\toff\n"

	peers := parseWgDump(dump, 51900)

	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].VPNIP != "10.7.0.2" {
		t.Errorf("VPNIP=%q, want 10.7.0.2", peers[0].VPNIP)
	}
}
