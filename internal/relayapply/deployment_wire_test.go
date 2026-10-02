// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"strings"
	"testing"
)

func TestDeploymentWireSnapshotValidation(t *testing.T) {
	const secret = "must-never-appear-in-an-error"
	e := DeploymentEntry{PublicKey: public("relay"), ListenPort: 51820, Peers: []DeploymentPeer{{PublicKey: public("peer"), Address: "10.78.0.1/32"}}}
	header := secret + "\t" + e.PublicKey + "\t51820\toff\n"
	peer := e.Peers[0].PublicKey + "\t(none)\t192.0.2.4:51820\t10.78.0.1/32\t123\t456\t789\toff\n"
	for _, tc := range []struct {
		name, text      string
		ready, conflict bool
	}{
		{"complete", header + peer, true, false},
		{"roaming", header + strings.ReplaceAll(peer, "192.0.2.4:51820", "[2001:db8::4]:51821"), true, false},
		{"unlearned-endpoint", header + strings.ReplaceAll(peer, "192.0.2.4:51820", "(none)"), true, false},
		{"missing-peer", header, false, false},
		{"unconfigured", "(none)\t(none)\t0\toff\n", false, false},
		{"missing-allowed", header + strings.ReplaceAll(peer, "10.78.0.1/32", "(none)"), false, false},
		{"duplicate-peer", header + peer + peer, false, true},
		{"unexpected-peer", header + strings.ReplaceAll(peer, e.Peers[0].PublicKey, public("foreign")), false, true},
		{"wrong-public", strings.ReplaceAll(header, e.PublicKey, public("foreign")) + peer, false, true},
		{"wrong-port", strings.ReplaceAll(header, "51820", "51821") + peer, false, true},
		{"wrong-mark", strings.ReplaceAll(header, "off", "0x42") + peer, false, true},
		{"psk", header + strings.Replace(peer, "(none)", secret, 1), false, true},
		{"keepalive", header + strings.ReplaceAll(peer, "off", "25"), false, true},
		{"broader-allowed", header + strings.ReplaceAll(peer, "10.78.0.1/32", "10.78.0.0/24"), false, true},
		{"extra-allowed", header + strings.ReplaceAll(peer, "10.78.0.1/32", "10.78.0.1/32,0.0.0.0/0"), false, true},
		{"extra-header", strings.TrimSpace(header) + "\textra\n" + peer, false, true},
		{"short-header", secret + "\n" + peer, false, true},
		{"short-peer", header + e.Peers[0].PublicKey + "\n", false, true},
		{"extra-peer-column", header + strings.TrimSpace(peer) + "\textra\n", false, true},
		{"blank-peer", header + "\n" + peer, false, true},
		{"empty", "", false, true},
		{"oversize", strings.Repeat("x", (512<<10)+1), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.text)
			ready, err := validateDeploymentWire(raw, e)
			if ready != tc.ready || (err != nil) != tc.conflict {
				t.Fatalf("ready=%v error=%v", ready, err)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Fatal("secret leaked")
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("command output not erased")
			}
		})
	}
}
