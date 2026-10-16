// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
)

func TestUplinkAPIRequiresExplicitWatchAndUIDs(t *testing.T) {
	for _, args := range [][]string{
		{"--target-id", "app", "--uplink-api-dir", "/run/vpnctl-app"},
		{"--target-id", "app", "--watch", "--uplink-api-dir", "/run/vpnctl-app"},
		{"--target-id", "app", "--watch", "--uplink-api-allow-uids", "0"},
		{"--target-id", "app", "--watch", "--uplink-api-dir", "/run/vpnctl-app", "--uplink-api-allow-uids", "-1"},
		{"--target-id", "app", "--watch", "--uplink-api-dir", "/run/vpnctl-app", "--uplink-api-allow-uids", "0,0"},
	} {
		if err := runNodeRelaySelection(args, true); err == nil || !strings.Contains(err.Error(), "uplink API") {
			t.Fatal("invalid API flags not rejected before config/cache", err)
		}
	}
	if err := runNodeRelaySelection([]string{"--target-id", "app", "--watch", "--uplink-api-dir", "/run/vpnctl-app", "--uplink-api-allow-uids", "0"}, false); err == nil || !strings.Contains(err.Error(), "uplink API") {
		t.Fatal("observation-only select exposed applied API", err)
	}
}

func TestUplinkAPIWithdrawsOnAdmissionFailure(t *testing.T) {
	node := &config.NodeConfig{Name: "robot", PKIDir: t.TempDir()}
	p, err := relayapply.NewUplinkPublisher("app")
	if err != nil {
		t.Fatal(err)
	}
	before := p.Snapshot().Revision
	out, err := reconcileApplicationTarget(context.Background(), node, node.PKIDir+"/missing", "app", "", time.Second, nil, p)
	if out.Diagnostics == nil || !out.Diagnostics.MonotonicAvailable || out.Diagnostics.Phases["admission"].Calls != 1 {
		t.Fatal("API admission failure lost coordinator diagnostics")
	}
	if err == nil || p.Snapshot().Revision <= before || p.Snapshot().Availability != "unknown" {
		t.Fatal("admission failure did not withdraw status")
	}
}
