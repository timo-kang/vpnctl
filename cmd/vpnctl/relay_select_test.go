// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"testing"
	"time"
	"vpnctl/internal/config"
)

func TestTargetSelectionCLIRejectsUnsafePolicyBeforeOpeningCache(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--target-id", "app", "--mode", "automatic"},
		{"--target-id", "app", "--mode", "manual"},
		{"--target-id", "app", "--path-id", "p0"},
		{"--target-id", "app", "--samples", "1"},
		{"--target-id", "app", "--probe-timeout", "0"},
		{"--target-id", "app", "--probe-timeout", "3s"},
		{"--target-id", "app", "--hold-down", "0"},
		{"--target-id", "app", "--minimum-dwell", "0"},
		{"--target-id", "app", "--max-cost", "-2"},
		{"--target-id", "app", "--interval", "1ms"},
	} {
		if err := runNodeRelaySelect(args); err == nil {
			t.Fatal("invalid selection args accepted", args)
		}
	}
}
func TestMissingTargetCacheProducesNoEvidence(t *testing.T) {
	node := &config.NodeConfig{Name: "robot", PKIDir: t.TempDir()}
	r := collectTargetObservation(context.Background(), node, node.PKIDir+"/missing", "app", "", time.Second)
	if r.Valid || r.Reason != "cache_unavailable" || len(r.Paths) != 0 {
		t.Fatal(r)
	}
}
