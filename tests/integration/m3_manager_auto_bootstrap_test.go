//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

// This constructor starts file readers only. No socket or network configuration
// is needed to retain the first failed application cycle before baseline passes.
func TestManagerTimelineBootstrapCapturesCyclesBeforeTraffic(t *testing.T) {
	logs := map[string]string{}
	for _, target := range []string{"app", "app2"} {
		path := filepath.Join(t.TempDir(), target+".jsonl")
		result := relayapply.TargetReconcileResult{
			SchemaVersion: 1,
			Application:   relayapply.TargetGuardResult{State: "blocked", Reason: "target_quarantine_conflict"},
			Selection:     relayselect.Decision{State: "unknown", Reason: "fixture_initial_failure"},
			Diagnostics:   &relayobserve.Diagnostics{MonotonicAvailable: true, StartedMono: time.Second, FinishedMono: 2 * time.Second},
		}
		b, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		logs[target] = path
	}
	trace := startManagerCycleTrace(logs)
	defer trace.close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		packets, cycles, err := trace.snapshot()
		if err != "" || len(packets) != 0 {
			t.Fatal("passive bootstrap collection failed or started packet probes", err, len(packets))
		}
		if len(cycles) == 2 {
			seen := map[string]bool{}
			for _, c := range cycles {
				if c.Applied || c.ApplicationReason != "target_quarantine_conflict" || c.Reason != "fixture_initial_failure" || c.Diagnostics == nil || c.Diagnostics.FinishedMono != 2*time.Second {
					t.Fatal("initial failure evidence lost", c.Target)
				}
				seen[c.Target] = true
			}
			if !seen["app"] || !seen["app2"] {
				t.Fatal("one watcher replaced the other's evidence")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial application cycles not captured before traffic admission", len(cycles))
		}
		time.Sleep(10 * time.Millisecond)
	}
	trace.close()
	packets, cycles, err := trace.snapshot()
	if len(packets) != 0 || len(cycles) != 2 || err != "" {
		t.Fatal("early shutdown lost retained evidence", len(packets), len(cycles), err)
	}
}
