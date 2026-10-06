//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
	"vpnctl/internal/relayselect"
)

func selectedEventCandidate(t *testing.T, path, id string) relayselect.Candidate {
	t.Helper()
	r := latestApplicationResult(path)
	for _, c := range r.Selection.Candidates {
		if c.PathID == id {
			return c
		}
	}
	t.Fatal("missing selected event candidate", r)
	return relayselect.Candidate{}
}
func TestNetns_M3TargetApplicationUnderlayEvents(t *testing.T) {
	requireNetwork(t)
	f := applicationFixture(t, true, 4)
	paths := map[string]string{}
	for _, p := range f.plan.Paths {
		if paths[p.UnderlayID] == "" {
			paths[p.UnderlayID] = p.PathID
		}
	}
	if paths["lan0"] == "" || paths["lan1"] == "" {
		t.Fatal("two independent underlays required")
	}
	logs := map[string]string{}
	for _, target := range []string{"app", "app2"} {
		underlay := "lan0"
		if target == "app2" {
			underlay = "lan1"
		}
		log := filepath.Join(f.results, "events-"+target+".jsonl")
		logs[target] = log
		startNetworkProcess(t, f.robot, log, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", target, "--watch", "--interval", "500ms", "--mode", "manual", "--path-id", paths[underlay])
	}
	eventually(t, 45*time.Second, "two event-aware apps", func() error {
		for _, target := range []string{"app", "app2"} {
			r := latestApplicationResult(logs[target])
			if !r.Applied {
				return fmt.Errorf("%s %s", target, r.Selection.Reason)
			}
		}
		return nil
	})
	if p := applicationPayload(t, f, m3Target); !p.OK {
		t.Fatal(p)
	}
	if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
		t.Fatal(p)
	}
	independent := selectedEventCandidate(t, logs["app2"], paths["lan1"])
	if len(independent.UnderlayGeneration) != 64 {
		t.Fatal("event provider not installed", independent)
	}
	steps := []struct {
		name     string
		commands [][]string
	}{
		{"address-restore", [][]string{{"address", "add", "203.0.113.100/32", "dev", "wan0"}, {"address", "del", "203.0.113.100/32", "dev", "wan0"}}},
		{"route-restore", [][]string{{"route", "add", "203.0.113.99/32", "dev", "wan0"}, {"route", "del", "203.0.113.99/32", "dev", "wan0"}}},
		{"rename-restore", [][]string{{"link", "set", "wan0", "name", "event-temp"}, {"link", "set", "event-temp", "name", "wan0"}}},
	}
	results := map[string]any{}
	t.Cleanup(func() {
		results["completed"] = !t.Failed()
		writeM3Report(t, filepath.Join(f.results, "application-underlay-events.json"), results)
	})
	for _, step := range steps {
		old := selectedEventCandidate(t, logs["app"], paths["lan0"])
		baseline := len(applicationResults(logs["app"]))
		secondBaseline := len(applicationResults(logs["app2"]))
		started := time.Now()
		for _, args := range step.commands {
			netOutput(t, f.robot, append([]string{"ip"}, args...)...)
		}
		sawConfirmation := false
		var current relayselect.Candidate
		eventually(t, 45*time.Second, "fresh generation and app recovery "+step.name, func() error {
			if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
				t.Fatal("underlay event interrupted independent payload", p)
			}
			for _, r := range applicationResults(logs["app2"])[secondBaseline:] {
				if !r.Applied {
					t.Fatal("independent app lost eligibility", r)
				}
				for _, c := range r.Selection.Candidates {
					if c.PathID == paths["lan1"] && c.UnderlayGeneration != independent.UnderlayGeneration {
						t.Fatal("unrelated underlay epoch changed", c)
					}
				}
			}
			for _, r := range applicationResults(logs["app"])[baseline:] {
				for _, c := range r.Selection.Candidates {
					if c.PathID != paths["lan0"] || c.UnderlayGeneration == old.UnderlayGeneration {
						continue
					}
					if c.ConsecutiveSuccesses == 1 && !c.Eligible {
						sawConfirmation = true
					}
					if c.Eligible && (!sawConfirmation || c.ConsecutiveSuccesses < 2) {
						t.Fatal("old confirmation reused after restored snapshot", c)
					}
					if r.Applied && c.PathID == r.Selection.DesiredPathID {
						current = c
					}
				}
			}
			if !sawConfirmation || !current.Eligible {
				return fmt.Errorf("awaiting fresh confirmations")
			}
			if p := applicationPayload(t, f, m3Target); !p.OK {
				return fmt.Errorf("fresh payload unavailable: %+v", p)
			}
			return nil
		})
		results[step.name] = map[string]any{"old_generation": old.UnderlayGeneration, "new_generation": current.UnderlayGeneration, "fresh_confirmations": current.ConsecutiveSuccesses, "payload_recovery_seconds": time.Since(started).Seconds(), "independent_payload_preserved": true}
	}
}
