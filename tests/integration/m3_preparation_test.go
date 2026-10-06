//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
)

func latestPreparation(path, id string) relayapply.PreparationStatus {
	b, _ := os.ReadFile(path)
	lines := strings.Split(string(b), "\n")
	var latest relayapply.PreparationStatus
	for _, line := range lines[:len(lines)-1] {
		var r struct {
			Preparation *relayapply.Result `json:"preparation"`
		}
		if json.Unmarshal([]byte(line), &r) != nil || r.Preparation == nil {
			continue
		}
		for _, p := range r.Preparation.Preparations {
			if p.PathID == id {
				latest = p
			}
		}
	}
	return latest
}

func enablePreparation(t *testing.T, f *m3AuthorityFixture, id string) relayapply.PreparationStatus {
	t.Helper()
	b := nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", id, "--app-routes", "--auto-rebuild")
	var r relayapply.Result
	if err := json.Unmarshal([]byte(b), &r); err != nil {
		t.Fatal(err, b)
	}
	for _, p := range r.Preparations {
		if p.PathID == id && p.Enabled {
			return p
		}
	}
	t.Fatal("missing explicit preparation consent", r)
	return relayapply.PreparationStatus{}
}

// All operations below target the fixture's owned veth pair/bridge inside the
// disposable --network none container. No host device or manager is touched.
func recreatePreparationUnderlay(t *testing.T, f *m3AuthorityFixture, reuse bool, source string) {
	t.Helper()
	var robot []struct {
		Index int `json:"ifindex"`
		Peer  int `json:"link_index"`
	}
	if err := json.Unmarshal([]byte(netOutput(t, f.robot, "ip", "-j", "-d", "link", "show", "wan0")), &robot); err != nil || len(robot) != 1 {
		t.Fatal(err)
	}
	var parent []struct {
		Index  int    `json:"ifindex"`
		Name   string `json:"ifname"`
		Master string `json:"master"`
	}
	if err := json.Unmarshal(runOut(t, ".", "ip", "-j", "link", "show"), &parent); err != nil {
		t.Fatal(err)
	}
	peer, bridge := "", ""
	for _, l := range parent {
		if l.Index == robot[0].Peer {
			peer, bridge = l.Name, l.Master
		}
	}
	if peer == "" || bridge == "" {
		t.Fatal("owned veth peer/bridge unavailable", robot, parent)
	}
	netOutput(t, f.robot, "ip", "link", "del", "wan0")
	args := []string{"ip", "link", "add", "wan0"}
	if reuse {
		args = append(args, "index", strconv.Itoa(robot[0].Index))
	}
	// Request the index on the local end: Linux does not preserve a peer's
	// requested index when moving that peer into a different namespace.
	args = append(args, "type", "veth", "peer", "name", peer, "netns", "1")
	netOutput(t, f.robot, args...)
	run(t, ".", "ip", "link", "set", peer, "master", bridge)
	run(t, ".", "ip", "link", "set", peer, "up")
	netOutput(t, f.robot, "ip", "addr", "add", source+"/24", "dev", "wan0")
	netOutput(t, f.robot, "ip", "link", "set", "wan0", "up")
}

func TestNetns_M3PreparationRecovery(t *testing.T) {
	requireNetwork(t)
	f := applicationFixture(t, true, 4)
	managed := enablePreparation(t, f, "p00")
	logs := map[string]string{}
	for target, path := range map[string]string{"app": "p00", "app2": "p01"} {
		log := filepath.Join(f.results, "rebuild-"+target+".jsonl")
		logs[target] = log
		startNetworkProcess(t, f.robot, log, nil, integrationBinary(t), "node", "relay", "target", "reconcile", "--config", f.node, "--target-id", target, "--watch", "--interval", "500ms", "--mode", "manual", "--path-id", path)
	}
	eventually(t, 45*time.Second, "two apps before rebuild", func() error {
		for _, log := range logs {
			if !latestApplicationResult(log).Applied {
				return fmt.Errorf("app not active")
			}
		}
		return nil
	})
	supervision := filepath.Join(f.results, "application-node-supervisor.jsonl")
	source := "192.0.2.10"
	steps := []string{"missing_endpoint", "source_change", "gateway_change", "link_down_up", "rename_restore", "new_ifindex", "reused_ifindex"}
	results := map[string]any{}
	t.Cleanup(func() {
		results["completed"] = !t.Failed()
		writeM3Report(t, filepath.Join(f.results, "preparation-recovery.json"), results)
	})
	for _, fault := range steps {
		old := managed.Current
		if old == nil {
			t.Fatal("missing prior candidate")
		}
		baseline := len(applicationResults(logs["app"]))
		independentBaseline := len(applicationResults(logs["app2"]))
		started := time.Now()
		switch fault {
		case "missing_endpoint":
			netOutput(t, f.robot, "ip", "route", "del", old.Pin.EndpointPrefix, "table", strconv.Itoa(int(old.Pin.Table)))
		case "source_change":
			netOutput(t, f.robot, "ip", "address", "del", source+"/24", "dev", "wan0")
			source = "192.0.2.20"
			netOutput(t, f.robot, "ip", "address", "add", source+"/24", "dev", "wan0")
		case "gateway_change":
			netOutput(t, f.robot, "ip", "route", "add", old.Pin.EndpointPrefix, "via", "192.0.2.11", "dev", "wan0", "src", source, "onlink")
		case "link_down_up":
			netOutput(t, f.robot, "ip", "link", "set", "wan0", "down")
			netOutput(t, f.robot, "ip", "link", "set", "wan0", "up")
			// Kernel versions differ in retaining static routes with linkdown.
			// Explicit deletion verifies the required lost-route case as well.
			netOutput(t, f.robot, "ip", "route", "flush", "table", strconv.Itoa(int(old.Pin.Table)), "to", old.Pin.EndpointPrefix)
		case "rename_restore":
			netOutput(t, f.robot, "ip", "link", "set", "wan0", "name", "rebuild-temp")
			netOutput(t, f.robot, "ip", "link", "set", "rebuild-temp", "name", "wan0")
			netOutput(t, f.robot, "ip", "route", "del", old.Pin.EndpointPrefix, "table", strconv.Itoa(int(old.Pin.Table)))
		case "new_ifindex":
			recreatePreparationUnderlay(t, f, false, source)
		case "reused_ifindex":
			recreatePreparationUnderlay(t, f, true, source)
		}
		sawConfirmation := false
		var gap time.Duration
		eventually(t, 120*time.Second, "owned rebuild "+fault, func() error {
			if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
				t.Fatal("independent payload lost during rebuild", fault, p)
			}
			_, gap = applicationContinuity(t, logs["app2"], independentBaseline)
			managed = latestPreparation(supervision, "p00")
			for _, r := range applicationResults(logs["app"])[baseline:] {
				for _, c := range r.Selection.Candidates {
					if c.PathID == "p00" && c.ConsecutiveSuccesses == 1 && !c.Eligible {
						sawConfirmation = true
					}
				}
			}
			if managed.Current == nil || managed.Current.Owner == old.Owner || managed.Phase != "ready" {
				return fmt.Errorf("phase=%s reason=%s step=%d", managed.Phase, managed.Reason, managed.Step)
			}
			if managed.Current.Pin.Source != source {
				t.Fatal("stale source", managed)
			}
			if fault == "new_ifindex" && managed.Current.Pin.IfIndex == old.Pin.IfIndex {
				t.Fatal("ifindex was not replaced")
			}
			if fault == "reused_ifindex" && managed.Current.Pin.IfIndex != old.Pin.IfIndex {
				t.Fatal("ifindex reuse not exercised")
			}
			if !latestApplicationResult(logs["app"]).Applied {
				return fmt.Errorf("fresh confirmation pending")
			}
			if !sawConfirmation {
				t.Fatal("old selection confirmation reused")
			}
			if p := applicationPayload(t, f, m3Target); !p.OK {
				return fmt.Errorf("reconstructed app payload unavailable: %+v", p)
			}
			return nil
		})
		results[fault] = map[string]any{"previous": old, "current": managed.Current, "recovery_seconds": time.Since(started).Seconds(), "independent_maximum_gap_seconds": gap.Seconds(), "new_confirmation": sawConfirmation}
	}
	// Release must remain an opt-out even while the same supervisor continues.
	nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "release", "--config", f.node, "--path-id", "p00")
	until := time.Now().Add(4 * time.Second)
	for time.Now().Before(until) {
		if p := applicationPayload(t, f, m3Target); p.OK {
			t.Fatal("released app resurrected", p)
		}
		if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
			t.Fatal("release affected independent app", p)
		}
		time.Sleep(200 * time.Millisecond)
	}
	results["explicit_release_preserved"] = true
}
