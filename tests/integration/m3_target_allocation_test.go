//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycatalog"
)

func TestNetns_M3TargetApplicationSlotCollision(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: true, independentRecipients: true, underlays: 2})
	f.releaseNodeCandidates()
	priority := func(id string) uint32 {
		h := sha256.Sum256([]byte(f.plan.ControllerID + "\x00robot\x00" + id))
		return 32000 + binary.BigEndian.Uint32(h[4:8])%760
	}
	id := ""
	for i := 0; i < 100000; i++ {
		candidate := fmt.Sprint("collision-", i)
		if priority(candidate) == priority("app") {
			id = candidate
			break
		}
	}
	if id == "" {
		t.Fatal("could not construct priority collision")
	}
	// Retire the already-bound fixture paths through the public approval API.
	for i := range f.spec.Paths {
		f.spec.Paths[i].Disabled = true
	}
	f.controller.apply(f.spec, 3600)
	f.spec.Targets = append(f.spec.Targets, relaycatalog.Target{ID: id, Prefixes: []string{"198.18.0.3/32"}, ProbeAddress: "198.18.0.3", Protocol: "tcp", Port: 9192})
	for i := range f.spec.Paths {
		// Bound path identities are immutable; the new target set needs a new
		// approved path identity, even though this test only reserves targets.
		f.spec.Paths[i].ID = "collision-" + f.spec.Paths[i].ID
		f.spec.Paths[i].Disabled = false
		f.spec.Paths[i].TargetIDs = []string{"app", id}
	}
	f.controller.apply(f.spec, 3600)
	f.nodeCall("refresh", "")
	call := func(action, target string) relayapply.TargetGuardResult {
		t.Helper()
		b := netOutput(t, f.robot, integrationBinary(t), "node", "relay", "target", action, "--config", f.node, "--target-id", target)
		var out relayapply.TargetGuardResult
		if json.Unmarshal([]byte(b), &out) != nil || out.Activated || action != "release" && !out.Guarded {
			t.Fatal("invalid reservation", b)
		}
		return out
	}
	first := call("reserve", "app")
	// A foreign owner occupying the next slot is a conflict, not permission to
	// keep searching or delete that rule. Only this fixture removes it afterward.
	foreignPriority := fmt.Sprint(32000 + (first.Reservation.Priority-32000+1)%760)
	netOutput(t, f.robot, "ip", "rule", "add", "priority", foreignPriority, "to", "198.18.0.3/32", "lookup", "9999", "protocol", "99")
	before := netOutput(t, f.robot, "ip", "-j", "-4", "rule", "show")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	b, err := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", id).CombinedOutput()
	cancel()
	if err == nil || !strings.Contains(string(b), `"reason":"kernel_conflict_or_unavailable"`) || before != netOutput(t, f.robot, "ip", "-j", "-4", "rule", "show") {
		t.Fatal("foreign collision adopted or modified", err, string(b))
	}
	call("inspect", "app")
	netOutput(t, f.robot, "ip", "rule", "del", "priority", foreignPriority, "to", "198.18.0.3/32", "lookup", "9999", "protocol", "99")
	second := call("reserve", id)
	if first.Reservation.AllocationSlot != 0 || second.Reservation.AllocationSlot == 0 || first.Reservation.Priority == second.Reservation.Priority || first.Reservation.Table == second.Reservation.Table {
		t.Fatal("collision unresolved", first, second)
	}
	call("inspect", "app")
	call("recover", id) // A separate process reopens the durable allocation.
	call("release", "app")
	after := call("inspect", id)
	if after.Reservation.Priority != second.Reservation.Priority || after.Reservation.Table != second.Reservation.Table || after.Reservation.AllocationSlot != second.Reservation.AllocationSlot {
		t.Fatal("surviving target reassigned", second, after)
	}
	call("release", id)
	writeM3Report(t, filepath.Join(f.results, "application-allocation.json"), map[string]any{"completed": !t.Failed(), "initial_priority": priority("app"), "first": first, "second": second, "foreign_collision_preserved_and_refused": true, "reopen_and_release_preserved_allocation": true})
}
