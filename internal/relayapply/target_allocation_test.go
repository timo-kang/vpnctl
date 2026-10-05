// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"vpnctl/internal/relaycatalog"
)

func TestTargetAllocationReportedCollision(t *testing.T) {
	// Exact public identity from CI 37334104350, not a randomly passing fixture.
	const controller = "7895f2cf50e105e75f4ecf1677eac81d"
	a, err := allocateTargetSlots(TargetGuard{Controller: controller, Node: "robot", TargetID: "app"}, nil)
	if err != nil || a.Priority != 32551 || a.Table != 731881 || a.AllocationSlot != 0 {
		t.Fatal(a, err)
	}
	_, collision := targetSlots(controller, "robot", "app2")
	if collision != a.Priority {
		t.Fatal("reported collision not exercised")
	}
	b, err := allocateTargetSlots(TargetGuard{Controller: controller, Node: "robot", TargetID: "app2"}, []TargetGuard{a})
	if err != nil || b.AllocationSlot == 0 || b.Priority == a.Priority || b.Table == a.Table {
		t.Fatal("distinct approved targets cannot coexist", a, b, err)
	}
	raw, err := json.Marshal(a)
	if err != nil || strings.Contains(string(raw), "allocation_slot") {
		t.Fatal("legacy zero-slot encoding changed", string(raw), err)
	}
}

func TestTargetAllocationMaximumCollisionRecovery(t *testing.T) {
	e, m, dir := targetFixture(t)
	ctx := context.Background()
	first, err := e.ReserveTarget(ctx, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	base := *first.Reservation
	// Deliberately give all 32 disjoint targets the same initial priority.
	// Recovery of a durable blocking reservation needs no fresh authorization.
	for search, count := 0, 1; count < relaycatalog.MaxTargets; search++ {
		if search > 200000 {
			t.Fatal("could not construct collision population")
		}
		id := fmt.Sprint("collision-", search)
		_, priority := targetSlots(base.Controller, base.Node, id)
		if priority != base.Priority {
			continue
		}
		g := base
		g.TargetID, g.Phase = id, "reserving"
		g.Prefixes = []string{fmt.Sprintf("198.18.%d.2/32", count)}
		g.Owner, g.Metric, _, err = token()
		if err != nil {
			t.Fatal(err)
		}
		g, err = allocateTargetSlots(g, e.journal.Targets)
		if err != nil || g.AllocationSlot == 0 {
			t.Fatal(g, err)
		}
		e.journal.Targets = append(e.journal.Targets, g)
		if err := e.persist(); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			m.failAt, m.mode = m.mutations+2, "after"
		}
		out, err := e.RecoverTarget(ctx, id)
		if count == 1 {
			if err == nil || out.Guarded {
				t.Fatal("interrupted allocation claimed success", out, err)
			}
			e = reopenTarget(t, e, m, dir)
			m.failAt = 0
			out, err = e.RecoverTarget(ctx, id)
		}
		if err != nil || !out.Guarded || out.Reservation.Table != g.Table || out.Reservation.Priority != g.Priority {
			t.Fatal("allocation changed across recovery", out, err)
		}
		count++
	}
	if _, err := allocateTargetSlots(base, e.journal.Targets); err == nil {
		t.Fatal("capacity exceeded")
	}
	want := append([]TargetGuard(nil), e.journal.Targets[1:]...)
	if err := validateTargetGuards(e.journal.Targets, "robot"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReleaseTarget(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	e = reopenTarget(t, e, m, dir)
	if !reflect.DeepEqual(want, e.journal.Targets) {
		t.Fatal("removing an earlier target reassigned surviving slots")
	}
	for _, g := range want {
		if out, err := e.InspectTarget(ctx, g.TargetID); err != nil || !out.Guarded {
			t.Fatal(out, err)
		}
		if _, err := e.ReleaseTarget(ctx, g.TargetID); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.rules) != 0 || len(m.routes) != 0 || len(e.journal.Targets) != 0 {
		t.Fatal("collision release leaked resources")
	}
}
