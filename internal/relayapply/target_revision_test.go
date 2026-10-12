// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestTargetRouteRevisionTracksTransitionsNotCatalog(t *testing.T) {
	e, m, _, dir := appFixture(t)
	s := activateApp(t, e)
	revision := e.journal.Targets[0].RouteRevision
	if revision == 0 {
		t.Fatal("activation has no route revision")
	}
	e.journal.Targets[0].Generation++
	if out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second); err != nil || out.Application.Reservation.RouteRevision != revision {
		t.Fatal("steady verification or catalog revision changed route revision", err)
	}
	s.RecordApplied("p1", time.Now())
	if out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second); err != nil || out.Application.Reservation.RouteRevision <= revision {
		t.Fatal("switch did not advance route revision", err)
	}
	revision = e.journal.Targets[0].RouteRevision
	s.RecordApplied("p0", time.Now())
	if out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second); err != nil || out.Application.Reservation.RouteRevision <= revision {
		t.Fatal("return to original path lost transition", err)
	}
	revision = e.journal.Targets[0].RouteRevision
	e = reopenTarget(t, e, m, dir)
	if e.journal.Targets[0].RouteRevision != revision {
		t.Fatal("reopen lost route revision")
	}
}

func TestTargetRouteRevisionQuarantineRollbackAndExhaustion(t *testing.T) {
	e, m, _, _ := appFixture(t)
	s := activateApp(t, e)
	before := e.journal.Targets[0].RouteRevision
	s.RecordApplied("p1", time.Now())
	m.mutations, m.failAt, m.mode = 0, 1, "after"
	out, err := e.ReconcileTarget(context.Background(), "app", "", s, time.Second)
	if err == nil || out.Application.State != "rolled_back" || out.Application.Reservation.RouteRevision <= before+1 {
		t.Fatal("rollback to same path lost transitions", err)
	}
	m.failAt = 0
	before = e.journal.Targets[0].RouteRevision
	if _, err = e.quarantineTarget(context.Background(), "app"); err != nil || e.journal.Targets[0].RouteRevision <= before {
		t.Fatal("quarantine lost transition", err)
	}
	e.journal.Targets[0].RouteRevision = math.MaxUint64
	activateApp(t, e)
	if e.journal.Targets[0].RouteRevision != math.MaxUint64 {
		t.Fatal("revision wrapped")
	}
	if _, err = e.quarantineTarget(context.Background(), "app"); err != nil {
		t.Fatal("status counter blocked safety quarantine", err)
	}
}
