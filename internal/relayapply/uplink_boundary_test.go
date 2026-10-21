// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUplinkEveryEvidenceKindExpiresWithoutRevival(t *testing.T) {
	for _, kind := range []statusKind{statusReachable, statusUnreachable, statusBlocked} {
		for _, jump := range []time.Duration{time.Second, 24 * time.Hour} {
			now := uint64(100)
			clock := func() (statusStamp, error) { return statusStamp{statusDomain("test"), now}, nil }
			p, _ := newUplinkPublisher("app", clock)
			p.publish(statusObservation{stamp: statusStamp{p.domain, now}, kind: kind, maxAge: time.Second, approvalUntil: now + uint64(2*time.Second), leaseUntil: now + uint64(3*time.Second), pathID: "p0", routeIdentity: "route1"})
			now += uint64(time.Second) - 1
			if p.Snapshot().Freshness != "fresh" {
				t.Fatal("evidence expired before absolute deadline", kind)
			}
			now = 100 + uint64(jump) // Includes a suspend-sized BOOTTIME jump.
			s := p.Snapshot()
			if s.Availability != "unknown" || s.Freshness != "stale" || s.PathID != "" || s.Evidence != "" {
				t.Fatal("evidence survived deadline", kind)
			}
			now = 101
			if p.Snapshot().Availability != "unknown" {
				t.Fatal("expired evidence revived", kind)
			}
		}
	}
}

func TestUplinkWirePreservesLargeIntegersAndUnknownAge(t *testing.T) {
	now := uint64(1<<53 + 17)
	clock := func() (statusStamp, error) { return statusStamp{statusDomain("test"), now}, nil }
	p, _ := newUplinkPublisher("app", clock)
	unknown, _ := json.Marshal(p.Snapshot())
	if strings.Contains(string(unknown), "observed_age_ms") || strings.Contains(string(unknown), "observed_boot_ns") {
		t.Fatal("unknown observation has invented age")
	}
	p.revision, p.pathRevision = 1<<53+3, 1<<53+7
	p.publish(statusObservation{stamp: statusStamp{p.domain, now}, kind: statusReachable, maxAge: time.Second, approvalUntil: now + uint64(time.Second), leaseUntil: now + uint64(time.Second), pathID: "p0", routeIdentity: "route1"})
	original := p.Snapshot()
	wire, err := json.Marshal(original)
	if err != nil || len(wire) > 2048 {
		t.Fatal("wire bound", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"revision", "path_revision", "observed_boot_ns", "valid_until_boot_ns"} {
		if _, ok := raw[field].(string); !ok {
			t.Fatal("uint64 encoded as lossy number", field)
		}
	}
	var decoded UplinkSnapshot
	if err := json.Unmarshal(wire, &decoded); err != nil || decoded.SchemaVersion != 1 || decoded.Revision != original.Revision || decoded.PathRevision != original.PathRevision || decoded.ObservedBootNS != now || decoded.ValidUntilBootNS != original.ValidUntilBootNS {
		t.Fatal("wire contract/precision changed", err)
	}
}

func TestUplinkInvalidBudgetsAndExhaustedCountersWithholdConfidence(t *testing.T) {
	for _, fault := range []string{"overflow", "short", "long", "path", "identity", "revision", "path-revision", "expired-approval", "expired-lease"} {
		t.Run(fault, func(t *testing.T) {
			now := uint64(100)
			clock := func() (statusStamp, error) { return statusStamp{statusDomain("test"), now}, nil }
			p, _ := newUplinkPublisher("app", clock)
			o := statusObservation{stamp: statusStamp{p.domain, now}, kind: statusReachable, maxAge: time.Second, approvalUntil: now + uint64(time.Second), leaseUntil: now + uint64(time.Second), pathID: "p0", routeIdentity: "route1"}
			switch fault {
			case "overflow":
				now = ^uint64(0) - 1
				o.stamp.boot = now
			case "short":
				o.maxAge = time.Millisecond
			case "long":
				o.maxAge = 31 * time.Second
			case "path":
				o.pathID = strings.Repeat("a", 65)
			case "identity":
				o.routeIdentity = strings.Repeat("a", 257)
			case "revision":
				p.revision = ^uint64(0)
			case "path-revision":
				p.pathRevision = ^uint64(0)
			case "expired-approval":
				o.approvalUntil = now
			case "expired-lease":
				o.leaseUntil = now
			}
			p.publish(o)
			if p.Snapshot().Availability != "unknown" {
				t.Fatal("invalid observation survived")
			}
		})
	}
}
