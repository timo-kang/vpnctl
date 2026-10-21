// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUplinkSnapshotExpiryDoesNotRestartOnRead(t *testing.T) {
	now := uint64(10 * time.Second)
	clock := func() (statusStamp, error) { return statusStamp{"v1:" + strings.Repeat("a", 64), now}, nil }
	p, err := newUplinkPublisher("app", clock)
	if err != nil {
		t.Fatal(err)
	}
	p.publish(statusObservation{stamp: statusStamp{p.domain, now}, kind: statusReachable, maxAge: 10 * time.Second, approvalUntil: now + uint64(8*time.Second), leaseUntil: now + uint64(4*time.Second), pathID: "p0", routeIdentity: "owned:1"})
	now += uint64(3 * time.Second)
	s := p.Snapshot()
	if s.Availability != "reachable" || s.RemainingValidityMS != 1000 || s.ObservedAgeMS == nil || *s.ObservedAgeMS != 3000 || s.ValidUntilBootNS != uint64(14*time.Second) {
		t.Fatal("read renewed evidence", s)
	}
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"valid_until_boot_ns":"14000000000"`) {
		t.Fatal("deadline lost decimal-string contract")
	}
	now += uint64(time.Second)
	if s = p.Snapshot(); s.Availability != "unknown" || s.Freshness != "stale" || s.PathID != "" {
		t.Fatal("delayed evidence survived expiry", s)
	}
	now = uint64(20 * time.Second)
	if age := p.Snapshot().ObservedAgeMS; age == nil || *age != 10000 {
		t.Fatal("stale evidence age was reset", age)
	}
	now = uint64(12 * time.Second)
	if s = p.Snapshot(); s.Availability != "unknown" {
		t.Fatal("clock reversal revived expired snapshot")
	}
}

func TestUplinkPublisherBlocksReplayAndSeparatesNegativePolicyLifetime(t *testing.T) {
	now := uint64(100)
	clock := func() (statusStamp, error) { return statusStamp{"v1:" + strings.Repeat("b", 64), now}, nil }
	p, _ := newUplinkPublisher("app", clock)
	observation := statusObservation{stamp: statusStamp{p.domain, now}, kind: statusBlocked, maxAge: time.Second, approvalUntil: 99}
	p.publish(observation)
	if s := p.Snapshot(); s.Availability != "blocked" || s.Freshness != "fresh" {
		t.Fatal("negative policy wrongly needs live grant", s)
	}
	first := p.Snapshot().ValidUntilBootNS
	now += 20
	p.publish(observation)
	if s := p.Snapshot(); s.Availability != "unknown" || s.ValidUntilBootNS != 0 {
		t.Fatal("replayed observation became new evidence", s, first)
	}
	q, _ := newUplinkPublisher("app", clock)
	if q.Snapshot().ProducerID == p.Snapshot().ProducerID || q.Snapshot().Availability != "unknown" {
		t.Fatal("restart reused producer/evidence")
	}
}

func TestUplinkPublisherClockFailureAndDomainChangeLatch(t *testing.T) {
	for _, fault := range []string{"clock", "domain", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			now := uint64(100)
			domain := "v1:" + strings.Repeat("c", 64)
			var clockErr error
			clock := func() (statusStamp, error) { return statusStamp{domain, now}, clockErr }
			p, _ := newUplinkPublisher("app", clock)
			p.publish(statusObservation{stamp: statusStamp{domain, now}, kind: statusReachable, maxAge: time.Second, approvalUntil: 2000, leaseUntil: 2000, pathID: "p0", routeIdentity: "owned:1"})
			switch fault {
			case "clock":
				clockErr = errors.New("unavailable")
			case "domain":
				domain = "v1:" + strings.Repeat("d", 64)
			case "rollback":
				now = 99
			}
			if p.Snapshot().Availability != "unknown" {
				t.Fatal("clock/domain failure remained reachable")
			}
			clockErr = nil
			domain = p.domain
			now = 101
			if p.Snapshot().Availability != "unknown" {
				t.Fatal("old evidence revived after clock recovery")
			}
			p.publish(statusObservation{stamp: statusStamp{domain, now}, kind: statusReachable, maxAge: time.Second, approvalUntil: 2000, leaseUntil: 2000, pathID: "p0", routeIdentity: "owned:1"})
			if p.Snapshot().Availability != "reachable" {
				t.Fatal("new actual evidence did not recover")
			}
		})
	}
}

func TestUplinkPublisherConcurrentReadsAreIsolatedValues(t *testing.T) {
	var now atomic.Uint64
	now.Store(100)
	clock := func() (statusStamp, error) { return statusStamp{"v1:" + strings.Repeat("e", 64), now.Load()}, nil }
	p, _ := newUplinkPublisher("app", clock)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s := p.Snapshot()
				s.PathID = "mutated"
				b, _ := json.Marshal(s)
				if len(b) > 2048 {
					t.Error("snapshot exceeds fixed bound")
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		at := now.Add(1)
		p.publish(statusObservation{stamp: statusStamp{p.domain, at}, kind: statusReachable, maxAge: time.Second, approvalUntil: 2000, leaseUntil: 2000, pathID: "p0", routeIdentity: "owned:1"})
	}
	wg.Wait()
	if s := p.Snapshot(); s.PathID != "p0" || s.PathRevision != 1 || s.Revision != 101 {
		t.Fatal("read mutated producer or unchanged path advanced", s)
	}
}

func TestUplinkWithdrawalRejectsAlreadyRunningPublication(t *testing.T) {
	now := uint64(100)
	clock := func() (statusStamp, error) { return statusStamp{"v1:" + strings.Repeat("a", 64), now}, nil }
	p, _ := newUplinkPublisher("app", clock)
	now = 110
	delayed := statusObservation{stamp: statusStamp{p.domain, now}, kind: statusReachable, maxAge: time.Second, approvalUntil: 2000, leaseUntil: 2000, pathID: "p0", routeIdentity: "owned:1", withdrawal: p.withdrawal.Load()}
	now = 120
	p.Unavailable()
	now = 130
	p.publish(delayed)
	if p.Snapshot().Availability != "unknown" {
		t.Fatal("late result revived a withdrawn publication")
	}
	delayed.stamp.boot = 140
	delayed.withdrawal = p.withdrawal.Load()
	now = 140
	p.publish(delayed)
	if p.Snapshot().Availability != "reachable" {
		t.Fatal("fresh later cycle did not recover")
	}
}
