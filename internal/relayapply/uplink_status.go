// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayguard"
)

// UplinkSnapshot is observation only, never route/lease authority. Decimal-string
// counters/deadlines preserve uint64 precision for consumers in other languages.
// No private journal identity, address, key, approval witness or raw error escapes.
type UplinkSnapshot struct {
	SchemaVersion       int     `json:"schema_version"`
	TargetID            string  `json:"target_id"`
	ProducerID          string  `json:"producer_id"`
	Revision            uint64  `json:"revision,string"`
	Availability        string  `json:"availability"`
	Freshness           string  `json:"freshness"`
	Reason              string  `json:"reason"`
	ClockDomain         string  `json:"clock_domain"`
	ObservedBootNS      uint64  `json:"observed_boot_ns,string,omitempty"`
	ValidUntilBootNS    uint64  `json:"valid_until_boot_ns,string,omitempty"`
	ObservedAgeMS       *uint64 `json:"observed_age_ms,omitempty"`
	RemainingValidityMS uint64  `json:"remaining_validity_ms"`
	PathID              string  `json:"path_id,omitempty"`
	PathRevision        uint64  `json:"path_revision,string"`
	Evidence            string  `json:"evidence,omitempty"`
	SessionContinuity   string  `json:"session_continuity"`
}

type statusStamp struct {
	domain string
	boot   uint64
}
type statusKind uint8

const (
	statusUnknown statusKind = iota
	statusReachable
	statusUnreachable
	statusBlocked
)

// Only live in-process reconciliation constructs this value. It is deliberately
// private and has no serialized authority path from UplinkSnapshot or CLI JSON.
type statusObservation struct {
	withdrawal                uint64
	stamp                     statusStamp
	kind                      statusKind
	maxAge                    time.Duration
	approvalUntil, leaseUntil uint64
	pathID, routeIdentity     string
}

type uplinkRecord struct{ snapshot UplinkSnapshot }

// UplinkPublisher retains one immutable, bounded snapshot. A future local API
// can read it without an Engine, private cache, kernel lock, or new probe.
// Reconciliation is the only writer; readers never acquire its publication lock.
type UplinkPublisher struct {
	withdrawal                              atomic.Uint64
	target, producer, domain                string
	clock                                   func() (statusStamp, error)
	mu                                      sync.Mutex
	revision, pathRevision, lastObservation uint64
	routeIdentity                           string
	record                                  atomic.Pointer[uplinkRecord]
	invalidated                             atomic.Uint64
}

func statusDomain(raw string) string {
	digest := sha256.Sum256([]byte("vpnctl.uplink.clock.v1\x00" + raw))
	return "v1:" + hex.EncodeToString(digest[:])
}

// LocalUplinkClock identifies the local boot/netns and validates zero time-
// namespace offsets. BOOTTIME includes suspend; wall time is never a fallback.
func LocalUplinkClock() (domain string, bootNS uint64, err error) {
	raw, err := relaycache.KernelDomain()
	if err != nil {
		return "", 0, err
	}
	bootNS, err = relayguard.Now()
	if err != nil {
		return "", 0, err
	}
	return statusDomain(raw), bootNS, nil
}

func NewUplinkPublisher(target string) (*UplinkPublisher, error) {
	return newUplinkPublisher(target, func() (statusStamp, error) { d, b, e := LocalUplinkClock(); return statusStamp{d, b}, e })
}
func newUplinkPublisher(target string, clock func() (statusStamp, error)) (*UplinkPublisher, error) {
	if !validGuardID(target) || clock == nil {
		return nil, errors.New("valid target and local clock required")
	}
	at, err := clock()
	if err != nil {
		return nil, err
	}
	if len(at.domain) != 67 || at.boot == 0 {
		return nil, errors.New("local clock domain unavailable")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	p := &UplinkPublisher{target: target, producer: hex.EncodeToString(id[:]), domain: at.domain, clock: clock}
	p.revision = 1
	p.record.Store(&uplinkRecord{p.emptySnapshot()})
	return p, nil
}

// Unavailable withdraws old observations after admission/open failure. It does
// not assert that the kernel has quarantined the target or that uplink is down.
func (p *UplinkPublisher) Unavailable() { p.withdrawal.Add(1); p.publish(statusObservation{}) }

func (p *UplinkPublisher) publish(o statusObservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revision == ^uint64(0) {
		p.invalidated.Store(p.revision)
		return
	}
	p.revision++
	s := p.emptySnapshot()
	defer func() { p.record.Store(&uplinkRecord{s}) }()
	now, err := p.clock()
	if err != nil || now.domain != p.domain || now.boot == 0 {
		s.Reason = "clock_unavailable"
		return
	}
	if o.stamp.boot == 0 {
		p.lastObservation = max(p.lastObservation, now.boot)
		return
	}
	if o.withdrawal != p.withdrawal.Load() {
		return
	}
	if o.stamp.domain != p.domain || o.stamp.boot == 0 || o.stamp.boot > now.boot || o.stamp.boot <= p.lastObservation {
		return
	}
	p.lastObservation = o.stamp.boot
	if len(o.routeIdentity) > 256 || len(o.pathID) > 64 {
		return
	}
	if o.routeIdentity != "" && o.routeIdentity != p.routeIdentity {
		if p.pathRevision == ^uint64(0) {
			s.Reason = "revision_exhausted"
			return
		}
		p.pathRevision++
		p.routeIdentity = o.routeIdentity
		s.PathRevision = p.pathRevision
	}
	if o.maxAge < time.Second || o.maxAge > 30*time.Second || uint64(o.maxAge) > ^uint64(0)-o.stamp.boot {
		return
	}
	until := o.stamp.boot + uint64(o.maxAge)
	switch o.kind {
	case statusReachable:
		if !validGuardID(o.pathID) || o.routeIdentity == "" {
			return
		}
		until = min(until, o.approvalUntil, o.leaseUntil)
		s.Availability, s.Reason, s.Evidence, s.PathID = "reachable", "unbound_tcp_connect_verified", "unbound_tcp_connect", o.pathID
	case statusUnreachable:
		until = min(until, o.approvalUntil)
		s.Availability, s.Reason, s.Evidence = "unreachable", "approved_candidates_unreachable", "bound_tcp_connect"
	case statusBlocked:
		s.Availability, s.Reason = "blocked", "approval_denied_or_expired"
	default:
		return
	}
	s.Freshness, s.ObservedBootNS, s.ValidUntilBootNS = "fresh", o.stamp.boot, until
	if until <= now.boot {
		s = staleUplink(s, "observation_expired")
		p.invalidated.Store(s.Revision)
	}
}

func staleUplink(s UplinkSnapshot, reason string) UplinkSnapshot {
	s.Availability, s.Freshness, s.Reason = "unknown", "stale", reason
	s.PathID, s.Evidence = "", ""
	s.RemainingValidityMS = 0
	return s
}
func (p *UplinkPublisher) invalidate(revision uint64) {
	for old := p.invalidated.Load(); old < revision; old = p.invalidated.Load() {
		if p.invalidated.CompareAndSwap(old, revision) {
			return
		}
	}
}

// Snapshot returns a value copy. Expiration is latched per publication so an
// invalid clock/read followed by clock recovery cannot revive old evidence.
// A caller must recheck the absolute deadline at receipt and before use; the
// informational remaining duration never starts a new TTL at the consumer.
func (p *UplinkPublisher) Snapshot() UplinkSnapshot {
	r := p.record.Load()
	s := r.snapshot
	if s.ObservedBootNS == 0 {
		return s
	}
	now, err := p.clock()
	if err == nil && now.domain == s.ClockDomain && now.boot >= s.ObservedBootNS {
		age := (now.boot - s.ObservedBootNS) / uint64(time.Millisecond)
		s.ObservedAgeMS = &age
	}
	if s.Freshness != "fresh" {
		return s
	}
	reason := ""
	switch {
	case err != nil || now.domain != s.ClockDomain || now.boot < s.ObservedBootNS:
		reason = "clock_unavailable"
	case now.boot >= s.ValidUntilBootNS:
		reason = "observation_expired"
	case p.invalidated.Load() >= s.Revision:
		reason = "observation_invalidated"
	}
	if reason != "" {
		p.invalidate(s.Revision)
		return staleUplink(s, reason)
	}
	s.RemainingValidityMS = (s.ValidUntilBootNS - now.boot) / uint64(time.Millisecond)
	return s
}

func (p *UplinkPublisher) emptySnapshot() UplinkSnapshot {
	return UplinkSnapshot{SchemaVersion: 1, TargetID: p.target, ProducerID: p.producer, Revision: p.revision, Availability: "unknown", Freshness: "unknown", Reason: "observation_unavailable", ClockDomain: p.domain, PathRevision: p.pathRevision, SessionContinuity: "not_established"}
}
