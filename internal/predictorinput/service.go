// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictorinput

import (
	"fmt"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/uplink"
)

// ServiceStream identifies a target-wide source, not an individual route. NodeID
// comes from the authenticated envelope; callers must split configuration epochs
// when reusing a target ID for a changed endpoint or probing policy.
type ServiceStream struct {
	NodeID   string
	TargetID string
	Protocol string
}

// ServiceResult preserves protocol-specific service evidence. It deliberately
// has no implicit conversion to the peer RTT or packet loss model dimensions.
// Ready includes completed failures; unknown/stale/missing have no Success value.
type ServiceResult struct {
	Stream       ServiceStream
	SnapshotID   string
	CycleAt      time.Time
	IntervalSec  int
	Dropped      uint64 // process-scoped cumulative counter, not an event count
	Feature      Feature
	CompletedAt  *time.Time
	DurationKind string
	Success      *bool
	DurationMS   *float64
	Ready        bool
}

// BuildUplinkService adapts one raw snapshot at an explicit event-time tick. Age
// is conservatively measured from service-call start, not cycle completion or
// receipt time. The completed interval includes DNS/retries; DurationMS is only
// the successful protocol attempt measured by the existing NetworkProber.
func BuildUplinkService(stream ServiceStream, snapshot uplink.Snapshot, now time.Time, maxAge time.Duration) (ServiceResult, error) {
	now = now.Round(0).UTC()
	if now.IsZero() || maxAge <= 0 || maxAge > MaxWindow || !uplink.ValidID(stream.TargetID) ||
		(stream.Protocol != "tcp" && stream.Protocol != "tls" && stream.Protocol != "udp-echo") {
		return ServiceResult{}, ErrInvalid
	}
	// Reuse M2's node-label admission contract without emitting a probe record.
	if err := history.Validate(stream.NodeID, history.Observation{ID: "scope", PeerID: "scope", Path: "unknown", Timestamp: now, Success: new(bool)}, now); err != nil {
		return ServiceResult{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	stale := snapshot.Stale
	snapshot.Stale = false // query freshness is metadata, not malformed raw input
	if err := snapshot.Validate(now); err != nil {
		return ServiceResult{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	stale = stale || snapshot.Fresh(now).Stale
	out := ServiceResult{Stream: stream, SnapshotID: snapshot.ID, CycleAt: snapshot.At.Round(0).UTC(),
		IntervalSec: snapshot.IntervalSec, Dropped: snapshot.Dropped,
		Feature: Feature{Source: "uplink-service", State: "missing", Reason: "target_not_collected"}}
	switch stream.Protocol {
	case "tcp":
		out.DurationKind = "tcp_connect"
	case "tls":
		out.DurationKind = "tcp_connect_tls_handshake"
	case "udp-echo":
		out.DurationKind = "udp_socket_echo"
	}
	for _, target := range snapshot.Targets {
		if target.ID != stream.TargetID {
			continue
		}
		if target.Protocol != stream.Protocol {
			return ServiceResult{}, fmt.Errorf("%w: target protocol changed", ErrInvalid)
		}
		out.Feature.InputCount = 1
		if target.Service.State == "unknown" {
			out.Feature.UnknownCount = 1
		}
		if target.ServiceStartedAt == nil {
			out.Feature.Reason = "service_time_unavailable"
			return out, nil
		}
		started, completed := target.ServiceStartedAt.Round(0).UTC(), target.ServiceCompletedAt.Round(0).UTC()
		age := int64(now.Sub(started))
		out.Feature.ObservedAt, out.Feature.AgeNS, out.CompletedAt = &started, &age, &completed
		if stale || time.Duration(age) >= maxAge {
			out.Feature.State, out.Feature.Reason = "stale", "service_expired"
			return out, nil
		}
		if target.Service.State == "unknown" {
			out.Feature.State, out.Feature.Reason = "unknown", target.Service.Reason
			if out.Feature.Reason == "" {
				out.Feature.Reason = "service_unknown"
			}
			return out, nil
		}
		success := target.Service.State == "up"
		out.Success, out.Ready = &success, true
		out.Feature.State, out.Feature.Reason = "observed", target.Service.Reason
		if target.Service.RTTMs != nil {
			duration := *target.Service.RTTMs
			out.DurationMS = &duration
		}
		return out, nil
	}
	return out, nil
}
