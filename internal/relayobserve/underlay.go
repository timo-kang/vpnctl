// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import "context"

// UnderlayEvents is live, local evidence. A generation must change even when an
// intervening network change restores the same final interface/address tuple.
// Errors mean unknown, never proof of no uplink. It must honor ctx and bound work.
type UnderlayEvents interface {
	Generation(context.Context, string) (string, error)
}
type underlayEventsKey struct{}

// TerminalScope comes only from the locked local apply journal. It scopes
// notifications for one exact owned unreachable-default tuple; it is never
// approval, route readiness, or permission to ignore a foreign policy route.
type TerminalScope struct {
	UnderlayID string `json:"underlay_id"`
	Table      uint32 `json:"table"`
	Metric     uint32 `json:"metric"`
}

func SetTerminalScopes(ctx context.Context, scopes []TerminalScope) error {
	if events, ok := ctx.Value(underlayEventsKey{}).(interface {
		SetTerminalScopes(context.Context, []TerminalScope) error
	}); ok {
		return events.SetTerminalScopes(ctx, scopes)
	}
	return ctx.Err()
}

func WithUnderlayEvents(ctx context.Context, events UnderlayEvents) context.Context {
	return context.WithValue(ctx, underlayEventsKey{}, events)
}

// An absent provider preserves the snapshot-only library contract. Operational
// selection commands install a provider for their whole lifetime, not per cycle.
func UnderlayGeneration(ctx context.Context, id string) (string, error) {
	if events, ok := ctx.Value(underlayEventsKey{}).(UnderlayEvents); ok {
		return events.Generation(ctx, id)
	}
	return "", ctx.Err()
}
