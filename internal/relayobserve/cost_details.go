// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"context"
	"time"
)

// CostDetails is opt-in experimental accounting. Steps are nested in the
// existing phases, so their times/counts must NOT be added to the phase totals.
// Names are fixed code labels, never path IDs, argv, output or credentials.
type CostDetails struct {
	Steps    map[string]PhaseCost   `json:"steps"`
	Commands map[string]ProcessCost `json:"commands"`
}

// ProcessCost reports OS usage for reaped children (and, where the OS includes
// them, their waited-for descendants). It excludes the Go parent's CPU. Wall
// time also includes setup, scheduling, I/O and waiting; wall minus child CPU
// is NOT an attribution to Go, GC, throttling, or a specific wait mechanism.
type ProcessCost struct {
	Calls          int           `json:"calls"`
	CPUAvailable   int           `json:"cpu_available"`
	CPUUnavailable int           `json:"cpu_unavailable"`
	Wall           time.Duration `json:"summed_wall_ns"`
	MaxWall        time.Duration `json:"max_wall_ns"`
	User           time.Duration `json:"summed_user_cpu_ns"`
	System         time.Duration `json:"summed_system_cpu_ns"`
}

type detailKey struct{}

// Detail records a substep without changing existing phase attribution. It is
// a no-op when disabled. Call done exactly once; sibling contexts stay isolated.
func Detail(ctx context.Context, name string) (context.Context, func()) {
	s, ok := ctx.Value(scopeKey{}).(scope)
	if !ok || s.recorder.details == nil {
		return ctx, func() {}
	}
	started := time.Now()
	return context.WithValue(ctx, detailKey{}, name), func() {
		r := s.recorder
		r.mu.Lock()
		defer r.mu.Unlock()
		p := r.details.Steps[name]
		p.Calls++
		p.Duration += time.Since(started)
		r.details.Steps[name] = p
	}
}

func commandFamily(name string) string {
	switch name {
	case "ip", "nft", "wg", "sysctl", "cat":
		return name
	default:
		return "other"
	}
}
