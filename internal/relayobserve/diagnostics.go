// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Diagnostics is cost accounting only, never approval or reachability evidence.
// Phase durations are sums; concurrent phases may exceed total elapsed time.
// Commands count external processes, not BPF syscalls. No argv or output is kept.
type PhaseCost struct {
	Calls             int           `json:"calls"`
	Duration          time.Duration `json:"summed_duration_ns"`
	KernelCommands    int           `json:"kernel_commands"`
	InventoryCommands int           `json:"inventory_commands"`
	CommandDuration   time.Duration `json:"summed_command_duration_ns"`
}
type Diagnostics struct {
	Elapsed       time.Duration        `json:"monotonic_elapsed_ns"`
	BootElapsed   time.Duration        `json:"boottime_elapsed_ns"`
	BootAvailable bool                 `json:"boottime_available"`
	Phases        map[string]PhaseCost `json:"phases"`
}
type Recorder struct {
	mu      sync.Mutex
	started time.Time
	boot    time.Duration
	bootOK  bool
	phases  map[string]PhaseCost
}
type scope struct {
	recorder *Recorder
	phase    string
}
type scopeKey struct{}

func bootTime() (time.Duration, bool) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return time.Duration(ts.Nano()), err == nil
}
func Start(ctx context.Context) (context.Context, *Recorder) {
	if s, ok := ctx.Value(scopeKey{}).(scope); ok {
		return ctx, s.recorder
	}
	boot, ok := bootTime()
	r := &Recorder{started: time.Now(), boot: boot, bootOK: ok, phases: map[string]PhaseCost{}}
	return context.WithValue(ctx, scopeKey{}, scope{r, "other"}), r
}
func (r *Recorder) Snapshot() *Diagnostics {
	r.mu.Lock()
	defer r.mu.Unlock()
	boot, ok := bootTime()
	d := &Diagnostics{Elapsed: time.Since(r.started), BootAvailable: ok && r.bootOK && boot >= r.boot, Phases: map[string]PhaseCost{}}
	if d.BootAvailable {
		d.BootElapsed = boot - r.boot
	}
	for k, v := range r.phases {
		d.Phases[k] = v
	}
	return d
}
func Phase(ctx context.Context, name string) (context.Context, func()) {
	s, ok := ctx.Value(scopeKey{}).(scope)
	if !ok {
		return ctx, func() {}
	}
	started := time.Now()
	return context.WithValue(ctx, scopeKey{}, scope{s.recorder, name}), func() {
		r := s.recorder
		r.mu.Lock()
		defer r.mu.Unlock()
		p := r.phases[name]
		p.Calls++
		p.Duration += time.Since(started)
		r.phases[name] = p
	}
}
func Command(ctx context.Context, inventory bool) func() {
	s, ok := ctx.Value(scopeKey{}).(scope)
	if !ok {
		return func() {}
	}
	started := time.Now()
	return func() {
		r := s.recorder
		r.mu.Lock()
		defer r.mu.Unlock()
		p := r.phases[s.phase]
		if inventory {
			p.InventoryCommands++
		} else {
			p.KernelCommands++
		}
		p.CommandDuration += time.Since(started)
		r.phases[s.phase] = p
	}
}
