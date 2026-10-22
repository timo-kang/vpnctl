// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"math"
	"time"

	"golang.org/x/sys/unix"
)

// PhaseCPUCost samples all threads in this process, excluding command children.
// Reads occur inside the phase's elapsed interval. This is not per-goroutine
// CPU, scheduler delay, or a partition of wall time. Nested/overlapping phases
// must not be added. Missing reads are explicit; totals cover sampled calls only.
type PhaseCPUCost struct {
	Scope               string        `json:"scope"`
	SampledCalls        int           `json:"sampled_calls"`
	UnavailableCalls    int           `json:"unavailable_calls"`
	User                time.Duration `json:"sampled_user_cpu_ns"`
	System              time.Duration `json:"sampled_system_cpu_ns"`
	VoluntarySwitches   int64         `json:"sampled_voluntary_switches"`
	InvoluntarySwitches int64         `json:"sampled_involuntary_switches"`
	InputBlocks         int64         `json:"sampled_input_blocks"`
	OutputBlocks        int64         `json:"sampled_output_blocks"`
}

type cpuSample struct {
	user, system                          time.Duration
	voluntary, involuntary, input, output int64
	valid                                 bool
}

func readPhaseCPU() cpuSample {
	var usage unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &usage) != nil {
		return cpuSample{}
	}
	user, userOK := cpuDuration(int64(usage.Utime.Sec), int64(usage.Utime.Usec))
	system, systemOK := cpuDuration(int64(usage.Stime.Sec), int64(usage.Stime.Usec))
	return cpuSample{user: user, system: system, voluntary: usage.Nvcsw, involuntary: usage.Nivcsw,
		input: usage.Inblock, output: usage.Oublock, valid: userOK && systemOK}
}

func cpuDuration(seconds, micros int64) (time.Duration, bool) {
	if seconds < 0 || micros < 0 || micros >= 1_000_000 || seconds > math.MaxInt64/int64(time.Second) {
		return 0, false
	}
	ns := seconds * int64(time.Second)
	fraction := micros * int64(time.Microsecond)
	if ns > math.MaxInt64-fraction {
		return 0, false
	}
	return time.Duration(ns + fraction), true
}

func addPhaseCPU(previous *PhaseCPUCost, before, after cpuSample) *PhaseCPUCost {
	// Copy on write keeps already-published Snapshot values immutable.
	out := &PhaseCPUCost{Scope: "process_self"}
	if previous != nil {
		*out = *previous
	}
	if !before.valid || !after.valid || before.user < 0 || before.system < 0 || after.user < before.user || after.system < before.system {
		out.UnavailableCalls++
		return out
	}
	user, system := after.user-before.user, after.system-before.system
	if out.User > time.Duration(math.MaxInt64)-user || out.System > time.Duration(math.MaxInt64)-system {
		out.UnavailableCalls++
		return out
	}
	// These are process-wide event counts, not wait durations or proof that a
	// particular syscall blocked on physical I/O. Reject partial counter deltas.
	deltas := [4]int64{}
	for i, pair := range [][2]int64{{before.voluntary, after.voluntary}, {before.involuntary, after.involuntary}, {before.input, after.input}, {before.output, after.output}} {
		if pair[0] < 0 || pair[1] < pair[0] {
			out.UnavailableCalls++
			return out
		}
		deltas[i] = pair[1] - pair[0]
	}
	totals := []*int64{&out.VoluntarySwitches, &out.InvoluntarySwitches, &out.InputBlocks, &out.OutputBlocks}
	for i, total := range totals {
		if *total > math.MaxInt64-deltas[i] {
			out.UnavailableCalls++
			return out
		}
	}
	for i, total := range totals {
		*total += deltas[i]
	}
	out.SampledCalls++
	out.User += user
	out.System += system
	return out
}
