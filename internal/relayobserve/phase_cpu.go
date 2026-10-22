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
	Scope            string        `json:"scope"`
	SampledCalls     int           `json:"sampled_calls"`
	UnavailableCalls int           `json:"unavailable_calls"`
	User             time.Duration `json:"sampled_user_cpu_ns"`
	System           time.Duration `json:"sampled_system_cpu_ns"`
}

type cpuSample struct {
	user, system time.Duration
	valid        bool
}

func readPhaseCPU() cpuSample {
	var usage unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &usage) != nil {
		return cpuSample{}
	}
	user, userOK := cpuDuration(int64(usage.Utime.Sec), int64(usage.Utime.Usec))
	system, systemOK := cpuDuration(int64(usage.Stime.Sec), int64(usage.Stime.Usec))
	return cpuSample{user, system, userOK && systemOK}
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
	out.SampledCalls++
	out.User += user
	out.System += system
	return out
}
