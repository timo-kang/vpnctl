// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"context"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPhaseCPURejectsMissingRegressedAndOverflowedSamples(t *testing.T) {
	good := cpuSample{user: 20, system: 30, valid: true}
	end := cpuSample{user: 25, system: 39, valid: true}
	first := addPhaseCPU(nil, good, end)
	if first.SampledCalls != 1 || first.UnavailableCalls != 0 || first.User != 5 || first.System != 9 {
		t.Fatal(first)
	}
	for _, invalid := range []cpuSample{{}, {user: 19, system: 39, valid: true}, {user: 25, system: 29, valid: true}} {
		got := addPhaseCPU(first, good, invalid)
		if got.SampledCalls != 1 || got.UnavailableCalls != 1 || got.User != 5 || got.System != 9 {
			t.Fatal(got)
		}
	}
	got := addPhaseCPU(nil, cpuSample{}, end)
	if got.SampledCalls != 0 || got.UnavailableCalls != 1 {
		t.Fatal(got)
	}
	full := &PhaseCPUCost{SampledCalls: 1, User: math.MaxInt64, System: 9}
	got = addPhaseCPU(full, good, end)
	if got.User != full.User || got.System != full.System || got.UnavailableCalls != 1 || got.SampledCalls != 1 {
		t.Fatal(got)
	}
	if first.UnavailableCalls != 0 || first.User != 5 {
		t.Fatal("published snapshot mutated", first)
	}
}

func TestPhaseCPUTimevalBounds(t *testing.T) {
	for _, invalid := range [][2]int64{{-1, 0}, {0, -1}, {0, 1_000_000}, {math.MaxInt64, 0}, {math.MaxInt64 / 1_000_000_000, 999999}} {
		if _, ok := cpuDuration(invalid[0], invalid[1]); ok {
			t.Fatal("accepted invalid CPU counter", invalid)
		}
	}
	if got, ok := cpuDuration(2, 123); !ok || got != 2*time.Second+123*time.Microsecond {
		t.Fatal(got, ok)
	}
}

func TestPhaseCPUIsNarrowAndSnapshotsAreImmutable(t *testing.T) {
	ctx, r := Start(context.Background())
	for _, name := range []string{"maintenance", "lease_staged", "precheck", "lease_guard_load"} {
		_, done := Phase(ctx, name)
		done()
	}
	first := r.Snapshot()
	for name, p := range first.Phases {
		want := name == "maintenance" || name == "lease_staged"
		if (p.ProcessCPU != nil) != want {
			t.Fatal(name, p)
		}
		if want && (p.ProcessCPU.SampledCalls != 1 || p.ProcessCPU.UnavailableCalls != 0 || p.ProcessCPU.Scope != "process_self") {
			t.Fatal(name, p.ProcessCPU)
		}
	}
	frozen := *first.Phases["maintenance"].ProcessCPU
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, done := Phase(ctx, "maintenance"); done() }()
	}
	wg.Wait()
	final := r.Snapshot().Phases["maintenance"]
	if final.Calls != 9 || final.ProcessCPU.SampledCalls != 9 || final.ProcessCPU.UnavailableCalls != 0 {
		t.Fatal(final)
	}
	if !reflect.DeepEqual(*first.Phases["maintenance"].ProcessCPU, frozen) {
		t.Fatal("snapshot changed")
	}
	expectedCPU := *final.ProcessCPU
	latest := r.Snapshot()
	latest.Phases["maintenance"].ProcessCPU.User = math.MaxInt64
	if !reflect.DeepEqual(*r.Snapshot().Phases["maintenance"].ProcessCPU, expectedCPU) {
		t.Fatal("caller can mutate recorder through a snapshot")
	}
	// Keeping the original context still attributes commands to its parent phase.
	parent, parentDone := Phase(ctx, "apply")
	_, childDone := Phase(parent, "lease_staged")
	commandDone := Command(parent, false)
	commandDone()
	childDone()
	parentDone()
	p := r.Snapshot().Phases
	if p["apply"].KernelCommands != 1 || p["lease_staged"].KernelCommands != 0 {
		t.Fatal(p)
	}
}

func TestPhaseCPUReadsSelfCounters(t *testing.T) {
	var before, after unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	sample := readPhaseCPU()
	if err := unix.Getrusage(unix.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	userBefore, _ := cpuDuration(int64(before.Utime.Sec), int64(before.Utime.Usec))
	userAfter, _ := cpuDuration(int64(after.Utime.Sec), int64(after.Utime.Usec))
	systemBefore, _ := cpuDuration(int64(before.Stime.Sec), int64(before.Stime.Usec))
	systemAfter, _ := cpuDuration(int64(after.Stime.Sec), int64(after.Stime.Usec))
	if !sample.valid || sample.user < userBefore || sample.user > userAfter || sample.system < systemBefore || sample.system > systemAfter {
		t.Fatal("sample is not inside actual process-self counter bounds", sample, before, after)
	}
}
