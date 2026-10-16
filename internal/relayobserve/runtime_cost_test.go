// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"math"
	"runtime/metrics"
	"sync"
	"testing"
	"time"
)

func TestRuntimeCostsOptInProducesProcessScopeEvidence(t *testing.T) {
	t.Setenv("VPNCTL_RUNTIME_COSTS", "1")
	_, r := Start(context.Background())
	var data map[string]json.RawMessage
	b, err := json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	if len(data["runtime_cost"]) == 0 {
		t.Fatal("process runtime evidence missing")
	}
}

func TestRuntimeCostsDisabledAndIndependentOfCommandDetails(t *testing.T) {
	for _, value := range []string{"", "0", "true", "1 "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VPNCTL_RUNTIME_COSTS", value)
			t.Setenv("VPNCTL_COST_DETAILS", "1")
			_, r := Start(context.Background())
			d := r.Snapshot()
			if d.RuntimeCost != nil || d.Details == nil || r.runtimeStart != nil {
				t.Fatal("disabled runtime sampling changed independent detail mode")
			}
			b, err := json.Marshal(d)
			if err != nil || bytes.Contains(b, []byte(`"runtime_cost"`)) {
				t.Fatalf("unexpected optional field: %s, %v", b, err)
			}
		})
	}
}

func TestRuntimeCostsRealSamplesHaveBoundedIndependentSnapshots(t *testing.T) {
	t.Setenv("VPNCTL_RUNTIME_COSTS", "1")
	t.Setenv("VPNCTL_COST_DETAILS", "0")
	ctx, r := Start(context.Background())
	_, nested := Start(ctx)
	if nested != r {
		t.Fatal("nested recorder replaced runtime baseline")
	}
	d := r.Snapshot()
	cost := d.RuntimeCost
	if d.Details != nil || cost == nil || cost.Scope != "process" || !cost.ProcessCPU.Available || len(cost.Metrics) != 8 {
		t.Fatalf("incomplete actual process evidence: %+v", cost)
	}
	for _, bounds := range []SamplingBounds{cost.Start.ProcessCPU, cost.Start.Metrics, cost.Finish.ProcessCPU, cost.Finish.Metrics} {
		if !bounds.Available || bounds.Before < d.StartedMono || bounds.After < bounds.Before || bounds.After > d.FinishedMono {
			t.Fatalf("sample outside cycle: %+v", bounds)
		}
	}
	for name, value := range cost.Metrics {
		if !value.Available {
			t.Fatalf("installed Go lacks expected sample: %s", name)
		}
	}
	data, err := json.Marshal(cost)
	if err != nil || len(data) > 4096 || bytes.Contains(data, []byte(`"buckets"`)) {
		t.Fatalf("unbounded/unserializable runtime evidence: %d %v", len(data), err)
	}
	*cost.ProcessCPU.User = -1
	const counter = "/gc/cycles/total:gc-cycles"
	*cost.Metrics[counter].Uint64 = math.MaxUint64
	delete(cost.Metrics, "/sched/latencies:seconds")
	next := r.Snapshot().RuntimeCost
	if *next.ProcessCPU.User < 0 || *next.Metrics[counter].Uint64 == math.MaxUint64 || len(next.Metrics) != 8 {
		t.Fatal("snapshot mutation escaped into retained baseline")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				_, done := Phase(ctx, "worker")
				done()
				if _, err := json.Marshal(r.Snapshot()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestRuntimeCostCountersRejectMissingWrongKindResetAndInvalidValues(t *testing.T) {
	integer := func(v uint64) runtimeValue { return runtimeValue{kind: metrics.KindUint64, integer: v} }
	real := func(v float64) runtimeValue { return runtimeValue{kind: metrics.KindFloat64, real: v} }
	cases := []struct {
		start, finish runtimeValue
		kind          metrics.ValueKind
	}{
		{runtimeValue{}, integer(0), metrics.KindUint64},
		{integer(0), runtimeValue{}, metrics.KindUint64},
		{integer(1), integer(0), metrics.KindUint64},
		{integer(0), real(1), metrics.KindUint64},
		{real(1), real(0), metrics.KindFloat64},
		{real(-1), real(1), metrics.KindFloat64},
		{real(math.NaN()), real(1), metrics.KindFloat64},
		{real(1), real(math.Inf(1)), metrics.KindFloat64},
	}
	for _, tc := range cases {
		got := metricDelta(tc.start, tc.finish, tc.kind)
		if got.Available || got.Uint64 != nil || got.Float64 != nil || got.Histogram != nil {
			t.Fatalf("bad evidence became measured zero: %+v", got)
		}
	}
	zero := metricDelta(integer(5), integer(5), metrics.KindUint64)
	if !zero.Available || zero.Uint64 == nil || *zero.Uint64 != 0 {
		t.Fatal("measured zero lost")
	}
	value := metricDelta(real(1.25), real(2.5), metrics.KindFloat64)
	if !value.Available || *value.Float64 != 1.25 {
		t.Fatal(value)
	}
}

func TestRuntimeHistogramDeltaRetainsBoundsWithoutJSONInfinity(t *testing.T) {
	start := metrics.Float64Histogram{Buckets: []float64{math.Inf(-1), 0, 1, math.Inf(1)}, Counts: []uint64{0, 7, 2}}
	finish := metrics.Float64Histogram{Buckets: append([]float64(nil), start.Buckets...), Counts: []uint64{0, 10, 3}}
	got := histogramDelta(start, finish)
	if got == nil || got.Events != 4 || got.MaxLower == nil || *got.MaxLower != 1 || got.MaxUpper != nil || !got.MaxUpperUnbounded {
		t.Fatalf("wrong maximum bucket: %+v", got)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatal(err)
	}
	zero := histogramDelta(start, start)
	if zero == nil || zero.Events != 0 || zero.MaxLower != nil || zero.MaxUpper != nil || zero.MaxUpperUnbounded {
		t.Fatalf("zero events reported a maximum: %+v", zero)
	}
	for _, mutate := range []func(*metrics.Float64Histogram){
		func(h *metrics.Float64Histogram) { h.Counts[1] = 0 },
		func(h *metrics.Float64Histogram) { h.Counts = h.Counts[:1] },
		func(h *metrics.Float64Histogram) { h.Buckets[1] = 0.5 },
		func(h *metrics.Float64Histogram) { h.Buckets[1] = math.NaN() },
		func(h *metrics.Float64Histogram) { h.Buckets[2] = h.Buckets[1] },
		func(h *metrics.Float64Histogram) { h.Counts[0], h.Counts[1] = math.MaxUint64, math.MaxUint64 },
	} {
		h := metrics.Float64Histogram{Buckets: append([]float64(nil), finish.Buckets...), Counts: append([]uint64(nil), finish.Counts...)}
		mutate(&h)
		if histogramDelta(start, h) != nil {
			t.Fatal("accepted corrupt histogram")
		}
	}
}

func TestRuntimeSampleCopyOwnsHistogramStorage(t *testing.T) {
	samples := []metrics.Sample{{Name: "/sched/latencies:seconds"}}
	metrics.Read(samples)
	copied := copyRuntimeValue(samples[0].Value)
	original := samples[0].Value.Float64Histogram()
	count, boundary := original.Counts[0], original.Buckets[0]
	copied.hist.Counts[0]++
	copied.hist.Buckets[0] = 99
	if original.Counts[0] != count || original.Buckets[0] != boundary {
		t.Fatal("baseline aliases runtime storage")
	}
}

func TestRuntimeCostProcessUsageAndSamplingValidity(t *testing.T) {
	start := &runtimeSample{cpuOK: true, user: 10, system: 20,
		bounds: RuntimeSampleBounds{ProcessCPU: SamplingBounds{true, 1, 2}}}
	finish := &runtimeSample{cpuOK: true, user: 15, system: 27,
		bounds: RuntimeSampleBounds{ProcessCPU: SamplingBounds{true, 3, 4}}}
	got := runtimeCostBetween(start, finish)
	if !got.ProcessCPU.Available || *got.ProcessCPU.User != 5 || *got.ProcessCPU.System != 7 {
		t.Fatal(got)
	}
	for _, value := range got.Metrics {
		if value.Available {
			t.Fatal("missing runtime sample accepted")
		}
	}
	for _, mutate := range []func(*runtimeSample){
		func(s *runtimeSample) { s.cpuOK = false },
		func(s *runtimeSample) { s.user = 9 },
		func(s *runtimeSample) { s.system = 19 },
		func(s *runtimeSample) { s.bounds.ProcessCPU.Available = false },
		func(s *runtimeSample) { s.bounds.ProcessCPU.Before = 1 },
		func(s *runtimeSample) { s.bounds.ProcessCPU.After = 2 },
	} {
		changed := *finish
		mutate(&changed)
		cpu := runtimeCostBetween(start, &changed).ProcessCPU
		if cpu.Available || cpu.User != nil || cpu.System != nil {
			t.Fatal("invalid CPU sample reported", cpu)
		}
	}
	for _, tv := range []unix.Timeval{{Sec: -1}, {Usec: -1}, {Usec: 1_000_000}, {Sec: math.MaxInt64}} {
		if _, ok := usageDuration(tv); ok {
			t.Fatal("bad OS usage accepted", tv)
		}
	}
	if duration, ok := usageDuration(unix.Timeval{Sec: 1, Usec: 500_000}); !ok || duration != 1500*time.Millisecond {
		t.Fatal(duration, ok)
	}
	if samplingBounds(3, true, 2, true).Available || samplingBounds(1, false, 2, true).Available {
		t.Fatal("bad clock accepted")
	}
}

func TestRuntimeSampleUsesParentOSCPUWithinIndependentUsageBounds(t *testing.T) {
	var before, after unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	sample := readRuntimeSample()
	if err := unix.Getrusage(unix.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	beforeUser, _ := usageDuration(before.Utime)
	beforeSystem, _ := usageDuration(before.Stime)
	afterUser, _ := usageDuration(after.Utime)
	afterSystem, _ := usageDuration(after.Stime)
	if !sample.cpuOK || sample.user < beforeUser || sample.user > afterUser || sample.system < beforeSystem || sample.system > afterSystem {
		t.Fatalf("usage is not this parent process: user=%v system=%v", sample.user, sample.system)
	}
}
