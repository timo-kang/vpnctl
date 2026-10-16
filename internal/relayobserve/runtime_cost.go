// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayobserve

import (
	"math"
	"runtime/metrics"
	"time"

	"golang.org/x/sys/unix"
)

// RuntimeCost is optional process-wide diagnostic accounting, not per-goroutine
// or per-phase attribution. Overlapping recorders must not be summed. OS CPU
// excludes children; Go CPU estimates are comparable only within /cpu/classes.
type RuntimeCost struct {
	Scope      string                        `json:"scope"`
	Start      RuntimeSampleBounds           `json:"start"`
	Finish     RuntimeSampleBounds           `json:"finish"`
	ProcessCPU ProcessCPUCost                `json:"process_cpu"`
	Metrics    map[string]RuntimeMetricDelta `json:"metrics"`
}

type RuntimeSampleBounds struct {
	ProcessCPU SamplingBounds `json:"process_cpu"`
	Metrics    SamplingBounds `json:"metrics"`
}

// SamplingBounds brackets one read, including its copying cost. The reads of
// getrusage and runtime/metrics are separate, not an atomic combined snapshot.
type SamplingBounds struct {
	Available bool          `json:"available"`
	Before    time.Duration `json:"before_monotonic_ns"`
	After     time.Duration `json:"after_monotonic_ns"`
}

type ProcessCPUCost struct {
	Available bool           `json:"available"`
	User      *time.Duration `json:"user_cpu_ns,omitempty"`
	System    *time.Duration `json:"system_cpu_ns,omitempty"`
}

// Metric names carry their units. Unavailable samples omit values, whereas an
// available zero is explicit. Histograms retain bounded summaries, not buckets.
type RuntimeMetricDelta struct {
	Available bool                  `json:"available"`
	Uint64    *uint64               `json:"uint64,omitempty"`
	Float64   *float64              `json:"float64,omitempty"`
	Histogram *RuntimeHistogramCost `json:"histogram,omitempty"`
}

type RuntimeHistogramCost struct {
	Events            uint64   `json:"events"`
	MaxLower          *float64 `json:"max_lower_seconds,omitempty"`
	MaxUpper          *float64 `json:"max_upper_seconds,omitempty"`
	MaxLowerUnbounded bool     `json:"max_lower_unbounded,omitempty"`
	MaxUpperUnbounded bool     `json:"max_upper_unbounded,omitempty"`
}

type runtimeValue struct {
	kind    metrics.ValueKind
	integer uint64
	real    float64
	hist    metrics.Float64Histogram
}

type runtimeSample struct {
	bounds       RuntimeSampleBounds
	cpuOK        bool
	user, system time.Duration
	values       map[string]runtimeValue
}

func runtimeMetricSamples() []metrics.Sample {
	return []metrics.Sample{
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
		{Name: "/cpu/classes/user:cpu-seconds"},
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/gc/heap/allocs:bytes"},
		{Name: "/sched/latencies:seconds"},
		{Name: "/sched/pauses/total/gc:seconds"},
		{Name: "/sync/mutex/wait/total:seconds"},
	}
}

func readRuntimeSample() *runtimeSample {
	s := &runtimeSample{values: make(map[string]runtimeValue, 8)}
	before, beforeOK := monotonicTime()
	var usage unix.Rusage
	err := unix.Getrusage(unix.RUSAGE_SELF, &usage)
	after, afterOK := monotonicTime()
	s.bounds.ProcessCPU = samplingBounds(before, beforeOK, after, afterOK)
	var userOK, systemOK bool
	s.user, userOK = usageDuration(usage.Utime)
	s.system, systemOK = usageDuration(usage.Stime)
	s.cpuOK = err == nil && userOK && systemOK

	before, beforeOK = monotonicTime()
	samples := runtimeMetricSamples()
	metrics.Read(samples)
	for _, sample := range samples {
		s.values[sample.Name] = copyRuntimeValue(sample.Value)
	}
	after, afterOK = monotonicTime()
	s.bounds.Metrics = samplingBounds(before, beforeOK, after, afterOK)
	return s
}

func samplingBounds(before time.Duration, beforeOK bool, after time.Duration, afterOK bool) SamplingBounds {
	if !beforeOK || !afterOK || before < 0 || after < before {
		return SamplingBounds{}
	}
	return SamplingBounds{Available: true, Before: before, After: after}
}

func usageDuration(v unix.Timeval) (time.Duration, bool) {
	if v.Sec < 0 || v.Usec < 0 || v.Usec >= 1_000_000 || v.Sec > math.MaxInt64/int64(time.Second) {
		return 0, false
	}
	ns := v.Sec * int64(time.Second)
	fraction := v.Usec * int64(time.Microsecond)
	if ns > math.MaxInt64-fraction {
		return 0, false
	}
	return time.Duration(ns + fraction), true
}

func copyRuntimeValue(v metrics.Value) runtimeValue {
	out := runtimeValue{kind: v.Kind()}
	switch out.kind {
	case metrics.KindUint64:
		out.integer = v.Uint64()
	case metrics.KindFloat64:
		out.real = v.Float64()
	case metrics.KindFloat64Histogram:
		h := v.Float64Histogram()
		out.hist.Counts = append([]uint64(nil), h.Counts...)
		out.hist.Buckets = append([]float64(nil), h.Buckets...)
	}
	return out
}

func runtimeCostBetween(start, finish *runtimeSample) *RuntimeCost {
	out := &RuntimeCost{Scope: "process", Start: start.bounds, Finish: finish.bounds,
		Metrics: make(map[string]RuntimeMetricDelta, 8)}
	if validSampleInterval(start.bounds.ProcessCPU, finish.bounds.ProcessCPU) && start.cpuOK && finish.cpuOK &&
		start.user >= 0 && start.system >= 0 && finish.user >= start.user && finish.system >= start.system {
		user, system := finish.user-start.user, finish.system-start.system
		out.ProcessCPU = ProcessCPUCost{Available: true, User: &user, System: &system}
	}
	for _, sample := range runtimeMetricSamples() {
		value := RuntimeMetricDelta{}
		if validSampleInterval(start.bounds.Metrics, finish.bounds.Metrics) {
			kind := metrics.KindFloat64
			switch sample.Name {
			case "/gc/cycles/total:gc-cycles", "/gc/heap/allocs:bytes":
				kind = metrics.KindUint64
			case "/sched/latencies:seconds", "/sched/pauses/total/gc:seconds":
				kind = metrics.KindFloat64Histogram
			}
			value = metricDelta(start.values[sample.Name], finish.values[sample.Name], kind)
		}
		out.Metrics[sample.Name] = value
	}
	return out
}

func validSampleInterval(start, finish SamplingBounds) bool {
	return start.Available && finish.Available && start.Before >= 0 && start.After >= start.Before &&
		finish.Before >= start.After && finish.After >= finish.Before
}

func metricDelta(start, finish runtimeValue, kind metrics.ValueKind) RuntimeMetricDelta {
	if start.kind != kind || finish.kind != kind {
		return RuntimeMetricDelta{}
	}
	switch kind {
	case metrics.KindUint64:
		if finish.integer >= start.integer {
			v := finish.integer - start.integer
			return RuntimeMetricDelta{Available: true, Uint64: &v}
		}
	case metrics.KindFloat64:
		if finite(start.real) && finite(finish.real) && start.real >= 0 && finish.real >= start.real {
			v := finish.real - start.real
			return RuntimeMetricDelta{Available: true, Float64: &v}
		}
	case metrics.KindFloat64Histogram:
		if h := histogramDelta(start.hist, finish.hist); h != nil {
			return RuntimeMetricDelta{Available: true, Histogram: h}
		}
	}
	return RuntimeMetricDelta{}
}

func histogramDelta(start, finish metrics.Float64Histogram) *RuntimeHistogramCost {
	if len(start.Counts) == 0 || len(start.Counts) != len(finish.Counts) ||
		len(start.Buckets) != len(start.Counts)+1 || len(finish.Buckets) != len(start.Buckets) {
		return nil
	}
	for i, b := range start.Buckets {
		if math.IsNaN(b) || b != finish.Buckets[i] ||
			(i > 0 && b <= start.Buckets[i-1]) ||
			(math.IsInf(b, -1) && i != 0) || (math.IsInf(b, 1) && i != len(start.Buckets)-1) {
			return nil
		}
	}
	out := &RuntimeHistogramCost{}
	last := -1
	for i, n := range finish.Counts {
		if n < start.Counts[i] || n-start.Counts[i] > math.MaxUint64-out.Events {
			return nil
		}
		delta := n - start.Counts[i]
		out.Events += delta
		if delta > 0 {
			last = i
		}
	}
	if last >= 0 {
		lo, hi := finish.Buckets[last], finish.Buckets[last+1]
		out.MaxLowerUnbounded, out.MaxUpperUnbounded = math.IsInf(lo, -1), math.IsInf(hi, 1)
		if !out.MaxLowerUnbounded {
			out.MaxLower = &lo
		}
		if !out.MaxUpperUnbounded {
			out.MaxUpper = &hi
		}
	}
	return out
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
