// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package quality

import "sort"

// PercentileRank returns a one-based nearest rank, or zero for an empty
// population. Callers use bounded sample counts and integer percentiles 1..100.
func PercentileRank(count, percentile int) int {
	if count == 0 {
		return 0
	}
	return (percentile*count + 99) / 100
}

// RTTPercentiles sorts successful, validated microsecond RTTs in place. Failed
// attempts and unavailable observations must not be included. Empty populations
// return nil; a measured zero is a non-nil zero.
func RTTPercentiles(rtts []int64) (p50, p95, p99 *float64) {
	if len(rtts) == 0 {
		return nil, nil, nil
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	value := func(percentile int) *float64 {
		return ptr(float64(rtts[PercentileRank(len(rtts), percentile)-1]) / 1000)
	}
	return value(50), value(95), value(99)
}

func (w *Window) percentiles(q *PeerQuality) {
	rtts := make([]int64, 0, len(w.samples))
	var jitter JitterSummary
	for _, s := range w.samples {
		jitter.Add(s.at.UnixMicro(), s.rtt, s.success)
		if s.success {
			rtts = append(rtts, s.rtt)
		}
	}
	q.P50RTTMs, q.P95RTTMs, q.P99RTTMs = RTTPercentiles(rtts)
	q.JitterStats = jitter.Stats()
}
