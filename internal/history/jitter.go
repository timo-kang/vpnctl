// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import "vpnctl/internal/quality"

// Check structural bounds before untrusted summaries participate in arithmetic.
func validJitter(j quality.JitterSummary, successes int64) bool {
	if j.Samples < 1 || j.Samples > MaxAggregateSamples || j.Groups < 1 || j.Groups > j.Samples {
		return false
	}
	for _, g := range []quality.JitterGroup{j.First, j.Last} {
		if g.At <= 0 || g.Count < 1 || g.Count > j.Samples || g.RTTUS < -1 || g.RTTUS > 60_000_000 || (g.Count > 1 && g.RTTUS != -1) {
			return false
		}
	}
	if j.Total.Pairs < 0 || j.Total.Pairs > j.Groups-1 || j.Total.Pairs > max(0, successes-1) || j.Total.SumUS < 0 || j.Total.SumUS > j.Total.Pairs*60_000_000 {
		return false
	}
	for _, e := range []quality.JitterEdge{j.Head, j.Tail} {
		if e.Pairs < 0 || e.Pairs > 1 || e.SumUS < 0 || e.SumUS > e.Pairs*60_000_000 || e.Pairs > j.Total.Pairs || e.SumUS > j.Total.SumUS {
			return false
		}
	}
	if (j.First.RTTUS < 0 && j.Head.Pairs != 0) || (j.Last.RTTUS < 0 && j.Tail.Pairs != 0) {
		return false
	}
	if j.Groups == 1 {
		return j.First == j.Last && j.First.Count == j.Samples && j.Total.Pairs == 0
	}
	if j.First.At >= j.Last.At || j.First.Count+j.Last.Count+j.Groups-2 > j.Samples {
		return false
	}
	if j.Groups == 2 {
		if j.First.Count+j.Last.Count != j.Samples || j.Total != j.Head || j.Total != j.Tail {
			return false
		}
		var expected quality.JitterSummary
		expected.Append(quality.JitterSummary{Samples: j.First.Count, Groups: 1, First: j.First, Last: j.First})
		expected.Append(quality.JitterSummary{Samples: j.Last.Count, Groups: 1, First: j.Last, Last: j.Last})
		return expected.Total == j.Total
	}
	return j.Head.Pairs+j.Tail.Pairs <= j.Total.Pairs && j.Head.SumUS+j.Tail.SumUS <= j.Total.SumUS
}
