// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"cmp"
	"context"
	"slices"
)

// Only ordered jitter needs a time-ordered copy of the primary-tree scan.
// Failed and unknown outcomes both break jitter edges (rttUS = -1).
// Query checks MaxRows before appending and reuses this buffer between streams.
type legacyJitterSample struct{ at, rttUS int64 }

// Sort bounded runs, then merge them with cancellation checks. A single sort of
// up to MaxRows samples could otherwise delay cancellation for the whole sort.
// Equal timestamps need no ID tie-break: all ties invalidate adjacent edges.
func sortLegacyJitter(ctx context.Context, samples []legacyJitterSample) error {
	const run = 4096
	for start := 0; start < len(samples); start += run {
		if err := ctx.Err(); err != nil {
			return err
		}
		slices.SortFunc(samples[start:min(start+run, len(samples))], func(a, b legacyJitterSample) int {
			return cmp.Compare(a.at, b.at)
		})
	}
	var scratch []legacyJitterSample
	for width := run; width < len(samples); width *= 2 {
		for start := 0; start+width < len(samples); start += 2 * width {
			if err := ctx.Err(); err != nil {
				return err
			}
			middle, end := start+width, min(start+2*width, len(samples))
			if samples[middle-1].at <= samples[middle].at {
				continue
			}
			if scratch == nil {
				scratch = make([]legacyJitterSample, len(samples))
			}
			// Copy in bounded pieces so a large population cannot defer cancellation.
			for i := start; i < end; i += run {
				if err := ctx.Err(); err != nil {
					return err
				}
				copy(scratch[i:min(i+run, end)], samples[i:min(i+run, end)])
			}
			left, right := start, middle
			for i := start; i < end; i++ {
				if (i-start)%run == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if right == end || (left < middle && scratch[left].at <= scratch[right].at) {
					samples[i] = scratch[left]
					left++
				} else {
					samples[i] = scratch[right]
					right++
				}
			}
		}
	}
	return ctx.Err()
}
